"""Core vulnerability scanner orchestrator."""

import asyncio
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
from urllib.parse import urljoin

from .crawler.advanced_crawler import AdvancedCrawler
from .detector.injection import SQLInjectionDetector, NoSQLInjectionDetector
from .detector.xss import XSSDetector
from .detector.security_config import (
    SecurityHeaderDetector,
    CORSDetector,
    DirectoryIndexingDetector,
)
from .detector.command_injection import CommandInjectionDetector
from .detector.ssti import SSTIDetector
from .detector.access_control import IDORDetector, AuthenticationDetector
from .detector.misconfiguration import (
    DirectoryListingDetector,
    HTTPMethodDetector,
    FileUploadDetector,
    CrossSiteRequestForgeryDetector,
)
from .risk_engine.cvss_engine import RiskEngine
from .utils.models import ScanResult, Vulnerability
from .utils.logging_util import setup_logging
from .utils.http_client import HTTPClient


logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """
    Enterprise-grade vulnerability scanner with modular detection.
    
    Features:
    - Advanced crawling engine
    - Multiple vulnerability detectors
    - Risk scoring (CVSS v3)
    - Results aggregation and reporting
    """
    
    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        max_urls: int = 1000,
        use_js: bool = False,
        timeout: int = 30,
        log_level: str = "INFO",
    ):
        """
        Initialize the scanner.
        
        Parameters
        ----------
        target_url : str
            Target URL to scan.
        max_depth : int
            Maximum crawl depth.
        max_urls : int
            Maximum URLs to discover.
        use_js : bool
            Enable JavaScript rendering.
        timeout : int
            Request timeout in seconds.
        log_level : str
            Logging level.
        """
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.use_js = use_js
        self.timeout = timeout
        
        # Setup logging
        self.logger = setup_logging(level=log_level, name="VulnerabilityScanner")
        
        # Initialize components
        self.crawler = AdvancedCrawler(
            base_url=target_url,
            max_depth=max_depth,
            max_urls=max_urls,
            use_js=use_js,
            timeout=timeout,
        )
        
        self.http_client = HTTPClient(timeout=timeout)
        self.risk_engine = RiskEngine()
        
        # Initialize detectors
        self.detectors = [
            # Injection detectors
            SQLInjectionDetector(),
            NoSQLInjectionDetector(),
            CommandInjectionDetector(),
            SSTIDetector(),
            # XSS detector
            XSSDetector(),
            # Security configuration detectors
            SecurityHeaderDetector(),
            CORSDetector(),
            DirectoryIndexingDetector(),
            DirectoryListingDetector(),
            HTTPMethodDetector(),
            FileUploadDetector(),
            CrossSiteRequestForgeryDetector(),
            # Access control detectors
            IDORDetector(),
            AuthenticationDetector(),
        ]
        
        # Results
        self.scan_result = ScanResult(target_url=target_url)
        
    async def scan(self) -> ScanResult:
        """
        Execute complete vulnerability scan.
        
        Returns
        -------
        ScanResult
            Complete scan results with all findings.
        """
        try:
            self.logger.info(f"Starting scan of {self.target_url}")
            
            # Phase 1: Crawl and discover attack surface
            self.logger.info("Phase 1: Discovering attack surface...")
            await self._crawl()
            
            # Phase 2: Active vulnerability testing
            self.logger.info("Phase 2: Testing for vulnerabilities...")
            await self._detect_vulnerabilities()
            
            # Phase 3: Risk scoring and prioritization
            self.logger.info("Phase 3: Calculating risks and scoring...")
            self.scan_result.vulnerabilities = self.risk_engine.assign_severity(
                self.scan_result.vulnerabilities
            )
            self.scan_result.vulnerabilities = self.risk_engine.prioritize(
                self.scan_result.vulnerabilities
            )
            
            # Update summary counts
            self._update_summary()
            
            # Mark end time
            self.scan_result.scan_end_time = datetime.utcnow()
            
            self.logger.info(f"Scan completed. Found {len(self.scan_result.vulnerabilities)} vulnerabilities.")
            return self.scan_result
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}", exc_info=True)
            self.scan_result.scan_end_time = datetime.utcnow()
            return self.scan_result
            
    async def _crawl(self):
        """Crawl target website to discover attack surface."""
        try:
            urls = await self.crawler.crawl()
            self.scan_result.discovered_urls = urls
            self.scan_result.discovered_forms = [
                f.to_dict() for f in self.crawler.discovered_forms
            ]
            self.scan_result.discovered_endpoints = [
                e.to_dict() for e in self.crawler.discovered_endpoints
            ]
            self.logger.info(f"Discovered {len(urls)} URLs")
        except Exception as e:
            self.logger.error(f"Crawling failed: {e}", exc_info=True)
            
    async def _detect_vulnerabilities(self):
        """Test discovered URLs and forms for vulnerabilities."""
        try:
            # Test URLs with GET requests
            urls_to_test = self.scan_result.discovered_urls
            self.logger.info(f"Testing {len(urls_to_test)} URLs")
            
            for url in urls_to_test:
                self.logger.debug(f"Testing {url}")
                
                # Get response
                response = await self.http_client.request(url)
                
                if response.get('error'):
                    self.logger.warning(f"Failed to fetch {url}")
                    continue
                    
                # Prepare evidence dictionary
                evidence = {
                    'request_url': url,
                    'request_method': 'GET',
                    'response_status': response.get('status', 0),
                    'response_headers': response.get('headers', {}),
                    'response_body': response.get('body', ''),
                    'response_length': len(response.get('body', '')),
                }
                
                # Run all detectors on page
                for detector in self.detectors:
                    try:
                        findings = await detector.detect(url, evidence)
                        self.scan_result.vulnerabilities.extend(findings)
                    except Exception as e:
                        self.logger.warning(f"Detector {detector.name} failed on {url}: {e}")
            
            # Test discovered forms with injection payloads
            forms_to_test = self.crawler.discovered_forms
            self.logger.info(f"Testing {len(forms_to_test)} forms with injection payloads")
            
            test_payloads = [
                # SQL Injection - Most important
                "' OR '1'='1",
                "' OR 1=1--",
                "admin' --",
                "' UNION SELECT NULL--",
                
                # XSS Attacks
                "<img src=x onerror=alert('xss')>",
                "\"><script>alert('xss')</script>",
                "<svg/onload=alert('xss')>",
                
                # Command Injection
                ";id",
                "|id",
                
                # SSTI/Template
                "${7*7}",
                "{{7*7}}",
                
                # Other
                "../../../etc/passwd",
                "{'$ne': null}",
            ]
            
            
            for form in forms_to_test:
                # Make URL absolute if action is relative
                form_url = urljoin(form.url, form.action) if form.action else form.url
                self.logger.info(f"Testing form: {form.method} {form_url} with {len(form.fields)} fields")
                
                # Test each form field with payloads
                for field in form.fields:
                    for payload in test_payloads:
                        try:
                            # Prepare form data
                            form_data = {f['name']: payload for f in form.fields}
                            
                            # Send request with payload
                            if form.method.upper() == "POST":
                                response = await self.http_client.request(
                                    form_url,
                                    method="POST",
                                    data=form_data
                                )
                            else:
                                response = await self.http_client.request(
                                    form_url,
                                    method="GET",
                                    params=form_data
                                )
                            
                            if response.get('error'):
                                continue
                            
                            # Prepare evidence
                            evidence = {
                                'request_url': form_url,
                                'request_method': form.method.upper(),
                                'response_status': response.get('status', 0),
                                'response_headers': response.get('headers', {}),
                                'response_body': response.get('body', ''),
                                'response_length': len(response.get('body', '')),
                                'injection_point': field['name'],
                                'payload_used': payload,
                            }
                            
                            # Run injection detectors
                            for detector in self.detectors:
                                if 'Injection' in detector.__class__.__name__ or 'XSS' in detector.__class__.__name__:
                                    try:
                                        findings = await detector.detect(form_url, evidence)
                                        self.scan_result.vulnerabilities.extend(findings)
                                    except Exception as e:
                                        self.logger.debug(f"Detector failed: {e}")
                                        
                        except Exception as e:
                            self.logger.debug(f"Error testing form field {field['name']}: {e}")
            
            # Test URL query parameters with payloads
            self.logger.info(f"Testing URL parameters from discovered URLs")
            from urllib.parse import urlparse, parse_qs
            
            tested_params = set()
            for url in self.crawler.visited_urls:
                try:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    
                    if params:
                        for param_name in params.keys():
                            param_key = f"{url}#{param_name}"
                            if param_key not in tested_params:
                                tested_params.add(param_key)
                                
                                # Test this parameter with payloads
                                for payload in test_payloads[:10]:  # Limit to first 10 payloads per param
                                    try:
                                        test_params = {k: (payload if k == param_name else v[0]) for k, v in params.items()}
                                        response = await self.http_client.request(url.split('?')[0], method="GET", params=test_params)
                                        
                                        if not response.get('error'):
                                            evidence = {
                                                'request_url': url,
                                                'request_method': 'GET',
                                                'response_status': response.get('status', 0),
                                                'response_headers': response.get('headers', {}),
                                                'response_body': response.get('body', ''),
                                                'response_length': len(response.get('body', '')),
                                                'injection_point': param_name,
                                                'payload_used': payload,
                                            }
                                            
                                            # Run injection-specific detectors
                                            for detector in self.detectors:
                                                if any(x in detector.name for x in ['Injection', 'XSS', 'Command', 'SSTI', 'IDOR', 'Authentication']):
                                                    try:
                                                        findings = await detector.detect(url, evidence)
                                                        self.scan_result.vulnerabilities.extend(findings)
                                                    except Exception as e:
                                                        self.logger.debug(f"Detector failed on param: {e}")
                                    except Exception:
                                        pass
                except Exception:
                    pass
                    
        except Exception as e:
            self.logger.error(f"Vulnerability detection failed: {e}", exc_info=True)
            
    def _update_summary(self):
        """Update vulnerability count summary."""
        for vuln in self.scan_result.vulnerabilities:
            if vuln.severity.value == "Critical":
                self.scan_result.critical_count += 1
            elif vuln.severity.value == "High":
                self.scan_result.high_count += 1
            elif vuln.severity.value == "Medium":
                self.scan_result.medium_count += 1
            elif vuln.severity.value == "Low":
                self.scan_result.low_count += 1
            else:
                self.scan_result.info_count += 1


def run_scan(
    target_url: str,
    max_depth: int = 3,
    use_js: bool = False,
    log_level: str = "INFO",
) -> ScanResult:
    """
    Convenience function to run scan synchronously.
    
    Parameters
    ----------
    target_url : str
        Target URL to scan.
    max_depth : int
        Maximum crawl depth.
    use_js : bool
        Enable JavaScript rendering.
    log_level : str
        Logging level.
        
    Returns
    -------
    ScanResult
        Scan results.
    """
    scanner = VulnerabilityScanner(
        target_url=target_url,
        max_depth=max_depth,
        use_js=use_js,
        log_level=log_level,
    )
    return asyncio.run(scanner.scan())
