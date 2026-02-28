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
# New detectors
from .detector.xxe import XXEDetector
from .detector.info_disclosure import InformationDisclosureDetector
from .detector.ssrf import SSRFDetector
from .risk_engine.cvss_engine import RiskEngine
from .utils.models import ScanResult, Vulnerability
from .utils.logging_util import setup_logging
from .utils.http_client import HTTPClient

# new helpers for AI-assisted scanning
from .payload_database import get_payloads
from .response_analyzer import ResponseAnalyzer
from .ai_selector import AISelector
from .mutation_engine import MutationEngine


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
        xss_payloads: Optional[List[str]] = None,
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
        
        # allow custom xss payload list or default from database
        self.xss_payloads = xss_payloads if xss_payloads is not None else get_payloads('xss')

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
            # New enhanced detectors
            XXEDetector(),
            InformationDisclosureDetector(),
            SSRFDetector(),
        ]
        
        # Results
        self.scan_result = ScanResult(target_url=target_url)

        # Track unique vulnerabilities to prevent duplicates
        # Key: (vulnerability_type, url, parameter/injection_point)
        self._found_vulnerabilities: Dict[tuple, bool] = {}
        
        # Track which URLs have already had security headers checked
        self._security_headers_checked: set = set()

        # baseline responses for comparison during analysis
        self._baseline_responses: Dict[str, Dict] = {}

        # AI/analysis helpers
        self.response_analyzer = ResponseAnalyzer()
        self.ai_selector = AISelector()
        self.mutation_engine = MutationEngine()
        
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
        """Test discovered URLs and forms for vulnerabilities.

        The method has been significantly enhanced to make use of the
        payload database, response analysis and AI-assisted mutation.  It
        still preserves the original detectors for backwards compatibility.
        """
        try:
            urls_to_test = self.scan_result.discovered_urls
            self.logger.info(f"Testing {len(urls_to_test)} URLs")

            # fetch a baseline response for each unique clean URL (no query params)
            from urllib.parse import urlparse

            for url in urls_to_test:
                clean = url.split('?', 1)[0]
                if clean not in self._baseline_responses:
                    try:
                        resp = await self.http_client.request(clean)
                        self.scan_result.total_payloads_sent += 1
                        self._baseline_responses[clean] = resp
                    except asyncio.CancelledError:
                        self.logger.warning(f"Baseline request cancelled for {clean}")
                        self._baseline_responses[clean] = {}
                    except asyncio.TimeoutError:
                        self.logger.warning(f"Baseline request timeout for {clean}")
                        self._baseline_responses[clean] = {}
                    except Exception as e:
                        self.logger.debug(f"Failed to fetch baseline for {clean}: {e}")
                        self._baseline_responses[clean] = {}

            # helper closure to process any response, run detectors and AI
            async def _evaluate(url: str, baseline: Dict, payload: str, extra_evidence: Dict[str, Any], response: Dict[str, Any]):
                # build full evidence
                evidence = {
                    'request_url': url,
                    'request_method': extra_evidence.get('request_method', 'GET'),
                    'response_status': response.get('status', 0),
                    'response_headers': response.get('headers', {}),
                    'response_body': response.get('body', ''),
                    'response_length': len(response.get('body', '')),
                    'injection_point': extra_evidence.get('injection_point'),
                    'payload_used': payload,
                    'baseline_response': baseline,
                }
                # attach ai decision information if available
                features = self.response_analyzer.analyze(response, baseline, payload)
                ai_decision = self.ai_selector.select(features)
                evidence['ai_decision'] = ai_decision
                evidence['metadata'] = {'priority_score': ai_decision.get('priority_score', 0.0)}

                # Determine canonical clean URL for security headers using baseline if available
                from urllib.parse import urlparse
                base_for_headers = baseline.get('url') if isinstance(baseline, dict) and baseline.get('url') else url
                parsed_url = urlparse(base_for_headers)
                clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

                # Determine if we should run security header detector for this URL (only once per unique URL)
                run_security_headers = False
                if clean_url not in self._security_headers_checked:
                    self._security_headers_checked.add(clean_url)
                    run_security_headers = True
                    # Use baseline response headers for security header detection
                    evidence['response_headers'] = baseline.get('headers', {})

                # run detectors
                for detector in self.detectors:
                    # Skip SecurityHeaderDetector unless it's the first run for this URL
                    if isinstance(detector, SecurityHeaderDetector) and not run_security_headers:
                        continue
                        
                    try:
                        findings = await detector.detect(url, evidence)
                        
                        # Deduplicate findings before adding
                        unique_findings = []
                        for f in findings:
                            # Create unique key for this vulnerability. dataclass uses `type` and `target_url`.
                            vuln_type = f.type.value if hasattr(f.type, 'value') else str(f.type)

                            # For security headers and CORS, use only the base URL (without query params) for deduplication
                            # This prevents duplicate reports for the same missing headers across different payloads/params
                            if 'SECURITY' in vuln_type.upper() or 'CORS' in vuln_type.upper():
                                # For header/CORS bugs, use the baseline URL if we have one, so that
                                # variations from payloads or mutated paths do not produce new keys.
                                base_key_url = baseline.get('url') if isinstance(baseline, dict) and baseline.get('url') else f.target_url
                                parsed = urlparse(base_key_url)
                                clean_vuln_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                vuln_key = (vuln_type, clean_vuln_url)
                            else:
                                # For other vulnerabilities, include the parameter/injection_point
                                injection_point = extra_evidence.get('injection_point', '')
                                vuln_key = (
                                    vuln_type,
                                    f.target_url,
                                    # `affected_parameter` is used by the Vulnerability model
                                    getattr(f, 'affected_parameter', None) or injection_point or 'unknown'
                                )
                            
                            # Only add if not already found
                            if vuln_key not in self._found_vulnerabilities:
                                self._found_vulnerabilities[vuln_key] = True
                                # enrich each finding with priority if not already set
                                if not f.metadata:
                                    f.metadata = {}
                                f.metadata.setdefault('priority_score', ai_decision.get('priority_score', 0.0))
                                unique_findings.append(f)
                        
                        self.scan_result.vulnerabilities.extend(unique_findings)
                    except Exception as e:
                        self.logger.debug(f"Detector {detector.name} failed during evaluation: {e}")

                # if AI suggested mutation strategies, generate and re-test once
                if ai_decision.get('mutation_strategies'):
                    mutated = self.mutation_engine.mutate(payload, ai_decision['mutation_strategies'])
                    for mp in mutated:
                        try:
                            # simple re-request with mutated payload using same params or body
                            if extra_evidence.get('request_method', 'GET') == 'POST':
                                new_resp = await self.http_client.request(url, method="POST", data=extra_evidence.get('data'))
                                full_url = url
                            else:
                                # build parameter dict and compute full URL for mutated request
                                param_name = extra_evidence.get('injection_point')
                                new_params = {param_name: mp} if param_name else {}
                                new_resp = await self.http_client.request(url, params=new_params)
                                from urllib.parse import urlencode, urlparse
                                parsed = urlparse(url)
                                clean_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                full_url = clean_base + "?" + urlencode(new_params)
                            self.scan_result.total_payloads_sent += 1
                            # run detectors again but don't loop into AI again
                            new_evidence = evidence.copy()
                            new_evidence['payload_used'] = mp
                            new_evidence['request_url'] = full_url
                            # deduplicate mutated findings as well
                            for detector in self.detectors:
                                # skip security headers on mutation runs (already checked above)
                                if isinstance(detector, SecurityHeaderDetector):
                                    continue
                                try:
                                    findings = await detector.detect(url, new_evidence)
                                    # perform same deduplication logic as above
                                    for f in findings:
                                        vuln_type = f.type.value if hasattr(f.type, 'value') else str(f.type)
                                        if 'SECURITY' in vuln_type.upper() or 'CORS' in vuln_type.upper():
                                            base_key_url = baseline.get('url') if isinstance(baseline, dict) and baseline.get('url') else f.target_url
                                            parsed = urlparse(base_key_url)
                                            clean_vuln_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                            vuln_key = (vuln_type, clean_vuln_url)
                                        else:
                                            injection_point = extra_evidence.get('injection_point', '')
                                            vuln_key = (
                                                vuln_type,
                                                f.target_url,
                                                getattr(f, 'affected_parameter', None) or injection_point or 'unknown'
                                            )
                                        if vuln_key not in self._found_vulnerabilities:
                                            self._found_vulnerabilities[vuln_key] = True
                                            if not f.metadata:
                                                f.metadata = {}
                                            f.metadata.setdefault('priority_score', ai_decision.get('priority_score', 0.0))
                                            self.scan_result.vulnerabilities.append(f)
                                except Exception:
                                    pass
                        except (asyncio.CancelledError, asyncio.TimeoutError):
                            self.logger.debug(f"Timeout on mutated payload")
                            continue
                        except Exception:
                            pass

            # iterate over each discovered URL for baseline tests plus checks
            from urllib.parse import urlparse, parse_qs

            for url in urls_to_test:
                parsed = urlparse(url)
                clean = parsed.scheme + "://" + parsed.netloc + parsed.path
                baseline = self._baseline_responses.get(clean, {})

                # check query parameters if present
                params = parse_qs(parsed.query)
                if params:
                    for param_name, values in params.items():
                        payloads = get_payloads('sqli_error') + get_payloads('sqli_boolean') + self.xss_payloads
                        for payload in payloads:
                            test_params = {k: (payload if k == param_name else v[0]) for k, v in params.items()}
                            try:
                                resp = await self.http_client.request(clean, method="GET", params=test_params)
                                self.scan_result.total_payloads_sent += 1
                                if resp.get('error'):
                                    continue
                                # build a full URL reflecting the injected payload so that
                                # evidence.request_url accurately represents what was sent
                                from urllib.parse import urlencode
                                full_url = clean + "?" + urlencode(test_params, doseq=True)
                                await _evaluate(full_url, baseline, payload, {'request_method': 'GET', 'injection_point': param_name}, resp)
                            except (asyncio.CancelledError, asyncio.TimeoutError):
                                self.logger.debug(f"Timeout testing {param_name}")
                                continue
                            except Exception:
                                pass

                # directory traversal probes
                for payload in get_payloads('dir_traversal'):
                    target = clean + payload
                    try:
                        resp = await self.http_client.request(target)
                        self.scan_result.total_payloads_sent += 1
                        if not resp.get('error'):
                            await _evaluate(target, baseline, payload, {'request_method': 'GET'}, resp)
                    except (asyncio.CancelledError, asyncio.TimeoutError):
                        self.logger.debug(f"Timeout on {target}")
                        continue
                    except Exception:
                        pass

                # open redirect probes (append as ?next=... or similar)
                for payload in get_payloads('open_redirect'):
                    try:
                        resp = await self.http_client.request(clean, method="GET", params={'next': payload})
                        self.scan_result.total_payloads_sent += 1
                        if not resp.get('error'):
                            await _evaluate(url, baseline, payload, {'request_method': 'GET', 'injection_point': 'next'}, resp)
                    except (asyncio.CancelledError, asyncio.TimeoutError):
                        self.logger.debug(f"Timeout on redirect probe")
                        continue
                    except Exception:
                        pass

                # unsafe HTTP methods
                for method in get_payloads('http_methods'):
                    try:
                        resp = await self.http_client.request(clean, method=method)
                        self.scan_result.total_payloads_sent += 1
                        if resp.get('status', 0) not in (405, 501):
                            evidence = {
                                'request_url': clean,
                                'request_method': method,
                                'response_status': resp.get('status', 0),
                                'response_body': resp.get('body', ''),
                            }
                            # record as potential misconfiguration
                            for detector in self.detectors:
                                if isinstance(detector, HTTPMethodDetector):
                                    findings = await detector.detect(clean, evidence)
                                    self.scan_result.vulnerabilities.extend(findings)
                    except (asyncio.CancelledError, asyncio.TimeoutError):
                        self.logger.debug(f"Timeout testing {method}")
                        continue
                    except Exception:
                        pass

            # forms submission (previous behaviour, but using payload database)
            forms_to_test = self.crawler.discovered_forms
            self.logger.info(f"Testing {len(forms_to_test)} forms with injection payloads")

            for form in forms_to_test:
                form_url = urljoin(form.url, form.action) if form.action else form.url
                for field in form.fields:
                    payloads = get_payloads('sqli_error') + self.xss_payloads
                    for payload in payloads:
                        try:
                            form_data = {f['name']: payload for f in form.fields}
                            if form.method.upper() == "POST":
                                resp = await self.http_client.request(form_url, method="POST", data=form_data)
                            else:
                                resp = await self.http_client.request(form_url, method="GET", params=form_data)
                            self.scan_result.total_payloads_sent += 1
                            if resp.get('error'):
                                continue
                            await _evaluate(form_url, baseline, payload, {'request_method': form.method.upper(), 'injection_point': field['name'], 'data': form_data}, resp)
                        except (asyncio.CancelledError, asyncio.TimeoutError):
                            self.logger.debug(f"Timeout on form {form_url}")
                            continue
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
