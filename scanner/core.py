"""Core vulnerability scanner orchestrator."""

import asyncio
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from .crawler.advanced_crawler import AdvancedCrawler
from .detector.injection import SQLInjectionDetector, NoSQLInjectionDetector
from .detector.xss import XSSDetector
from .detector.security_config import (
    SecurityHeaderDetector,
    CORSDetector,
    DirectoryIndexingDetector,
)
from .detector.lfi import LFIDetector, DirectoryTraversalDetector, get_all_lfi_payloads
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
from .utils.response_utils import hash_response


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
            # LFI and Path Traversal detector
            LFIDetector(),
            DirectoryTraversalDetector(),
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
        
        # simple per-host rate limiter helper
        import random
        async def _limited_request(url, **kwargs):
            resp = await self.http_client.request(url, **kwargs)
            self.scan_result.total_payloads_sent += 1
            await asyncio.sleep(random.uniform(0.2, 0.5))
            return resp
        self._limited_request = _limited_request
        
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
            urls_to_test = self.scan_result.discovered_urls
            self.logger.info(f"Testing {len(urls_to_test)} URLs")

            # capture detailed baseline for each unique endpoint
            from scanner.utils.response_utils import capture_baseline
            import random

            for url in urls_to_test:
                clean = url.split('?', 1)[0]
                if clean not in self._baseline_responses:
                    try:
                        resp = await self.http_client.request(clean)
                        self.scan_result.total_payloads_sent += 1
                        baseline_record = capture_baseline(resp)
                        self._baseline_responses[clean] = baseline_record
                        self.logger.debug(f"Baseline captured for {clean}: status={resp.get('status')}, hash={baseline_record.get('hash', '')[:16]}...")
                    except Exception as e:
                        self.logger.debug(f"Failed to fetch baseline for {clean}: {e}")
                        self._baseline_responses[clean] = {}
                    # simple rate-limiting: small random delay between requests
                    await asyncio.sleep(random.uniform(0.2, 0.5))

            # helper closure to process any response, run detectors and AI
            async def _evaluate(url: str, baseline: Dict, payload: str, extra_evidence: Dict[str, Any], response: Dict[str, Any]):
                # Get hashes for debugging
                baseline_hash = baseline.get('hash', '') if baseline else ''
                response_body = response.get('body', '')
                response_hash = hash_response(response_body) if response_body else ''
                
                # Debug logging for injection testing
                self.logger.debug(f"[INJECTION] URL: {url}")
                self.logger.debug(f"[INJECTION] Method: {extra_evidence.get('request_method', 'GET')}")
                self.logger.debug(f"[INJECTION] Payload: {payload}")
                self.logger.debug(f"[INJECTION] Injection Point: {extra_evidence.get('injection_point', 'unknown')}")
                self.logger.debug(f"[INJECTION] Baseline Hash: {baseline_hash[:16] if baseline_hash else 'None'}...")
                self.logger.debug(f"[INJECTION] Response Hash: {response_hash[:16] if response_hash else 'None'}...")
                self.logger.debug(f"[INJECTION] Response Status: {response.get('status', 0)}")
                self.logger.debug(f"[INJECTION] Response Different: {baseline_hash != response_hash if baseline_hash and response_hash else 'N/A'}")
                
                # build full evidence
                evidence = {
                    'request_url': url,
                    'request_method': extra_evidence.get('request_method', 'GET'),
                    'response_status': response.get('status', 0),
                    'response_headers': response.get('headers', {}),
                    'response_body': response_body,
                    'response_length': len(response_body),
                    'injection_point': extra_evidence.get('injection_point'),
                    'payload_used': payload,
                    'baseline_response': baseline,
                    'response_hash': response_hash,
                    'baseline_hash': baseline_hash,
                }
                
                # attach ai decision information if available
                features = self.response_analyzer.analyze(response, baseline, payload)
                ai_decision = self.ai_selector.select(features)
                evidence['ai_decision'] = ai_decision
                evidence['metadata'] = {'priority_score': ai_decision.get('priority_score', 0.0)}

                # Determine canonical clean URL for security headers using baseline if available
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
                        
                        # Log if any findings detected
                        if findings:
                            self.logger.info(f"[DETECTOR {detector.name}] Found {len(findings)} vulnerabilities for {url} with payload: {payload[:50]}...")
                        
                        # Deduplicate findings before adding
                        unique_findings = []
                        for f in findings:
                            # Create unique key for this vulnerability
                            vuln_type = f.type.value if hasattr(f.type, 'value') else str(f.type)

                            # For security headers and CORS, use only the base URL for deduplication
                            if 'SECURITY' in vuln_type.upper() or 'CORS' in vuln_type.upper():
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
                                    getattr(f, 'affected_parameter', None) or injection_point or 'unknown'
                                )
                            
                            # Only add if not already found
                            if vuln_key not in self._found_vulnerabilities:
                                self._found_vulnerabilities[vuln_key] = True
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
                            if extra_evidence.get('request_method', 'GET') == 'POST':
                                new_resp = await self._limited_request(url, method="POST", data=extra_evidence.get('data'))
                                full_url = url
                            else:
                                param_name = extra_evidence.get('injection_point')
                                new_params = {param_name: mp} if param_name else {}
                                new_resp = self._limited_request(url, params=new_params)
                                parsed = urlparse(url)
                                clean_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                full_url = clean_base + "?" + urlencode(new_params)
                            self.scan_result.total_payloads_sent += 1
                            new_evidence = evidence.copy()
                            new_evidence['payload_used'] = mp
                            new_evidence['request_url'] = full_url
                            for detector in self.detectors:
                                if isinstance(detector, SecurityHeaderDetector):
                                    continue
                                try:
                                    findings = await detector.detect(url, new_evidence)
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
                        except Exception:
                            pass

            # iterate over each discovered URL for baseline tests plus checks
            for url in urls_to_test:
                parsed = urlparse(url)
                clean = parsed.scheme + "://" + parsed.netloc + parsed.path
                
                # IMPORTANT: Capture baseline from the ORIGINAL URL (with parameters)
                # not the clean URL, so comparison is meaningful
                if url not in self._baseline_responses:
                    try:
                        resp = await self.http_client.request(url)
                        self.scan_result.total_payloads_sent += 1
                        baseline_record = capture_baseline(resp)
                        self._baseline_responses[url] = baseline_record
                        self.logger.debug(f"[BASELINE] Original URL baseline: {url}")
                        self.logger.debug(f"[BASELINE] Status: {resp.get('status')}, Hash: {baseline_record.get('hash', '')[:16]}...")
                    except Exception as e:
                        self.logger.debug(f"Failed to fetch baseline for {url}: {e}")
                        self._baseline_responses[url] = {}
                    await asyncio.sleep(0.2)
                
                baseline = self._baseline_responses.get(url, {})

                # check query parameters if present
                params = parse_qs(parsed.query)
                if params:
                    self.logger.debug(f"[PARAM_EXTRACT] URL: {url}")
                    self.logger.debug(f"[PARAM_EXTRACT] Parameters found: {list(params.keys())}")
                    
                    for param_name, values in params.items():
                        original_value = values[0] if values else ''
                        self.logger.debug(f"[PARAM_INJECT] Target param: {param_name}, Original value: {original_value}")
                        
                        # Get both true and false boolean payloads for proper testing
                        error_payloads = get_payloads('sqli_error')
                        boolean_true_payloads = get_payloads('sqli_boolean_true')
                        boolean_false_payloads = get_payloads('sqli_boolean_false')
                        xss_payloads = self.xss_payloads
                        lfi_payloads = get_payloads('lfi')
                        
                        all_payloads = error_payloads + xss_payloads + lfi_payloads
                        
                        for payload in all_payloads:
                            # Build test parameters - ONLY replace target param, preserve others
                            test_params = {}
                            for k, v in params.items():
                                if k == param_name:
                                    test_params[k] = payload
                                else:
                                    test_params[k] = v[0] if v else ''
                            
                            # Reconstruct URL with mutated parameters
                            from urllib.parse import urlencode as urllib_urlencode
                            query_string = urllib_urlencode(test_params, doseq=True)
                            full_url = f"{clean}?{query_string}"
                            
                            self.logger.debug(f"[PARAM_MUTATE] Original: {url}")
                            self.logger.debug(f"[PARAM_MUTATE] Mutated:  {full_url}")
                            self.logger.debug(f"[PARAM_MUTATE] Payload: {payload[:50]}...")
                            
                            try:
                                resp = await self._limited_request(clean, method="GET", params=test_params)
                                if resp.get('error'):
                                    self.logger.debug(f"[PARAM_TEST] Error fetching: {resp.get('error')}")
                                    continue
                                    
                                resp_hash = hash_response(resp.get('body', ''))
                                baseline_hash = baseline.get('hash', '')
                                
                                self.logger.debug(f"[PARAM_COMPARE] Baseline hash: {baseline_hash[:16] if baseline_hash else 'None'}...")
                                self.logger.debug(f"[PARAM_COMPARE] Response hash:  {resp_hash[:16] if resp_hash else 'None'}...")
                                self.logger.debug(f"[PARAM_COMPARE] Hashes differ: {baseline_hash != resp_hash if baseline_hash and resp_hash else 'N/A'}")
                                
                                await _evaluate(full_url, baseline, payload, {'request_method': 'GET', 'injection_point': param_name}, resp)
                            except Exception as e:
                                self.logger.debug(f"[PARAM_TEST] Exception: {e}")
                                pass
                        
                        # Boolean-based testing: send true/false pairs together
                        self.logger.debug(f"[BOOLEAN_TEST] Testing boolean pairs for {param_name}")
                        for true_payload, false_payload in zip(boolean_true_payloads, boolean_false_payloads):
                            try:
                                # Test TRUE payload
                                test_params_true = {}
                                for k, v in params.items():
                                    if k == param_name:
                                        test_params_true[k] = true_payload
                                    else:
                                        test_params_true[k] = v[0] if v else ''
                                
                                from urllib.parse import urlencode as urllib_urlencode
                                query_true = urllib_urlencode(test_params_true, doseq=True)
                                full_url_true = f"{clean}?{query_true}"
                                
                                resp_true = await self._limited_request(clean, method="GET", params=test_params_true)
                                resp_true_hash = hash_response(resp_true.get('body', ''))
                                
                                self.logger.debug(f"[BOOLEAN] TRUE Payload: {true_payload[:50]}...")
                                self.logger.debug(f"[BOOLEAN] TRUE Response Hash: {resp_true_hash[:16] if resp_true_hash else 'None'}...")
                                
                                if not resp_true.get('error'):
                                    await _evaluate(full_url_true, baseline, true_payload, {'request_method': 'GET', 'injection_point': param_name, 'boolean_pair': 'true'}, resp_true)
                                
                                # Test FALSE payload
                                test_params_false = {}
                                for k, v in params.items():
                                    if k == param_name:
                                        test_params_false[k] = false_payload
                                    else:
                                        test_params_false[k] = v[0] if v else ''
                                
                                query_false = urllib_urlencode(test_params_false, doseq=True)
                                full_url_false = f"{clean}?{query_false}"
                                
                                resp_false = await self._limited_request(clean, method="GET", params=test_params_false)
                                resp_false_hash = hash_response(resp_false.get('body', ''))
                                
                                self.logger.debug(f"[BOOLEAN] FALSE Payload: {false_payload[:50]}...")
                                self.logger.debug(f"[BOOLEAN] FALSE Response Hash: {resp_false_hash[:16] if resp_false_hash else 'None'}...")
                                
                                if not resp_false.get('error'):
                                    await _evaluate(full_url_false, baseline, false_payload, {'request_method': 'GET', 'injection_point': param_name, 'boolean_pair': 'false'}, resp_false)
                                
                                # Log response difference for boolean pair
                                if resp_true_hash and resp_false_hash:
                                    self.logger.debug(f"[BOOLEAN] TRUE != FALSE: {resp_true_hash != resp_false_hash}")
                                    
                            except Exception as e:
                                self.logger.debug(f"[BOOLEAN_TEST] Exception: {e}")
                                pass

                # directory traversal probes
                # Ensure proper URL joining - add trailing slash if not present
                base_for_traversal = clean if clean.endswith('/') else clean + '/'
                for payload in get_payloads('dir_traversal'):
                    target = base_for_traversal + payload
                    try:
                        resp = await self._limited_request(target)
                        if not resp.get('error'):
                            await _evaluate(target, baseline, payload, {'request_method': 'GET'}, resp)
                    except Exception:
                        pass

                # open redirect probes (append as ?next=... or similar)
                for payload in get_payloads('open_redirect'):
                    try:
                        resp = await self._limited_request(clean, method="GET", params={'next': payload})
                        if not resp.get('error'):
                            await _evaluate(url, baseline, payload, {'request_method': 'GET', 'injection_point': 'next'}, resp)
                    except Exception:
                        pass

                # unsafe HTTP methods
                for method in get_payloads('http_methods'):
                    try:
                        resp = await self._limited_request(clean, method=method)
                        self.scan_result.total_payloads_sent += 1
                        if resp.get('status', 0) not in (405, 501):
                            evidence = {
                                'request_url': clean,
                                'request_method': method,
                                'response_status': resp.get('status', 0),
                                'response_body': resp.get('body', ''),
                            }
                            for detector in self.detectors:
                                if isinstance(detector, HTTPMethodDetector):
                                    findings = await detector.detect(clean, evidence)
                                    self.scan_result.vulnerabilities.extend(findings)
                    except Exception:
                        pass

            # forms submission
            forms_to_test = self.crawler.discovered_forms
            self.logger.info(f"Testing {len(forms_to_test)} forms with injection payloads")

            for form in forms_to_test:
                form_url = urljoin(form.url, form.action) if form.action else form.url
                
                # Get baseline for form URL
                if form_url not in self._baseline_responses:
                    try:
                        resp = await self.http_client.request(form_url)
                        self.scan_result.total_payloads_sent += 1
                        baseline_record = capture_baseline(resp)
                        self._baseline_responses[form_url] = baseline_record
                        self.logger.debug(f"[FORM_BASELINE] URL: {form_url}")
                        self.logger.debug(f"[FORM_BASELINE] Status: {resp.get('status')}, Hash: {baseline_record.get('hash', '')[:16]}...")
                    except Exception as e:
                        self.logger.debug(f"Failed to fetch baseline for form {form_url}: {e}")
                        self._baseline_responses[form_url] = {}
                    await asyncio.sleep(0.2)
                
                form_baseline = self._baseline_responses.get(form_url, {})
                
                # Extract field names and default values
                field_names = [f['name'] for f in form.fields]
                field_defaults = {f['name']: f.get('value', '') for f in form.fields}
                
                self.logger.debug(f"[FORM_EXTRACT] Form URL: {form_url}")
                self.logger.debug(f"[FORM_EXTRACT] Method: {form.method.upper()}")
                self.logger.debug(f"[FORM_EXTRACT] Fields: {field_names}")
                
                for field in form.fields:
                    field_name = field['name']
                    self.logger.debug(f"[FORM_TARGET] Testing field: {field_name}")
                    
                    # Get payloads for injection
                    error_payloads = get_payloads('sqli_error')
                    boolean_true_payloads = get_payloads('sqli_boolean_true')
                    boolean_false_payloads = get_payloads('sqli_boolean_false')
                    xss_payloads = self.xss_payloads
                    
                    all_payloads = error_payloads + xss_payloads
                    
                    for payload in all_payloads:
                        try:
                            # Build form data: ONLY replace target field, PRESERVE other field values/defaults
                            form_data = {}
                            for f in form.fields:
                                if f['name'] == field_name:
                                    form_data[f['name']] = payload
                                else:
                                    # Use the field's default value, or empty string
                                    form_data[f['name']] = f.get('value', '')
                            
                            self.logger.debug(f"[FORM_MUTATE] Target field: {field_name}")
                            self.logger.debug(f"[FORM_MUTATE] Payload: {payload[:50]}...")
                            self.logger.debug(f"[FORM_MUTATE] Form data keys: {list(form_data.keys())}")
                            self.logger.debug(f"[FORM_MUTATE] Injected field value: {form_data[field_name][:50]}...")
                            
                            if form.method.upper() == "POST":
                                resp = await self._limited_request(form_url, method="POST", data=form_data)
                            else:
                                resp = await self._limited_request(form_url, method="GET", params=form_data)
                            
                            self.scan_result.total_payloads_sent += 1
                            
                            if resp.get('error'):
                                self.logger.debug(f"[FORM_TEST] Error: {resp.get('error')}")
                                continue
                            
                            resp_hash = hash_response(resp.get('body', ''))
                            baseline_hash = form_baseline.get('hash', '')
                            
                            self.logger.debug(f"[FORM_COMPARE] Baseline hash: {baseline_hash[:16] if baseline_hash else 'None'}...")
                            self.logger.debug(f"[FORM_COMPARE] Response hash:  {resp_hash[:16] if resp_hash else 'None'}...")
                            self.logger.debug(f"[FORM_COMPARE] Hashes differ: {baseline_hash != resp_hash if baseline_hash and resp_hash else 'N/A'}")
                            
                            await _evaluate(form_url, form_baseline, payload, {'request_method': form.method.upper(), 'injection_point': field_name, 'data': form_data}, resp)
                        except Exception as e:
                            self.logger.debug(f"[FORM_TEST] Exception: {e}")
                            pass
                    
                    # Boolean-based testing for form fields
                    self.logger.debug(f"[FORM_BOOLEAN] Testing boolean pairs for {field_name}")
                    for true_payload, false_payload in zip(boolean_true_payloads, boolean_false_payloads):
                        try:
                            # Test TRUE payload
                            form_data_true = {}
                            for f in form.fields:
                                if f['name'] == field_name:
                                    form_data_true[f['name']] = true_payload
                                else:
                                    form_data_true[f['name']] = f.get('value', '')
                            
                            self.logger.debug(f"[FORM_BOOLEAN] TRUE Payload: {true_payload[:50]}...")
                            
                            if form.method.upper() == "POST":
                                resp_true = await self._limited_request(form_url, method="POST", data=form_data_true)
                            else:
                                resp_true = await self._limited_request(form_url, method="GET", params=form_data_true)
                            
                            resp_true_hash = hash_response(resp_true.get('body', ''))
                            self.logger.debug(f"[FORM_BOOLEAN] TRUE Response Hash: {resp_true_hash[:16] if resp_true_hash else 'None'}...")
                            
                            if not resp_true.get('error'):
                                await _evaluate(form_url, form_baseline, true_payload, {'request_method': form.method.upper(), 'injection_point': field_name, 'data': form_data_true, 'boolean_pair': 'true'}, resp_true)
                            
                            # Test FALSE payload
                            form_data_false = {}
                            for f in form.fields:
                                if f['name'] == field_name:
                                    form_data_false[f['name']] = false_payload
                                else:
                                    form_data_false[f['name']] = f.get('value', '')
                            
                            self.logger.debug(f"[FORM_BOOLEAN] FALSE Payload: {false_payload[:50]}...")
                            
                            if form.method.upper() == "POST":
                                resp_false = await self._limited_request(form_url, method="POST", data=form_data_false)
                            else:
                                resp_false = await self._limited_request(form_url, method="GET", params=form_data_false)
                            
                            resp_false_hash = hash_response(resp_false.get('body', ''))
                            self.logger.debug(f"[FORM_BOOLEAN] FALSE Response Hash: {resp_false_hash[:16] if resp_false_hash else 'None'}...")
                            
                            if not resp_false.get('error'):
                                await _evaluate(form_url, form_baseline, false_payload, {'request_method': form.method.upper(), 'injection_point': field_name, 'data': form_data_false, 'boolean_pair': 'false'}, resp_false)
                            
                            # Log response difference for boolean pair
                            if resp_true_hash and resp_false_hash:
                                self.logger.debug(f"[FORM_BOOLEAN] TRUE != FALSE: {resp_true_hash != resp_false_hash}")
                                
                        except Exception as e:
                            self.logger.debug(f"[FORM_BOOLEAN] Exception: {e}")
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
