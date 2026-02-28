"""SSRF (Server-Side Request Forgery) detection module."""

import logging
from typing import List, Dict, Any
from .base import BaseDetector
from ..utils.models import Vulnerability
from ..utils.constants import VulnerabilityType, Severity


logger = logging.getLogger(__name__)


class SSRFDetector(BaseDetector):
    """Detects Server-Side Request Forgery (SSRF) vulnerabilities."""
    
    # SSRF test payloads - various protocols and internal addresses
    SSRF_PAYLOADS = [
        'http://localhost/',
        'http://127.0.0.1/',
        'http://[::1]/',
        'http://169.254.169.254/',  # AWS metadata
        'http://metadata.google.internal/',  # GCP metadata
        'http://metadata.google.com/',
        'file:///etc/passwd',
        'gopher://127.0.0.1:6379/_INFO',
        'http://0.0.0.0/',
        'http://0x7f000001/',  # Hex localhost
    ]
    
    # Indicators that SSRF might have succeeded
    SSRF_SUCCESS_INDICATORS = [
        # AWS metadata service responses
        'ami-id',
        'instance-id',
        'local-hostname',
        'local-ipv4',
        # Generic internal network indicators
        'internal',
        'localhost',
        '127.0.0.1',
        '::1',
        # File content indicators
        'root:',
        'daemon:',
        'bin:',
    ]
    
    def __init__(self):
        """Initialize SSRF detector."""
        super().__init__("SSRFDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Detect SSRF vulnerabilities."""
        findings = []
        
        try:
            response_body = evidence.get('response_body', '')
            response_body_lower = response_body.lower()
            response_status = evidence.get('response_status', 0)
            payload_used = evidence.get('payload_used', '')
            injection_point = evidence.get('injection_point', '')
            
            # Check if payload is SSRF-related
            is_ssrf_payload = any(p in payload_used for p in [
                'localhost', '127.0.0.1', '0.0.0.0', '169.254',
                'metadata.google', 'file://', 'gopher://', '0x7f'
            ])
            
            if is_ssrf_payload:
                # Check for success indicators
                for indicator in self.SSRF_SUCCESS_INDICATORS:
                    if indicator in response_body_lower:
                        findings.append(Vulnerability(
                            vulnerability_type=VulnerabilityType.OPEN_REDIRECT,  # Using OPEN_REDIRECT as SSRF not in enum
                            title='Server-Side Request Forgery (SSRF)',
                            description=f'SSRF vulnerability detected. Internal resource access possible: {indicator}',
                            severity=Severity.CRITICAL,
                            confidence=0.85,
                            url=target_url,
                            parameter=injection_point or 'unknown',
                            payload_used=payload_used,
                            evidence=f'SSRF success indicator: {indicator}',
                        ))
                        return findings
                
                # If it's an SSRF payload but no clear success, flag as potential
                if response_status == 200 and len(response_body) > 0:
                    findings.append(Vulnerability(
                        vulnerability_type=VulnerabilityType.OPEN_REDIRECT,
                        title='Server-Side Request Forgery (Potential)',
                        description='SSRF payload returned a response. Manual verification recommended.',
                        severity=Severity.MEDIUM,
                        confidence=0.50,
                        url=target_url,
                        parameter=injection_point or 'unknown',
                        payload_used=payload_used,
                        evidence='SSRF payload returned HTTP 200',
                    ))
                    
        except Exception as e:
            logger.debug(f"SSRF detection error: {e}")
            
        return findings
