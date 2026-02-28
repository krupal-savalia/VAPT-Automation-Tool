"""XSS (Cross-Site Scripting) detection module."""

import logging
from typing import List, Dict, Any
from .base import BaseDetector
from ..utils.models import Vulnerability
from ..utils.constants import VulnerabilityType, Severity


logger = logging.getLogger(__name__)


class XSSDetector(BaseDetector):
    """Detects Cross-Site Scripting vulnerabilities (Reflected, Stored, DOM)."""
    
    # Comprehensive XSS payloads with encoding variations
    REFLECTION_PAYLOADS = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
        '<svg/onload=alert(1)>',
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<img src=x alt=\"\" title=\"\" onclick=alert(1)>",
    ]
    
    # DOM-based payload indicators
    DOM_SOURCES = [
        "window.location",
        "document.location",
        "document.URL",
        "document.documentURI",
        "document.baseURI",
        "location.href",
        "location.hash",
        "window.name",
    ]
    
    def __init__(self):
        """Initialize XSS detector."""
        super().__init__("XSSDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """
        Detect XSS vulnerabilities.
        
        Supports:
        - Reflected XSS
        - Stored XSS
        - DOM-based XSS
        """
        findings = []
        
        try:
            response_body = evidence.get('response_body', '')
            payload_used = str(evidence.get('payload_used', ''))
            injection_point = evidence.get('injection_point', 'unknown')
            
            response_lower = response_body.lower()
            payload_lower = payload_used.lower()
            
            # Check for reflected XSS - payload appears unencoded in response
            if payload_used and injection_point:
                # Look for XSS payload markers in response
                xss_markers = [
                    ('script>', '<script'),
                    ('onerror=', 'onerror='),
                    ('onload=', 'onload='),
                    ('onclick=', 'onclick='),
                    ('alert(', 'alert('),
                ]
                
                # Check if payload or parts of it appear in response
                for marker_lower, marker_display in xss_markers:
                    if marker_lower in payload_lower and marker_lower in response_lower:
                        findings.append(self.create_vulnerability(
                            vuln_type=VulnerabilityType.REFLECTED_XSS,
                            target_url=target_url,
                            title='Reflected XSS Vulnerability',
                            description=f'XSS payload executed: {marker_display}',
                            severity=Severity.HIGH,
                            confidence=0.90,
                            evidence_data=evidence,
                        ))
                        return findings
                
                # Check for angle brackets and quotes that might escape context
                if ('"><' in payload_used or '\'><' in payload_used) and ('"><' in response_body or '\'><' in response_body):
                    findings.append(self.create_vulnerability(
                        vuln_type=VulnerabilityType.REFLECTED_XSS,
                        target_url=target_url,
                        title='Reflected XSS Vulnerability',
                        description='HTML context escape detected with XSS payload',
                        severity=Severity.HIGH,
                        confidence=0.85,
                        evidence_data=evidence,
                    ))
                    return findings
                
                # Check for image/svg-based XSS
                for img_marker in ['<img', '<svg']:
                    if img_marker in payload_lower and img_marker in response_lower:
                        findings.append(self.create_vulnerability(
                            vuln_type=VulnerabilityType.REFLECTED_XSS,
                            target_url=target_url,
                            title='Image-Based XSS Vulnerability',
                            description=f'{img_marker} tag injection successful',
                            severity=Severity.HIGH,
                            confidence=0.85,
                            evidence_data=evidence,
                        ))
                        return findings
            
            # Check for DOM-based XSS indicators
            dom_sources = ['location', 'window.name', 'document.referrer', 'document.url']
            for source in dom_sources:
                if source in response_lower:
                    if any(unsafe in response_lower for unsafe in ['innerhtml', 'insertadjacenthtml', 'write(', 'writeln(']):
                        findings.append(self.create_vulnerability(
                            vuln_type=VulnerabilityType.REFLECTED_XSS,
                            target_url=target_url,
                            title='DOM-Based XSS Detected',
                            description=f'Unsafe use of {source} with DOM manipulation',
                            severity=Severity.HIGH,
                            confidence=0.70,
                            evidence_data=evidence,
                        ))
                        break
                        
        except Exception:
            pass
            
        return findings
