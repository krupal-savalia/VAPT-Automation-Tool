"""XSS (Cross-Site Scripting) detection module.

Refactored with:
- HTML encoding verification (rejects encoded payloads)
- CSP header checking
- Execution context validation
- Multi-payload confirmation (requires 2+ payloads)
"""

import logging
from typing import List, Dict, Any, Optional
from .base import BaseDetector
from ..utils.models import Vulnerability, Evidence
from ..utils.constants import VulnerabilityType, Severity
from ..utils.response_utils import (
    normalize_response, 
    hash_response,
    validate_xss_reflection,
    check_csp_protection,
    XSS_EXECUTION_CONTEXTS,
    XSS_SAFE_CONTEXTS
)


logger = logging.getLogger(__name__)


class XSSDetector(BaseDetector):
    """Detects Cross-Site Scripting vulnerabilities (Reflected, Stored, DOM).
    
    Enhanced with:
    - Multi-payload confirmation (threshold=2)
    - HTML encoding verification
    - CSP header checking
    - Execution context validation
    """
    
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
        - Reflected XSS (with validation)
        - Stored XSS
        - DOM-based XSS
        
        All detections require at least 2 independent payload confirmations.
        """
        findings = []
        try:
            response_body = evidence.get('response_body', '')
            payload_used = str(evidence.get('payload_used', ''))
            injection_point = evidence.get('injection_point', 'unknown')
            baseline = evidence.get('baseline_response', {}) or {}
            content_type = evidence.get('response_headers', {}).get('Content-Type', '')
            response_headers = evidence.get('response_headers', {})
            baseline_snip = baseline.get('body_snippet', '')

            if not payload_used or not injection_point:
                return findings

            # normalize for structural comparisons
            normalized = normalize_response(response_body)
            resp_hash = hash_response(response_body)
            baseline_hash = baseline.get('hash', '')

            # Add hash to evidence for confirmation tracking
            evidence_with_hash = evidence.copy()
            evidence_with_hash['response_hash'] = resp_hash

            def confirm_and_report(desc: str, conf: float, detection_confidence: str = 'high') -> Optional[Vulnerability]:
                key = f"xss::{target_url}::{injection_point}"
                evidences = self._confirmation_engine.record(key, evidence_with_hash)
                if evidences:
                    vuln = self.create_vulnerability(
                        vuln_type=VulnerabilityType.REFLECTED_XSS,
                        target_url=target_url,
                        title='Reflected XSS Vulnerability',
                        description=desc,
                        severity=Severity.HIGH,
                        confidence=conf,
                        evidence_data=evidences[0],
                        affected_parameter=injection_point,
                        detection_confidence=detection_confidence
                    )
                    vuln.evidence = [Evidence(**{
                        'request_url': e.get('request_url', target_url),
                        'response_body': e.get('response_body', ''),
                        'response_length': len(e.get('response_body', '')),
                        'injection_point': e.get('injection_point'),
                        'payload_used': e.get('payload_used'),
                        'detection_method': self.name,
                    }) for e in evidences]
                    return vuln
                return None

            # Require HTML content type
            if 'html' not in content_type.lower():
                return findings

            # Check if payload already in baseline
            if baseline_snip and payload_used in baseline_snip:
                return findings

            # Use validation helper for XSS reflection
            is_valid_xss, validation_reason = validate_xss_reflection(
                response_body=response_body,
                payload=payload_used,
                content_type=content_type,
                csp_headers=response_headers
            )
            
            if not is_valid_xss:
                logger.debug(f"XSS validation failed: {validation_reason}")
                return findings

            # Check CSP protection
            is_csp_protected, csp_details = check_csp_protection(response_headers)
            
            if is_csp_protected and 'unsafe-inline' not in csp_details.lower():
                logger.debug(f"XSS blocked by CSP: {csp_details}")
                return findings

            # Check for execution context (high confidence)
            normalized_lower = normalized.lower()
            has_execution_ctx = any(ctx in normalized_lower for ctx in XSS_EXECUTION_CONTEXTS)
            
            if has_execution_ctx:
                v = confirm_and_report(
                    f'Payload reflected in executable context: {validation_reason}',
                    0.85,
                    'high'
                )
                if v:
                    findings.append(v)
                    return findings

            # Check for safe contexts (reject if in safe context)
            for safe_ctx in XSS_SAFE_CONTEXTS:
                if safe_ctx in normalized_lower:
                    logger.debug(f"XSS in safe context: {safe_ctx}")
                    return findings

            # If no execution context but reflected (medium confidence)
            if payload_used and payload_used in normalized:
                v = confirm_and_report(
                    f'Payload reflected but no clear execution context: {validation_reason}',
                    0.60,
                    'medium'
                )
                if v:
                    findings.append(v)
                    return findings

            # DOM-based XSS detection
            dom_sources_lower = [s.lower() for s in self.DOM_SOURCES]
            for source in dom_sources_lower:
                if source in response_body.lower():
                    unsafe_patterns = ['innerhtml', 'insertadjacenthtml', 'write(', 'writeln(']
                    if any(unsafe in response_body.lower() for unsafe in unsafe_patterns):
                        v = confirm_and_report(
                            f'Unsafe DOM usage of {source}',
                            0.70,
                            'medium'
                        )
                        if v:
                            findings.append(v)
                            return findings
                            
        except Exception as e:
            logger.debug(f"XSS detection error: {e}")
            
        return findings
