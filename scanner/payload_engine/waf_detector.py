"""WAF detection and fingerprinting module."""

import logging
import re
from typing import Optional, Dict, List


logger = logging.getLogger(__name__)


class WAFDetector:
    """
    Detect and fingerprint WAF/IDS products.
    
    Analyzes HTTP responses and headers to identify installed WAF products.
    """
    
    # WAF detection patterns
    WAF_SIGNATURES = {
        'ModSecurity': [
            r'ModSecurity',
            r'<title>error 403</title>',
        ],
        'AWS WAF': [
            r'AWS WAF',
            r'BadRequest',
        ],
        'Cloudflare': [
            r'cloudflare',
            r'error code: 1020',
            r'error code: 1010',
        ],
        'Akamai': [
            r'AkamaiIdentification',
            r'Reference #\.[\w]+ generation time',
        ],
        'F5 BIG-IP': [
            r'BigIP',
            r'F5',
        ],
        'Imperva SecureSphere': [
            r'_IMPERVA_',
            r'RequestDenied',
        ],
        'Fortinet': [
            r'FortiGate',
            r'error 403',
        ],
        'DenyAll': [
            r'DenyAll',
        ],
        'Barracuda': [
            r'Barracuda',
        ],
        'Sucuri': [
            r'Sucuri',
        ],
        'Wordfence': [
            r'Wordfence',
        ],
    }
    
    def __init__(self):
        """Initialize WAF detector."""
        self.detected_waf: Optional[str] = None
        self.waf_confidence: float = 0.0
        
    def detect(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        status_code: int,
    ) -> Optional[str]:
        """
        Detect WAF product from response.
        
        Parameters
        ----------
        response_body : str
            Response body text.
        response_headers : Dict[str, str]
            Response headers.
        status_code : int
            HTTP status code.
            
        Returns
        -------
        Optional[str]
            Detected WAF product name or None.
        """
        # Check headers
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for header_name, header_value in response_headers.items():
                for signature in signatures:
                    if re.search(signature, str(header_value), re.IGNORECASE):
                        self.detected_waf = waf_name
                        self.waf_confidence = 0.9
                        logger.info(f"WAF detected: {waf_name}")
                        return waf_name
                        
        # Check response body
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for signature in signatures:
                if re.search(signature, response_body, re.IGNORECASE):
                    self.detected_waf = waf_name
                    self.waf_confidence = 0.7
                    logger.info(f"WAF detected: {waf_name}")
                    return waf_name
                    
        return None
        
    def should_use_evasion(self) -> bool:
        """Check if WAF evasion should be employed."""
        return self.detected_waf is not None and self.waf_confidence > 0.7
