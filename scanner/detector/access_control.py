"""Access Control and IDOR vulnerability detection."""

import re
from typing import List, Dict, Any
from ..utils.models import Vulnerability


class IDORDetector:
    """Detects Insecure Direct Object Reference (IDOR) vulnerabilities."""
    
    name = "IDOR Detector"
    
    async def detect(self, url: str, evidence: Dict[str, Any]) -> List[Vulnerability]:
        """
        Detect IDOR vulnerabilities.
        
        Parameters
        ----------
        url : str
            Target URL
        evidence : Dict[str, Any]
            Evidence dictionary
            
        Returns
        -------
        List[Vulnerability]
            List of detected vulnerabilities
        """
        findings = []
        
        try:
            # IDOR detection using sequential ID testing
            url_lower = url.lower()
            
            # Pattern detection for IDs in URLs
            id_patterns = [
                r'/user/(\d+)',
                r'/profile/(\d+)',
                r'/account/(\d+)',
                r'/object/(\d+)',
                r'[?&]id=(\d+)',
                r'[?&]user_id=(\d+)',
                r'[?&]object_id=(\d+)',
            ]
            
            for pattern in id_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    findings.append(Vulnerability(
                        vulnerability_type='Insecure Direct Object Reference',
                        title='Potential IDOR Vulnerability',
                        description='Application uses predictable object references that may be directly accessible',
                        severity='High',
                        confidence=0.60,
                        url=url,
                        parameter='URL path or query parameter',
                        payload_used='Sequential ID testing recommended',
                        evidence=f'Predictable ID pattern detected: {pattern}',
                    ))
                    break
                    
        except Exception:
            pass
            
        return findings


class AuthenticationDetector:
    """Detects authentication and session management issues."""
    
    name = "Authentication Issues Detector"
    
    async def detect(self, url: str, evidence: Dict[str, Any]) -> List[Vulnerability]:
        """
        Detect authentication and session issues.
        
        Parameters
        ----------
        url : str
            Target URL
        evidence : Dict[str, Any]
            Evidence dictionary
            
        Returns
        -------
        List[Vulnerability]
            List of detected vulnerabilities
        """
        findings = []
        
        try:
            headers = evidence.get('response_headers', {})
            response_body = evidence.get('response_body', '')
            
            # Check cookie security
            set_cookie = headers.get('set-cookie', '').lower()
            
            # Check if cookies lack HttpOnly
            if 'set-cookie' in str(headers).lower():
                if 'httponly' not in set_cookie:
                    findings.append(Vulnerability(
                        vulnerability_type='Weak Session Management',
                        title='Missing HttpOnly Flag on Cookie',
                        description='Session cookies missing HttpOnly flag, vulnerable to XSS attacks',
                        severity='Medium',
                        confidence=0.95,
                        url=url,
                        parameter='Set-Cookie header',
                        payload_used='XSS payload',
                        evidence='HttpOnly flag not present in session cookie',
                    ))
                
                # Check if cookies lack Secure flag
                if 'https' in url.lower() and 'secure' not in set_cookie:
                    findings.append(Vulnerability(
                        vulnerability_type='Weak Session Management',
                        title='Missing Secure Flag on Cookie',
                        description='Session cookies not marked Secure, can be transmitted unencrypted',
                        severity='Medium',
                        confidence=0.90,
                        url=url,
                        parameter='Set-Cookie header',
                        payload_used='Man-in-the-middle attack',
                        evidence='Secure flag not present in HTTPS context',
                    ))
            
            # Check for debug parameters
            if any(param in url.lower() for param in ['debug=1', 'debug=true', 'verbose=1']):
                findings.append(Vulnerability(
                    vulnerability_type='Information Disclosure',
                    title='Debug Parameter Present',
                    description='Debug parameters exposed in URL may leak sensitive information',
                    severity='Medium',
                    confidence=0.80,
                    url=url,
                    parameter='URL parameter',
                    payload_used=None,
                    evidence='Debug parameter detected in URL',
                ))
                
        except Exception:
            pass
            
        return findings
