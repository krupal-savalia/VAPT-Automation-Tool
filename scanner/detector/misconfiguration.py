"""Additional misconfiguration and vulnerability detection."""

import re
from typing import List, Dict, Any
from ..utils.models import Vulnerability


class DirectoryListingDetector:
    """Detects directory listing vulnerabilities."""
    
    name = "Directory Listing Detector"
    
    async def detect(self, url: str, evidence: Dict[str, Any]) -> List[Vulnerability]:
        """Detect directory listing vulnerabilities."""
        findings = []
        
        try:
            response_body = evidence.get('response_body', '').lower()
            
            # Common directory listing patterns
            patterns = [
                r'<title>index of',
                r'directory listing',
                r'\[\s*to\s+parent\s+directory\s*\]',
                r'<h1>\s*index of\s*</h1>',
            ]
            
            for pattern in patterns:
                if re.search(pattern, response_body):
                    findings.append(Vulnerability(
                        vulnerability_type='Information Disclosure',
                        title='Directory Listing Enabled',
                        description='Server allows directory browsing, exposing file structure',
                        severity='Medium',
                        confidence=0.95,
                        url=url,
                        parameter=None,
                        payload_used=None,
                        evidence='Directory listing HTML detected',
                    ))
                    break
                    
        except Exception:
            pass
            
        return findings


class HTTPMethodDetector:
    """Detects HTTP method abuse."""
    
    name = "HTTP Method Detector"
    
    async def detect(self, url: str, evidence: Dict[str, Any]) -> List[Vulnerability]:
        """Detect HTTP method vulnerabilities."""
        findings = []
        
        try:
            headers = evidence.get('response_headers', {})
            status = evidence.get('status', 0)
            
            # Check Allow header for dangerous methods
            allow_header = headers.get('Allow', '').upper()
            
            if 'TRACE' in allow_header:
                findings.append(Vulnerability(
                    vulnerability_type='HTTP Method Abuse',
                    title='TRACE Method Enabled',
                    description='TRACE method enabled, can be used for XST attacks',
                    severity='Medium',
                    confidence=0.90,
                    url=url,
                    parameter='HTTP Method',
                    payload_used='TRACE',
                    evidence='TRACE method listed in Allow header',
                ))
            
            if 'CONNECT' in allow_header:
                findings.append(Vulnerability(
                    vulnerability_type='HTTP Method Abuse',
                    title='CONNECT Method Enabled',
                    description='CONNECT method allows tunneling, potential for abuse',
                    severity='Low',
                    confidence=0.70,
                    url=url,
                    parameter='HTTP Method',
                    payload_used='CONNECT',
                    evidence='CONNECT method available',
                ))
                
        except Exception:
            pass
            
        return findings


class FileUploadDetector:
    """Detects file upload vulnerabilities."""
    
    name = "File Upload Detector"
    
    async def detect(self, url: str, evidence: Dict[str, Any]) -> List[Vulnerability]:
        """Detect file upload vulnerabilities."""
        findings = []
        
        try:
            response_body = evidence.get('response_body', '')
            
            # Check for file upload forms
            if re.search(r'<input[^>]*type=["\']file', response_body, re.IGNORECASE):
                # Check if there's file validation or restrictions mentioned
                response_lower = response_body.lower()
                
                if not any(x in response_lower for x in ['accept=', '.jpg', '.png', 'extension']):
                    findings.append(Vulnerability(
                        vulnerability_type='Unsafe File Upload',
                        title='Unrestricted File Upload',
                        description='File upload form found without obvious extension/type restrictions',
                        severity='High',
                        confidence=0.65,
                        url=url,
                        parameter='File upload field',
                        payload_used='Malicious file (php/exe)',
                        evidence='File upload input detected without restrictions',
                    ))
                    
        except Exception:
            pass
            
        return findings


class CrossSiteRequestForgeryDetector:
    """Detects CSRF vulnerabilities."""
    
    name = "CSRF Detector"
    
    async def detect(self, url: str, evidence: Dict[str, Any]) -> List[Vulnerability]:
        """Detect CSRF vulnerabilities."""
        findings = []
        
        try:
            response_body = evidence.get('response_body', '')
            
            # Check for CSRF token
            if re.search(r'<form[^>]*method=["\']post', response_body, re.IGNORECASE):
                # Check if CSRF token present
                csrf_patterns = [
                    r'name=["\']csrf',
                    r'name=["\']_token',
                    r'name=["\']token',
                    r'name=["\']authenticity_token',
                ]
                
                has_token = any(re.search(pattern, response_body, re.IGNORECASE) for pattern in csrf_patterns)
                
                if not has_token:
                    findings.append(Vulnerability(
                        vulnerability_type='Cross-Site Request Forgery',
                        title='Missing CSRF Token',
                        description='POST form found without CSRF protection token',
                        severity='Medium',
                        confidence=0.70,
                        url=url,
                        parameter='Form submission',
                        payload_used='CSRF payload',
                        evidence='POST form without CSRF token detected',
                    ))
                    
        except Exception:
            pass
            
        return findings
