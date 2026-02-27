"""Security misconfiguration detection module."""

import logging
from typing import List, Dict, Any
from .base import BaseDetector
from ..utils.models import Vulnerability
from ..utils.constants import (
    VulnerabilityType, 
    Severity,
    REQUIRED_SECURITY_HEADERS,
)


logger = logging.getLogger(__name__)


class SecurityHeaderDetector(BaseDetector):
    """Detects missing or misconfigured security headers."""
    
    # Headers that should be present
    CRITICAL_HEADERS = {
        'Strict-Transport-Security': 'Forces HTTPS connections',
        'X-Frame-Options': 'Prevents clickjacking attacks',
        'X-Content-Type-Options': 'Prevents MIME-type sniffing',
        'Content-Security-Policy': 'Restricts resource loading',
    }
    
    RECOMMENDED_HEADERS = {
        'X-XSS-Protection': 'Legacy XSS protection',
        'Referrer-Policy': 'Controls referrer information',
        'Permissions-Policy': 'Controls browser features',
    }
    
    # Insecure header values
    INSECURE_VALUES = {
        'X-Frame-Options': ['ALLOW-FROM'],  # Deprecated
        'Access-Control-Allow-Origin': ['*'],  # Too permissive
    }
    
    def __init__(self):
        """Initialize security header detector."""
        super().__init__("SecurityHeaderDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """
        Detect missing or misconfigured security headers.
        """
        findings = []
        response_headers = evidence.get('response_headers', {})
        
        # Check for missing critical headers
        missing_headers = []
        for header in self.CRITICAL_HEADERS.keys():
            if header not in response_headers:
                missing_headers.append(header)
                
        if missing_headers:
            vuln = self.create_vulnerability(
                vuln_type=VulnerabilityType.MISSING_SECURITY_HEADERS,
                target_url=target_url,
                title="Missing Security Headers",
                description=f"The following critical security headers are missing: {', '.join(missing_headers)}",
                severity=Severity.MEDIUM,
                confidence=0.9,
                evidence_data=evidence,
                affected_headers=missing_headers,
                remediation="Implement all critical security headers recommended by OWASP."
            )
            findings.append(vuln)
            
        # Check for insecure header values
        for header, insecure_values in self.INSECURE_VALUES.items():
            if header in response_headers:
                value = response_headers[header]
                for insecure in insecure_values:
                    if insecure in value:
                        vuln = self.create_vulnerability(
                            vuln_type=VulnerabilityType.MISSING_SECURITY_HEADERS,
                            target_url=target_url,
                            title=f"Insecure {header} Configuration",
                            description=f"The header {header} has an insecure value: {value}",
                            severity=Severity.MEDIUM,
                            confidence=0.85,
                            evidence_data=evidence,
                        )
                        findings.append(vuln)
                        
        return findings


class CORSDetector(BaseDetector):
    """Detects CORS misconfiguration vulnerabilities."""
    
    def __init__(self):
        """Initialize CORS detector."""
        super().__init__("CORSDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Detect CORS misconfigurations."""
        findings = []
        response_headers = evidence.get('response_headers', {})
        
        # Check for overly permissive CORS
        acao = response_headers.get('Access-Control-Allow-Origin', '')
        if acao == '*':
            vuln = self.create_vulnerability(
                vuln_type=VulnerabilityType.CORS_MISCONFIGURATION,
                target_url=target_url,
                title="CORS: Access-Control-Allow-Origin is *",
                description="Access-Control-Allow-Origin header is set to '*', allowing any domain to access the resource.",
                severity=Severity.MEDIUM,
                confidence=0.95,
                evidence_data=evidence,
                remediation="Restrict CORS to specific domains instead of using '*'."
            )
            findings.append(vuln)
            
        return findings


class DirectoryIndexingDetector(BaseDetector):
    """Detects directory indexing vulnerabilities."""
    
    def __init__(self):
        """Initialize directory indexing detector."""
        super().__init__("DirectoryIndexingDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Detect directory indexing vulnerability."""
        findings = []
        response_body = evidence.get('response_body', '')
        
        # Check for directory listing patterns
        dir_patterns = [
            r'<title>Index of',
            r'Directory listing for',
            r'\[To Parent Directory\]',
        ]
        
        import re
        is_directory_listing = any(
            re.search(pattern, response_body, re.IGNORECASE)
            for pattern in dir_patterns
        )
        
        if is_directory_listing:
            vuln = self.create_vulnerability(
                vuln_type=VulnerabilityType.DIR_INDEXING,
                target_url=target_url,
                title="Directory Indexing Enabled",
                description="The server is configured to show directory listings.",
                severity=Severity.MEDIUM,
                confidence=0.95,
                evidence_data=evidence,
                remediation="Disable directory indexing in web server configuration."
            )
            findings.append(vuln)
            
        return findings
