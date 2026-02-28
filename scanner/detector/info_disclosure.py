"""Information Disclosure detection module."""

import logging
import re
from typing import List, Dict, Any
from .base import BaseDetector
from ..utils.models import Vulnerability
from ..utils.constants import VulnerabilityType, Severity


logger = logging.getLogger(__name__)


class InformationDisclosureDetector(BaseDetector):
    """Detects information disclosure vulnerabilities."""
    
    # Sensitive information patterns
    SENSITIVE_PATTERNS = {
        'Email': [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ],
        'AWS Key': [
            r'AKIA[0-9A-Z]{16}',
            r'aws_access_key_id\s*=\s*[A-Z0-9]{20}',
        ],
        'Private Key': [
            r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        ],
        'API Key': [
            r'api[_-]?key\s*["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}',
            r'apikey\s*["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}',
        ],
        'Password': [
            r'password\s*["\']?\s*[:=]\s*["\']?[^\s"\'<]{4,}',
            r'passwd\s*["\']?\s*[:=]\s*["\']?[^\s"\'<]{4,}',
        ],
        'Database Connection': [
            r'mysql://[^\s]+',
            r'postgresql://[^\s]+',
            r'mongodb://[^\s]+',
            r'redis://[^\s]+',
        ],
        'JWT Token': [
            r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        ],
        'GitHub Token': [
            r'gh[pousr]_[A-Za-z0-9]{36,}',
            r'github_pat_[A-Za-z0-9_]{22,}',
        ],
    }
    
    # Error patterns that leak information
    ERROR_LEAK_PATTERNS = [
        r'fatal:\s*(.+)',
        r'warning:\s*(.+)',
        r'notice:\s*(.+)',
        r'stack trace:',
        r'at\s+[\w\.]+\([\w\.\:]+\)',
        r'java\.lang\.',
        r'org\.apache\.',
        r'python\.',
        r'ruby:',
        r'undefined\s+method',
    ]
    
    # Files that might be exposed
    SENSITIVE_FILES = [
        '.env',
        '.git/config',
        '.htpasswd',
        'phpinfo.php',
        'info.php',
        'server-status',
        'server-info',
    ]
    
    def __init__(self):
        """Initialize Information Disclosure detector."""
        super().__init__("InformationDisclosureDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Detect information disclosure vulnerabilities."""
        findings = []
        
        try:
            response_body = evidence.get('response_body', '')
            response_status = evidence.get('response_status', 0)
            payload_used = evidence.get('payload_used', '')
            url = evidence.get('request_url', target_url)
            
            # Skip if response is too large
            if len(response_body) > 500000:
                return findings
            
            # Check for sensitive information in response
            for info_type, patterns in self.SENSITIVE_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, response_body, re.IGNORECASE)
                    if matches:
                        # Filter out false positives (common in test data)
                        if info_type == 'Email':
                            # Check if it's a real email (not example.com, test.com, etc.)
                            real_emails = [m for m in matches if not any(x in m.lower() for x in ['example', 'test', 'localhost'])]
                            if real_emails:
                                findings.append(Vulnerability(
                                    vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                    title=f'Information Disclosure - {info_type}',
                                    description=f'Potentially sensitive email address found in response',
                                    severity=Severity.MEDIUM,
                                    confidence=0.70,
                                    url=target_url,
                                    parameter='response_body',
                                    payload_used=payload_used,
                                    evidence=f'Email pattern detected: {real_emails[0][:50]}',
                                ))
                        elif info_type in ['AWS Key', 'Private Key', 'API Key', 'JWT Token', 'GitHub Token', 'Password']:
                            # These are always high severity
                            findings.append(Vulnerability(
                                vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                title=f'Information Disclosure - {info_type}',
                                description=f'Potentially sensitive {info_type} found in response',
                                severity=Severity.HIGH,
                                confidence=0.85,
                                url=target_url,
                                parameter='response_body',
                                payload_used=payload_used,
                                evidence=f'{info_type} pattern detected',
                            ))
                        else:
                            findings.append(Vulnerability(
                                vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                title=f'Information Disclosure - {info_type}',
                                description=f'Potentially sensitive {info_type} pattern found',
                                severity=Severity.MEDIUM,
                                confidence=0.75,
                                url=target_url,
                                parameter='response_body',
                                payload_used=payload_used,
                                evidence=f'{info_type} pattern detected',
                            ))
            
            # Check for stack traces and error messages
            for pattern in self.ERROR_LEAK_PATTERNS:
                matches = re.search(pattern, response_body, re.IGNORECASE)
                if matches:
                    findings.append(Vulnerability(
                        vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        title='Information Disclosure - Stack Trace',
                        description='Detailed error/trace information exposed',
                        severity=Severity.MEDIUM,
                        confidence=0.80,
                        url=target_url,
                        parameter='response_body',
                        payload_used=payload_used,
                        evidence=f'Stack trace pattern detected',
                    ))
                    break
            
            # Check for sensitive file paths in response
            for sensitive_file in self.SENSITIVE_FILES:
                if sensitive_file in response_body.lower():
                    findings.append(Vulnerability(
                        vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        title='Information Disclosure - Sensitive File Reference',
                        description=f'Reference to potentially sensitive file: {sensitive_file}',
                        severity=Severity.LOW,
                        confidence=0.60,
                        url=target_url,
                        parameter='response_body',
                        payload_used=payload_used,
                        evidence=f'Sensitive file reference: {sensitive_file}',
                    ))
                    
        except Exception as e:
            logger.debug(f"Information disclosure detection error: {e}")
            
        return findings
