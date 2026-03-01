"""Local File Inclusion (LFI) and Path Traversal detection module.

This module detects LFI vulnerabilities by:
1. Testing various path traversal patterns
2. Checking for sensitive file exposure (/etc/passwd, win.ini, etc.)
3. Comparing responses with baseline to detect file content leaks
4. Validating against common false positives
"""

import logging
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
from .base import InjectionDetector
from ..utils.response_utils import (
    normalize_response,
    hash_response,
    check_generic_500_crash,
)
from ..utils.models import Vulnerability, Evidence
from ..utils.constants import VulnerabilityType, Severity


logger = logging.getLogger(__name__)


class LFIDetector(InjectionDetector):
    """Detects Local File Inclusion and Path Traversal vulnerabilities.
    
    Enhanced detection includes:
    - Multiple path traversal patterns (Unix and Windows)
    - Sensitive file detection (/etc/passwd, win.ini, etc.)
    - Baseline comparison for response differences
    - Validation against false positives (error pages, generic 500)
    """
    
    # Path traversal payloads - organized by type
    UNIX_TRAVERSAL = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/shadow",
        "../../../../etc/shadow",
        "../../../../../../etc/shadow",
        "../../../etc/hosts",
        "../../../etc/group",
        "../../../proc/self/environ",
        "../../../proc/self/cmdline",
        "../../../proc/version",
        "../../../../proc/version",
        "../../../../../proc/version",
    ]
    
    WINDOWS_TRAVERSAL = [
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\system32\\config\\sam",
        "..\\..\\..\\..\\winnt\\win.ini",
        "..\\..\\..\\..\\winnt\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\..\\winnt\\win.ini",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    ]
    
    URL_ENCODED_TRAVERSAL = [
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "..%5C..%5C..%5Cwindows%5Cwin.ini",
        "....//....//....//etc/passwd",
        "....\\\\....\\\\....\\\\windows\\win.ini",
    ]
    
    NULL_BYTE_TRAVERSAL = [
        "../../etc/passwd%00.jpg",
        "../../etc/passwd%00.png",
        "../../etc/passwd\x00.jpg",
        "..\\..\\windows\\win.ini%00.txt",
    ]
    
    # Sensitive file content patterns to detect successful reads
    SENSITIVE_FILES = {
        '/etc/passwd': [
            r"root:.*:0:0:",
            r"daemon:.*:1:1:",
            r"nobody:.*:65534:",
            r"bin:.*:1:1:",
            r"sys:.*:3:3:",
        ],
        '/etc/shadow': [
            r"root:\$[0-9a-zA-Z\$]+:",
            r"daemon:\*:",
        ],
        '/etc/hosts': [
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost",
        ],
        'win.ini': [
            r"\[fonts\]",
            r"\[extensions\]",
            r"\[files\]",
            r"\[Mail\]",
        ],
        'boot.ini': [
            r"\[boot loader\]",
            r"timeout=",
            r"default=",
        ],
    }
    
    # Generic error patterns that indicate failure (not vulnerability)
    ERROR_PATTERNS = [
        r"permission denied",
        r"access denied",
        r"not found",
        r"no such file",
        r"cannot read",
        r"forbidden",
        r"403",
    ]
    
    # Safe file extensions that shouldn't cause execution
    SAFE_EXTENSIONS = ['.jpg', '.png', '.gif', '.css', '.js', '.html', '.txt', '.xml']
    
    def __init__(self):
        """Initialize LFI detector."""
        super().__init__("LFIDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """
        Detect LFI/Path Traversal vulnerabilities.
        
        Analyzes response for:
        - Sensitive file content exposure
        - Response differences from baseline
        - Valid file path indicators
        """
        findings = []
        try:
            response_body = evidence.get('response_body', '')
            response_body_lower = response_body.lower()
            response_status = evidence.get('response_status', 0)
            payload_used = evidence.get('payload_used', '')
            baseline = evidence.get('baseline_response', {}) or {}
            baseline_hash = baseline.get('hash', '')
            baseline_status = baseline.get('status', 0)
            injection_point = evidence.get('injection_point', '')
            
            # Skip if generic error/crash
            if check_generic_500_crash(baseline_status, response_status):
                logger.debug(f"LFI detection skipped: generic 500 crash")
                return findings
            
            # Skip if payload doesn't look like LFI/traversal
            if not self._is_lfi_payload(payload_used):
                return findings
            
            # Check for sensitive file content in response
            for file_pattern, content_patterns in self.SENSITIVE_FILES.items():
                if file_pattern.lower() in payload_used.lower():
                    # Check if any content pattern matches
                    for pattern in content_patterns:
                        if re.search(pattern, response_body, re.IGNORECASE):
                            findings.append(self.create_vulnerability(
                                vuln_type=VulnerabilityType.PATH_TRAVERSAL,
                                target_url=target_url,
                                title='Local File Inclusion - Sensitive File Read',
                                description=f'Path traversal successfully read sensitive file: {file_pattern}',
                                severity=Severity.HIGH,
                                confidence=0.95,
                                evidence_data=evidence,
                                affected_parameter=injection_point or 'path',
                                detection_confidence='high'
                            ))
                            return findings
            
            # Check for response differences from baseline
            resp_hash = hash_response(response_body)
            if baseline_hash and resp_hash != baseline_hash:
                # Response changed - could be LFI success
                # Validate it's not just an error page
                if not self._is_error_response(response_body, response_status):
                    # Additional checks for potential LFI
                    content_indicators = [
                        'root:' in response_body,  # /etc/passwd
                        '[boot loader]' in response_body_lower,  # boot.ini
                        'fonts]' in response_body_lower,  # win.ini
                        'extensions]' in response_body_lower,  # win.ini
                    ]
                    
                    if any(content_indicators) or len(response_body) > 100:
                        findings.append(self.create_vulnerability(
                            vuln_type=VulnerabilityType.PATH_TRAVERSAL,
                            target_url=target_url,
                            title='Path Traversal - Response Difference Detected',
                            description=f'Path traversal payload caused response change. Possible file inclusion.',
                            severity=Severity.MEDIUM,
                            confidence=0.70,
                            evidence_data=evidence,
                            affected_parameter=injection_point or 'path',
                            detection_confidence='medium'
                        ))
                        return findings
            
            # Check for directory listing exposure via traversal
            if self._is_directory_listing(response_body):
                findings.append(self.create_vulnerability(
                    vuln_type=VulnerabilityType.DIR_INDEXING,
                    target_url=target_url,
                    title='Directory Traversal - Directory Listing Exposed',
                    description='Path traversal revealed directory listing',
                    severity=Severity.MEDIUM,
                    confidence=0.80,
                    evidence_data=evidence,
                    affected_parameter=injection_point or 'path',
                    detection_confidence='medium'
                ))
                return findings
                
        except Exception as e:
            logger.debug(f"LFI detection error: {e}")
            
        return findings
    
    def _is_lfi_payload(self, payload: str) -> bool:
        """Check if payload is an LFI/path traversal attempt."""
        if not payload:
            return False
        
        payload_lower = payload.lower()
        
        # Check for traversal patterns
        traversal_patterns = [
            '../', '..\\', '%2e%2e', '..%2f', '..%5c',
            '....//', '....\\\\', '%c0%ae',  # Unicode bypass attempts
        ]
        
        # Check for sensitive file targets
        sensitive_targets = [
            'etc/passwd', 'etc/shadow', 'etc/hosts', 'etc/group',
            'windows/win.ini', 'winnt/win.ini',
            'boot.ini', 'sam', 'config',
            'proc/self', 'proc/version',
        ]
        
        return any(p in payload_lower for p in traversal_patterns) or \
               any(t in payload_lower for t in sensitive_targets)
    
    def _is_error_response(self, response_body: str, status: int) -> bool:
        """Check if response is an error page (false positive)."""
        if status == 404 or status == 403:
            return True
        
        body_lower = response_body.lower()
        
        # Check for common error patterns
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                return True
        
        # Check for common error page content
        error_indicators = [
            'error 404', 'not found', 'page not found',
            'forbidden', 'access denied', '403 forbidden',
            'server error', '500 internal server error',
        ]
        
        return any(indicator in body_lower for indicator in error_indicators)
    
    def _is_directory_listing(self, response_body: str) -> bool:
        """Check if response contains directory listing."""
        listing_patterns = [
            r'<title>index of',
            r'<title>directory listing',
            r'directory listing for',
            r'\[to parent directory\]',
            r'parent directory',
            r'<img src="/icons/folder',
            r'last modified',
            r'directory',
        ]
        
        body_lower = response_body.lower()
        return any(re.search(p, body_lower) for p in listing_patterns)


class DirectoryTraversalDetector(InjectionDetector):
    """Enhanced Directory Traversal detector with multiple bypass techniques.
    
    This detector focuses on web path traversal (directory listing/reading)
    rather than file system access.
    """
    
    # Common web-accessible paths that could reveal traversal
    WEB_PATHS = [
        "../../../",
        "../../../../",
        "../../../../../",
        "../../../../../../",
        "..\\..\\..\\",
        "..\\..\\..\\..\\",
        "..\\..\\..\\..\\..\\",
        "../..//../..",
        "....//....//....//",
        "..%2F..%2F..%2F",
        "..%252F..%252F..%252F",
    ]
    
    def __init__(self):
        """Initialize directory traversal detector."""
        super().__init__("DirectoryTraversalDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Detect directory traversal vulnerabilities."""
        findings = []
        
        try:
            response_body = evidence.get('response_body', '')
            response_status = evidence.get('response_status', 0)
            payload_used = evidence.get('payload_used', '')
            baseline = evidence.get('baseline_response', {})
            baseline_status = baseline.get('status', 0)
            
            # Check if payload is traversal
            if not ('../' in payload_used or '..\\' in payload_used):
                return findings
            
            # Skip if baseline comparison is invalid
            if check_generic_500_crash(baseline_status, response_status):
                return findings
            
            # Check for directory listing
            if self._detect_directory_listing(response_body):
                findings.append(self.create_vulnerability(
                    vuln_type=VulnerabilityType.PATH_TRAVERSAL,
                    target_url=target_url,
                    title='Directory Traversal - Listing Enabled',
                    description='Directory traversal reveals directory contents',
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    evidence_data=evidence,
                    detection_confidence='high'
                ))
                
        except Exception as e:
            logger.debug(f"Directory traversal detection error: {e}")
            
        return findings
    
    def _detect_directory_listing(self, body: str) -> bool:
        """Detect directory listing patterns."""
        patterns = [
            'index of', 'directory listing', 'directory for',
            '[to parent directory]', '<title>index', 'parent directory',
        ]
        body_lower = body.lower()
        return any(p in body_lower for p in patterns)


def get_all_lfi_payloads() -> List[str]:
    """Get comprehensive list of LFI/traversal payloads."""
    detector = LFIDetector()
    return (
        detector.UNIX_TRAVERSAL +
        detector.WINDOWS_TRAVERSAL +
        detector.URL_ENCODED_TRAVERSAL +
        detector.NULL_BYTE_TRAVERSAL
    )
