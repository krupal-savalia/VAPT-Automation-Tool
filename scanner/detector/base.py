"""Base detector class and detection utilities."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import logging
from ..utils.models import Vulnerability, Evidence
from ..utils.constants import VulnerabilityType, Severity


logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """
    Abstract base class for vulnerability detectors.
    
    All detection modules should inherit from this class and implement
    the detect() method.
    """
    
    def __init__(self, name: str):
        """
        Initialize detector.
        
        Parameters
        ----------
        name : str
            Name of the detector module.
        """
        self.name = name
        self.findings: List[Vulnerability] = []
        
    @abstractmethod
    async def detect(self, target_url: str, evidence: Dict[str, Any]) -> List[Vulnerability]:
        """
        Detect vulnerabilities.
        
        Parameters
        ----------
        target_url : str
            URL to test.
        evidence : Dict[str, Any]
            Evidence/context for detection (response, parameters, etc).
            
        Returns
        -------
        List[Vulnerability]
            List of detected vulnerabilities.
        """
        pass
        
    def create_vulnerability(
        self,
        vuln_type: VulnerabilityType,
        target_url: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: float,
        evidence_data: Dict[str, Any],
        **kwargs
    ) -> Vulnerability:
        """Helper to create a vulnerability finding."""
        evidence = Evidence(
            request_url=evidence_data.get('request_url', target_url),
            request_method=evidence_data.get('request_method', 'GET'),
            request_headers=evidence_data.get('request_headers', {}),
            request_body=evidence_data.get('request_body'),
            response_status=evidence_data.get('response_status', 200),
            response_headers=evidence_data.get('response_headers', {}),
            response_body=evidence_data.get('response_body', ''),
            response_length=evidence_data.get('response_length', 0),
            injection_point=evidence_data.get('injection_point'),
            payload_used=evidence_data.get('payload_used'),
            detection_method=self.name,
        )
        
        return Vulnerability(
            type=vuln_type,
            target_url=target_url,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            evidence=[evidence],
            scanner_module=self.name,
            **kwargs
        )


class InjectionDetector(BaseDetector):
    """Base class for injection-style vulnerability detection."""
    
    # Error patterns for various backends
    SQL_ERROR_PATTERNS = [
        r"sql.*error",
        r"mysql.*error",
        r"warning.*mysql",
        r"sql.*syntax",
        r"database.*error",
        r"unexpected.*token",
    ]
    
    def detect_error_pattern(self, response_text: str, patterns: List[str]) -> bool:
        """Check if response contains error patterns."""
        import re
        response_lower = response_text.lower()
        for pattern in patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                return True
        return False
        
    def calculate_response_difference(
        self, 
        baseline: str, 
        test: str
    ) -> float:
        """Calculate similarity score between responses (0-1)."""
        if not baseline or not test:
            return 0.0
        
        baseline_len = len(baseline)
        test_len = len(test)
        
        if baseline_len == 0:
            return 1.0 if test_len == 0 else 0.0
            
        diff = abs(baseline_len - test_len) / baseline_len
        return max(0, min(1, 1.0 - diff))
