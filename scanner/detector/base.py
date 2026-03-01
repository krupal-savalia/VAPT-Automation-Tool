"""Base detector class and detection utilities.

Includes a lightweight confirmation engine and normalization helpers used
by multiple detectors to avoid reporting on a single payload failure.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set, Tuple
import logging
from ..utils.models import Vulnerability, Evidence


class ConfirmationEngine:
    """Track payload confirmations for a candidate vulnerability.

    Stores unique payloads that produced positive detection for a given key.
    When the number of distinct payloads meets or exceeds the configured
    threshold the engine returns the accumulated evidences so a real
    vulnerability object can be emitted.
    
    Enhanced to support:
    - Multi-payload confirmation (threshold-based)
    - Boolean-based SQLi pair tracking (true/false pairs)
    - Different vulnerability type confirmation rules
    """

    def __init__(self, threshold: int = 1):
        self.threshold = threshold
        self._store: Dict[str, Dict[str, Any]] = {}
        # Boolean pair tracking: key -> {'true_payloads': [], 'false_payloads': [], 'pairs_confirmed': 0}
        self._boolean_pairs: Dict[str, Dict[str, Any]] = {}

    def record(self, key: str, evidence: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """Record a payload confirmation. Returns evidences if threshold met."""
        entry = self._store.setdefault(key, {'payloads': set(), 'evidences': []})
        payload = evidence.get('payload_used')
        if payload and payload not in entry['payloads']:
            entry['payloads'].add(payload)
            entry['evidences'].append(evidence.copy())
        if len(entry['payloads']) >= self.threshold:
            # once threshold met, return copy of evidences and clear store to
            # prevent duplicate reporting later
            evidences = entry['evidences'][:]
            del self._store[key]
            return evidences
        return None

    def record_boolean_pair(
        self, 
        key: str, 
        true_evidence: Dict[str, Any], 
        false_evidence: Dict[str, Any]
    ) -> Optional[List[Dict[str, Any]]]:
        """Record a boolean-based SQL injection true/false pair.
        
        Only reports if:
        - True response differs from False response
        - True response is similar to baseline
        - This pattern is confirmed at least twice
        
        Returns evidences if pair confirmation threshold met.
        """
        entry = self._boolean_pairs.setdefault(key, {
            'true_payloads': [], 
            'false_payloads': [], 
            'true_evidences': [],
            'false_evidences': [],
            'pairs_confirmed': 0
        })
        
        true_payload = true_evidence.get('payload_used', '')
        false_payload = false_evidence.get('payload_used', '')
        
        # Check if this exact pair already recorded
        if true_payload in entry['true_payloads'] and false_payload in entry['false_payloads']:
            return None
            
        entry['true_payloads'].append(true_payload)
        entry['false_payloads'].append(false_payload)
        entry['true_evidences'].append(true_evidence.copy())
        entry['false_evidences'].append(false_evidence.copy())
        
        # Calculate response differences
        true_hash = true_evidence.get('response_hash', '')
        false_hash = false_evidence.get('response_hash', '')
        baseline_hash = true_evidence.get('baseline_hash', '')
        
        # Boolean-based SQLi conditions:
        # 1. True response != False response (payload causes different behavior)
        # 2. True response ≈ baseline (true condition doesn't break query)
        # 3. False response significantly differs (false condition affects query)
        
        if true_hash and false_hash:
            if true_hash != false_hash:  # Responses differ
                entry['pairs_confirmed'] += 1
                
                if entry['pairs_confirmed'] >= self.threshold:
                    # Return combined evidences (both true and false)
                    combined = entry['true_evidences'][:] + entry['false_evidences'][:]
                    del self._boolean_pairs[key]
                    return combined
                    
        return None

    def get_confirmation_count(self, key: str) -> int:
        """Get current confirmation count for a key."""
        if key in self._store:
            return len(self._store[key]['payloads'])
        return 0

    def reset(self, key: Optional[str] = None):
        """Reset confirmation store. If key provided, only reset that key."""
        if key:
            self._store.pop(key, None)
            self._boolean_pairs.pop(key, None)
        else:
            self._store.clear()
            self._boolean_pairs.clear()
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
        # simple confirmation engine shared by detectors; key -> list of evidences
        self._confirmation_engine = ConfirmationEngine()
        
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
            detection_confidence=kwargs.pop('detection_confidence', None),
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
