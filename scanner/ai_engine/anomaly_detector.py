"""AI-powered anomaly detection for false positive reduction."""

import logging
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN

from ..utils.models import Vulnerability, Evidence
from ..utils.constants import VulnerabilityType, Severity


logger = logging.getLogger(__name__)


class ResponseAnalyzer:
    """Analyzes HTTP responses to identity anomalies."""
    
    def __init__(self, baseline_responses: List[str] = None):
        """Initialize response analyzer."""
        self.baseline_responses = baseline_responses or []
        self.baseline_lengths = [len(r) for r in self.baseline_responses]
        self.baseline_entropy = [self._calculate_entropy(r) for r in self.baseline_responses]
        self.baseline_avg_length = np.mean(self.baseline_lengths) if self.baseline_lengths else 0
        self.baseline_std_length = np.std(self.baseline_lengths) if self.baseline_lengths else 1
        
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of response."""
        if not text:
            return 0.0
            
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
            
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in freq.values():
            p = count / text_len
            entropy -= p * np.log2(p)
            
        return entropy
        
    def is_anomalous(
        self,
        response_text: str,
        threshold: float = 2.0,  # Standard deviations
    ) -> bool:
        """Check if response is anomalous compared to baseline."""
        response_len = len(response_text)
        
        if not self.baseline_lengths:
            return False
            
        # Check if length is >2 std devs from baseline
        z_score = abs((response_len - self.baseline_avg_length) / self.baseline_std_length)
        return z_score > threshold
        
    def calculate_similarity(self, response1: str, response2: str) -> float:
        """Calculate similarity between two responses (0-1)."""
        if not response1 or not response2:
            return 0.0
            
        # Simple character overlap metric
        chars1 = set(response1)
        chars2 = set(response2)
        
        if not chars1 or not chars2:
            return 1.0 if chars1 == chars2 else 0.0
            
        intersection = len(chars1 & chars2)
        union = len(chars1 | chars2)
        
        return intersection / union if union > 0 else 0.0


class AnomalyDetector:
    """
    ML-based anomaly detection for vulnerability confirmation.
    
    Uses Isolation Forest to identify anomalous responses that may indicate
    vulnerability exploitation.
    """
    
    def __init__(self, contamination: float = 0.1):
        """
        Initialize anomaly detector.
        
        Parameters
        ----------
        contamination : float
            Expected proportion of anomalies (0-1).
        """
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.response_analyzer = ResponseAnalyzer()
        
    def extract_features(self, response_text: str, response_headers: Dict[str, str]) -> np.ndarray:
        """Extract numerical features from response."""
        features = [
            len(response_text),  # Response length
            response_text.count('<'),  # HTML tag density
            response_text.count('error'),  # Error mentions
            response_text.count('warning'),
            len(response_headers),  # Number of headers
            response_text.lower().count('database'),
            response_text.lower().count('exception'),
            self.response_analyzer._calculate_entropy(response_text),
        ]
        
        return np.array([features])
        
    def fit(self, normal_responses: List[Tuple[str, Dict[str, str]]]):
        """
        Train anomaly detector on known normal responses.
        
        Parameters
        ----------
        normal_responses : List[Tuple[str, Dict[str, str]]]
            List of (response_body, response_headers) tuples.
        """
        if len(normal_responses) < 5:
            logger.warning("Too few samples for anomaly detection training")
            return
            
        X = []
        for response_text, headers in normal_responses:
            features = self.extract_features(response_text, headers)
            X.append(features[0])
            
        X = np.array(X)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        logger.info("Anomaly detector trained")
        
    def predict(
        self,
        response_text: str,
        response_headers: Dict[str, str],
    ) -> Tuple[bool, float]:
        """
        Predict if response is anomalous.
        
        Parameters
        ----------
        response_text : str
            Response body.
        response_headers : Dict[str, str]
            Response headers.
            
        Returns
        -------
        Tuple[bool, float]
            (is_anomalous, anomaly_score)
        """
        if not self.is_trained:
            return False, 0.0
            
        features = self.extract_features(response_text, response_headers)
        X_scaled = self.scaler.transform(features)
        
        prediction = self.model.predict(X_scaled)[0]
        anomaly_score = -self.model.score_samples(X_scaled)[0]
        
        is_anomalous = prediction == -1  # -1 indicates anomaly
        
        return is_anomalous, float(anomaly_score)


class VulnerabilityConfirmer:
    """
    Correlation engine to confirm vulnerabilities using multiple signals.
    
    Combines detection results with anomaly scoring and heuristics
    to reduce false positives.
    """
    
    def __init__(self, anomaly_detector: Optional[AnomalyDetector] = None):
        """Initialize vulnerability confirmer."""
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        
    def confirm_vulnerability(
        self,
        vulnerabilities: List[Vulnerability],
        baseline_responses: List[str] = None,
    ) -> List[Vulnerability]:
        """
        Confirm vulnerabilities using multiple signals.
        
        Increases confidence when multiple signals align:
        - Detection logic
        - Response anomaly
        - Specific error patterns
        """
        confirmed = []
        
        for vuln in vulnerabilities:
            # Extract evidence
            if not vuln.evidence:
                confirmed.append(vuln)
                continue
                
            evidence = vuln.evidence[0]
            response_body = evidence.response_body
            response_headers = evidence.response_headers
            
            # Check for anomalies
            is_anomalous, anomaly_score = self.anomaly_detector.predict(
                response_body,
                response_headers
            )
            
            # Check for specific patterns
            has_error_pattern = self._check_error_patterns(response_body, vuln.type)
            has_injection_pattern = self._check_injection_patterns(response_body, vuln.type)
            
            # Calculate confirmation score
            confirmation_signals = sum([
                is_anomalous,
                has_error_pattern,
                has_injection_pattern,
            ])
            
            # Boost confidence based on signals
            if confirmation_signals > 0:
                signal_boost = 0.1 * confirmation_signals
                vuln.confidence = min(0.99, vuln.confidence + signal_boost)
                
            confirmed.append(vuln)
            
        return confirmed
        
    def _check_error_patterns(self, response_body: str, vuln_type: VulnerabilityType) -> bool:
        """Check for error patterns indicating successful exploitation."""
        error_patterns = {
            VulnerabilityType.SQL_INJECTION: [
                'sql', 'mysql', 'postgresql', 'syntax error', 'database error',
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                'command', 'execute', 'shell', 'exec', 'system',
            ],
            VulnerabilityType.SSTI: [
                'jinja2', 'template', 'render', 'expression',
            ],
        }
        
        patterns = error_patterns.get(vuln_type, [])
        response_lower = response_body.lower()
        
        return any(p in response_lower for p in patterns)
        
    def _check_injection_patterns(self, response_body: str, vuln_type: VulnerabilityType) -> bool:
        """Check for injection-specific success patterns."""
        if vuln_type == VulnerabilityType.REFLECTED_XSS:
            return '<script>' in response_body or 'onerror=' in response_body
        elif vuln_type == VulnerabilityType.SQL_INJECTION:
            return 'syntax' in response_body.lower()
            
        return False
