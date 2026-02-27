"""Risk scoring engine using CVSS v3 and dynamic risk calculation."""

import logging
from typing import Dict, List, Optional
from ..utils.models import Vulnerability
from ..utils.constants import VulnerabilityType, Severity


logger = logging.getLogger(__name__)


class RiskEngine:
    """Advanced risk scoring using CVSS v3 and contextual factors."""
    
    # CVSS v3.1 Base Score Ranges
    SEVERITY_THRESHOLDS = {
        Severity.CRITICAL: (9.0, 10.0),
        Severity.HIGH: (7.0, 8.9),
        Severity.MEDIUM: (4.0, 6.9),
        Severity.LOW: (0.1, 3.9),
        Severity.INFO: (0.0, 0.1),
    }
    
    # Attack Vector scoring
    ATTACK_VECTOR_SCORES = {
        'local': 0.55,
        'adjacent': 0.62,
        'network': 0.85,
        'physical': 0.2,
    }
    
    # Attack Complexity scoring
    ATTACK_COMPLEXITY_SCORES = {
        'low': 0.77,
        'high': 0.44,
    }
    
    # Privileges Required scoring
    PRIVILEGES_REQUIRED_SCORES = {
        'none': 0.85,
        'low': 0.62,
        'high': 0.27,
    }
    
    # User Interaction scoring
    USER_INTERACTION_SCORES = {
        'none': 0.85,
        'required': 0.62,
    }
    
    def __init__(self):
        """Initialize risk engine."""
        self.findings: List[Vulnerability] = []
        
    def calculate_cvss_score(
        self,
        attack_vector: str = 'network',
        attack_complexity: str = 'low',
        privileges_required: str = 'none',
        user_interaction: str = 'none',
        impact_confidentiality: str = 'high',
        impact_integrity: str = 'high',
        impact_availability: str = 'high',
    ) -> float:
        """
        Calculate CVSS v3.1 base score.
        
        All parameters default to worst-case (highest risk) scenarios.
        """
        # Get base metric scores
        av_score = self.ATTACK_VECTOR_SCORES.get(attack_vector.lower(), 0.85)
        ac_score = self.ATTACK_COMPLEXITY_SCORES.get(attack_complexity.lower(), 0.77)
        pr_score = self.PRIVILEGES_REQUIRED_SCORES.get(privileges_required.lower(), 0.85)
        ui_score = self.USER_INTERACTION_SCORES.get(user_interaction.lower(), 0.85)
        
        # Impact scoring (CIA)
        c_impact = 0.56 if impact_confidentiality.lower() == 'high' else 0.22
        i_impact = 0.56 if impact_integrity.lower() == 'high' else 0.22
        a_impact = 0.56 if impact_availability.lower() == 'high' else 0.22
        
        # Calculate impact
        impact = 1 - ((1 - c_impact) * (1 - i_impact) * (1 - a_impact))
        
        # Calculate exploitability
        exploitability = 8.15 * av_score * ac_score * pr_score * ui_score
        
        # Calculate base score
        if impact <= 0:
            base_score = 0
        else:
            base_score = min(10, 0 if impact == 0 else (exploitability + impact))
            
        return round(base_score, 1)
        
    def assign_severity(
        self,
        vulnerabilities: List[Vulnerability],
    ) -> List[Vulnerability]:
        """
        Re-score and assign severity levels to vulnerabilities.
        
        Considers:
        - Detection confidence
        - Exploitability
        - Reachability
        - CVSS score
        """
        for vuln in vulnerabilities:
            # Default CVSS based on type
            cvss = self._default_cvss_for_type(vuln.type)
            
            # Adjust based on factors
            if vuln.exploitability < 0.3:
                cvss *= 0.7
            elif vuln.exploitability > 0.8:
                cvss *= 1.2
                
            if vuln.reachability < 0.3:
                cvss *= 0.5
                
            # Confidence affects scoring
            cvss *= vuln.confidence
            
            # Cap at 10.0
            cvss = min(10.0, cvss)
            vuln.cvss_score = round(cvss, 1)
            
            # Assign severity based on score
            for severity, (low, high) in self.SEVERITY_THRESHOLDS.items():
                if low <= cvss <= high:
                    vuln.severity = severity
                    break
                    
        return vulnerabilities
        
    def _default_cvss_for_type(self, vuln_type: VulnerabilityType) -> float:
        """Get default CVSS score for vulnerability type."""
        defaults = {
            VulnerabilityType.SQL_INJECTION: 9.8,
            VulnerabilityType.REFLECTED_XSS: 7.5,
            VulnerabilityType.STORED_XSS: 8.2,
            VulnerabilityType.IDOR: 7.5,
            VulnerabilityType.BROKEN_ACCESS_CONTROL: 8.1,
            VulnerabilityType.MISSING_SECURITY_HEADERS: 5.3,
            VulnerabilityType.CORS_MISCONFIGURATION: 7.1,
        }
        return defaults.get(vuln_type, 5.5)
        
    def prioritize(
        self,
        vulnerabilities: List[Vulnerability],
    ) -> List[Vulnerability]:
        """Sort vulnerabilities by risk priority."""
        return sorted(
            vulnerabilities,
            key=lambda v: (
                v.severity.value,  # Primary: severity
                -v.cvss_score,     # Secondary: CVSS score
                -v.confidence,     # Tertiary: confidence
            ),
            reverse=True
        )
