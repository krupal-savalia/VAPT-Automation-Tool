"""GitHub Actions integration for CSEH Scanner."""

import json
from pathlib import Path
from typing import List, Dict, Any
from ..utils.models import ScanResult


class GitHubActionsReporter:
    """Generate GitHub Actions compatible output."""
    
    def generate_annotations(
        self,
        scan_result: ScanResult,
        output_file: str = "github_annotations.json"
    ) -> str:
        """
        Generate GitHub Actions annotations for vulnerabilities.
        
        Creates format compatible with GitHub Actions workflow annotations.
        """
        annotations = []
        
        for vuln in scan_result.vulnerabilities:
            annotation = {
                'title': vuln.title,
                'message': f"{vuln.description}\n\nSeverity: {vuln.severity.value}\nCVSS: {vuln.cvss_score}",
                'annotation_level': self._convert_severity_to_level(vuln.severity.value),
            }
            annotations.append(annotation)
            
        Path(output_file).write_text(json.dumps(annotations, indent=2))
        return output_file
        
    def _convert_severity_to_level(self, severity: str) -> str:
        """Convert severity to GitHub Actions level."""
        mapping = {
            'Critical': 'error',
            'High': 'error',
            'Medium': 'warning',
            'Low': 'notice',
            'Info': 'notice',
        }
        return mapping.get(severity, 'notice')


class SARIFReporter:
    """
    Generate SARIF (Static Analysis Results Interchange Format) output.
    
    SARIF is a standardized format for tool output, widely supported by
    GitHub Advanced Security and other platforms.
    """
    
    def generate(self, scan_result: ScanResult, output_file: str) -> str:
        """Generate SARIF report."""
        sarif = {
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'CSEH Scanner',
                        'version': '2.0',
                        'informationUri': 'https://github.com/cseh',
                        'rules': self._build_rules(scan_result),
                    }
                },
                'results': self._build_results(scan_result),
            }]
        }
        
        Path(output_file).write_text(json.dumps(sarif, indent=2))
        return output_file
        
    def _build_rules(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Build SARIF rules from vulnerabilities."""
        rules = {}
        
        for vuln in scan_result.vulnerabilities:
            rule_id = vuln.type.value.replace(' ', '_')
            
            if rule_id not in rules:
                rules[rule_id] = {
                    'id': rule_id,
                    'shortDescription': {'text': vuln.type.value},
                    'fullDescription': {'text': vuln.description},
                    'defaultConfiguration': {
                        'level': self._convert_severity_to_level(vuln.severity.value),
                    },
                    'helpUri': '',
                }
                
        return list(rules.values())
        
    def _build_results(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Build SARIF results from findings."""
        results = []
        
        for vuln in scan_result.vulnerabilities:
            if not vuln.evidence:
                continue
                
            evidence = vuln.evidence[0]
            result = {
                'ruleId': vuln.type.value.replace(' ', '_'),
                'level': self._convert_severity_to_level(vuln.severity.value),
                'message': {'text': vuln.title},
                'locations': [{
                    'physicalLocation': {
                        'address': {
                            'uri': evidence.request_url,
                            'relativeUri': evidence.request_url,
                        }
                    }
                }],
                'properties': {
                    'cvssScore': vuln.cvss_score,
                    'confidence': vuln.confidence,
                    'payload': evidence.payload_used or 'N/A',
                }
            }
            results.append(result)
            
        return results
        
    def _convert_severity_to_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            'Critical': 'error',
            'High': 'error',
            'Medium': 'warning',
            'Low': 'note',
            'Info': 'note',
        }
        return mapping.get(severity, 'note')


class PolicyChecker:
    """
    Enforce scanning policies and gate/block based on findings.
    
    Can fail CI/CD builds if scan results violate defined policies.
    """
    
    def __init__(self):
        """Initialize policy checker."""
        self.policies = {
            'fail_on_critical': True,
            'fail_on_high': False,
            'max_medium': None,
            'max_low': None,
        }
        
    def check_policies(self, scan_result: ScanResult) -> Dict[str, bool]:
        """
        Check scan results against policies.
        
        Returns
        -------
        Dict[str, bool]
            Dictionary with policy name and pass/fail status.
        """
        violations = {}
        
        if self.policies['fail_on_critical'] and scan_result.critical_count > 0:
            violations['critical_vulns_found'] = False
            
        if self.policies['fail_on_high'] and scan_result.high_count > 0:
            violations['high_vulns_found'] = False
            
        if self.policies['max_medium'] and scan_result.medium_count > self.policies['max_medium']:
            violations['medium_count_exceeded'] = False
            
        if self.policies['max_low'] and scan_result.low_count > self.policies['max_low']:
            violations['low_count_exceeded'] = False
            
        return violations
        
    def load_from_file(self, policy_file: str):
        """Load policies from JSON file."""
        import json
        with open(policy_file) as f:
            self.policies.update(json.load(f))
