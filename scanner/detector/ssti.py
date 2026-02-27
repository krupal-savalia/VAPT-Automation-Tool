"""Server-Side Template Injection (SSTI) vulnerability detection."""

import re
from typing import List, Dict, Any
from ..utils.models import Vulnerability


class SSTIDetector:
    """Detects Server-Side Template Injection vulnerabilities."""
    
    name = "SSTI Detector"
    
    def __init__(self):
        """Initialize detector."""
        self.test_payloads = [
            '${7*7}',
            '{{7*7}}',
            '{%set x=7*7%}{{x}}',
            '#{7*7}',
            '[= 7*7 =]',
            'freemarker.template.utility.Execute',
        ]
        
        self.template_responses = {
            '49': ('${7*7}', 'Jinja2/Spring'),
            '49': ('{{7*7}}', 'Jinja2/Python'),
            'freemarker': ('freemarker templates', 'FreeMarker'),
        }
    
    async def detect(self, url: str, evidence: Dict[str, Any]) -> List[Vulnerability]:
        """
        Detect SSTI vulnerabilities.
        
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
            response_body = evidence.get('response_body', '')
            payload = evidence.get('payload_used', '')
            
            # Check for arithmetic evaluation (7*7=49)
            if '49' in response_body and any(p in str(payload) for p in ['${7*7}', '{{7*7}}']):
                findings.append(Vulnerability(
                    vulnerability_type='Server-Side Template Injection',
                    title='SSTI Vulnerability Detected',
                    description='Server evaluates template expressions in user input',
                    severity='Critical',
                    confidence=0.95,
                    url=url,
                    parameter=evidence.get('injection_point', 'unknown'),
                    payload_used=payload,
                    evidence='Mathematical expression evaluated in response',
                ))
            
            # Check for template engine errors
            ssti_indicators = [
                'jinja2',
                'mako',
                'django',
                'jinja',
                'freemarker',
                'template syntax',
                'undefined is not defined',
            ]
            
            response_lower = response_body.lower()
            for indicator in ssti_indicators:
                if indicator in response_lower:
                    findings.append(Vulnerability(
                        vulnerability_type='Server-Side Template Injection',
                        title='SSTI Possible',
                        description=f'Template engine indicator found: {indicator}',
                        severity='High',
                        confidence=0.70,
                        url=url,
                        parameter=evidence.get('injection_point', 'unknown'),
                        payload_used=payload,
                        evidence=f'Template engine detected: {indicator}',
                    ))
                    break
                    
        except Exception:
            pass
            
        return findings
