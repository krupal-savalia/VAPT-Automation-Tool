"""Command Injection vulnerability detection."""

import re
import asyncio
from typing import List, Dict, Any
from ..utils.models import Vulnerability


class CommandInjectionDetector:
    """Detects command injection vulnerabilities."""
    
    name = "Command Injection Detector"
    
    def __init__(self):
        """Initialize detector."""
        self.command_patterns = [
            r'command not found',
            r'sh.*:.*not found',
            r'bash.*:.*not found',
            r'\$\(.*\)',
            r'`.*`',
            r'syntax error',
            r'unexpected token',
        ]
        
        self.test_payloads = [
            ';id',
            '|id',
            '||id',
            '&id',
            '&&id',
            '`id`',
            '$(id)',
            '\nid\n',
            '\rid\r',
        ]
    
    async def detect(self, url: str, evidence: Dict[str, Any]) -> List[Vulnerability]:
        """
        Detect command injection vulnerabilities.
        
        Parameters
        ----------
        url : str
            Target URL
        evidence : Dict[str, Any]
            Evidence dictionary with request/response data
            
        Returns
        -------
        List[Vulnerability]
            List of detected vulnerabilities
        """
        findings = []
        
        try:
            response_body = evidence.get('response_body', '').lower()
            request_data = evidence.get('request_data', {})
            
            # Check for command output patterns
            command_output_indicators = [
                'uid=', 'gid=', '/bin', '/usr', 'total ',
                'permission denied', 'no such file',
            ]
            
            for indicator in command_output_indicators:
                if indicator in response_body:
                    # Check if payload used suggests command injection
                    payload = evidence.get('payload_used', '')
                    if any(p in str(payload) for p in [';', '|', '`', '$(']):
                        findings.append(Vulnerability(
                            vulnerability_type='Command Injection',
                            title='Command Injection Detected',
                            description='Application may be vulnerable to OS command injection',
                            severity='High',
                            confidence=0.85,
                            url=url,
                            parameter=evidence.get('injection_point', 'unknown'),
                            payload_used=payload,
                            evidence=f'Command output indicator detected: {indicator}',
                        ))
                        break
            
            # Check for error-based indication
            error_patterns = [
                'command not found',
                'sh: 1:', 'bash: ',
                'syntax error',
            ]
            
            for pattern in error_patterns:
                if pattern in response_body:
                    payload = evidence.get('payload_used', '')
                    if any(p in str(payload) for p in [';', '|', '&']):
                        findings.append(Vulnerability(
                            vulnerability_type='Command Injection',
                            title='Possible Command Injection',
                            description='Error response suggests command execution attempt',
                            severity='High',
                            confidence=0.70,
                            url=url,
                            parameter=evidence.get('injection_point', 'unknown'),
                            payload_used=payload,
                            evidence=f'Error pattern matched: {pattern}',
                        ))
                        break
                        
        except Exception as e:
            pass
            
        return findings
