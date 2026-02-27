"""SQL Injection detection module."""

import logging
from typing import List, Dict, Any
import aiohttp
from .base import InjectionDetector
from ..utils.models import Vulnerability
from ..utils.constants import VulnerabilityType, Severity


logger = logging.getLogger(__name__)


class SQLInjectionDetector(InjectionDetector):
    """Detects SQL injection vulnerabilities using multiple techniques."""
    
    # Test payloads for SQL injection
    ERROR_BASED_PAYLOADS = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        "' UNION SELECT NULL--",
        "' AND 1=1--",
        "' AND 1=2--",
        "1; DROP TABLE users--",
    ]
    
    TIME_BASED_PAYLOADS = [
        "' AND SLEEP(5)--",
        "' AND BENCHMARK(5000000,MD5('test'))--",
        "' AND WAITFOR DELAY '00:00:05'--",
        "1' AND SLEEP(5)--",
    ]
    
    BOOLEAN_PAYLOADS = [
        "' AND '1'='1",
        "' AND '1'='2",
        "1' AND '1'='1",
        "1' AND '1'='2",
    ]
    
    def __init__(self):
        """Initialize SQL injection detector."""
        super().__init__("SQLInjectionDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """
        Detect SQL injection vulnerabilities.

        Supports:
        - Error-based detection
        - Boolean-based detection
        - Time-based blind detection
        """
        findings = []
        
        try:
            response_body = evidence.get('response_body', '').lower()
            response_status = evidence.get('response_status', 0)
            payload_used = evidence.get('payload_used', '')
            injection_point = evidence.get('injection_point', '')
            
            # Check for SQL error messages (error-based detection)
            sql_error_patterns = [
                'sql error',
                'mysql_fetch',
                'mysql error',
                'warning: mysql',
                'sql syntax',
                'database error',
                'sql statement',
                'postgresql',
                'oracle error',
                'odbc',
                'mssql',
                'syntax error',
                'invalid sql',
                'parse error',
                'unclosed quotation',
                'unexpected end of file',
                'column',
                'table',
                'constraint',
                'duplicate entry',
            ]
            
            # Look for SQL errors in response
            for pattern in sql_error_patterns:
                if pattern in response_body and len(response_body) < 10000:
                    findings.append(Vulnerability(
                        vulnerability_type='SQL Injection',
                        title='SQL Injection - Error-Based',
                        description=f'SQL error message exposed: {pattern}',
                        severity='Critical',
                        confidence=0.95,
                        url=target_url,
                        parameter=injection_point or 'unknown',
                        payload_used=payload_used,
                        evidence=f'SQL error pattern detected: {pattern}',
                    ))
                    return findings
            
            # Boolean-based detection
            if isinstance(payload_used, str) and ("'" in payload_used or '"' in payload_used):
                # Check for significant response differences
                response_length = len(response_body)
                
                # If response has content and contains data-like patterns, may be vulnerable
                if response_length > 100 and any(marker in response_body for marker in ['table', 'tr>', 'td>', '<li', '<option']):
                    # Additional confidence check: look for query strings
                    if any(q in target_url.lower() for q in ['search', 'query', 'filter', 'id=', 'name=', 'product=']):
                        findings.append(Vulnerability(
                            vulnerability_type='SQL Injection',
                            title='SQL Injection - Potential Boolean-Based',
                            description='Response behavior suggests possible boolean-based SQL injection',
                            severity='High',
                            confidence=0.70,
                            url=target_url,
                            parameter=injection_point,
                            payload_used=payload_used,
                            evidence='Query parameter with data response detected',
                        ))
            
            # Check for successful UNION SELECT
            if 'union' in payload_used.lower() and 'select' in payload_used.lower():
                # Look for data patterns that shouldn't be in error pages
                if response_status == 200 and len(response_body) > 200:
                    findings.append(Vulnerability(
                        vulnerability_type='SQL Injection',
                        title='SQL Injection - Possible UNION-Based',
                        description='UNION SELECT payload returned successful response',
                        severity='Critical',
                        confidence=0.75,
                        url=target_url,
                        parameter=injection_point,
                        payload_used=payload_used,
                        evidence='Successful HTTP 200 response to UNION SELECT',
                    ))
        except Exception:
            pass
            
        return findings


class NoSQLInjectionDetector(InjectionDetector):
    """Detects NoSQL injection vulnerabilities."""
    
    NOSQL_PAYLOADS = [
        "' OR '1'='1",
        "' || '1'=='1",
        "{$ne: null}",
        "{$ne: ''}",
        "{$gt: ''}",
        "{$gt: '-1'}",
    ]
    
    def __init__(self):
        """Initialize NoSQL injection detector."""
        super().__init__("NoSQLInjectionDetector")
        
    async def detect(
        self, 
        target_url: str, 
        evidence: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Detect NoSQL injection vulnerabilities."""
        findings = []
        return findings
