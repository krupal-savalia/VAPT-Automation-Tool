"""SQL Injection detection module."""

import logging
import re
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
        - Boolean-based detection with baseline comparison
        - Time-based blind detection
        - UNION-based detection with response analysis
        """
        findings = []
        
        try:
            response_body = evidence.get('response_body', '')
            response_body_lower = response_body.lower()
            response_status = evidence.get('response_status', 0)
            payload_used = evidence.get('payload_used', '')
            injection_point = evidence.get('injection_point', '')
            baseline = evidence.get('baseline_response', {})
            baseline_body = baseline.get('body', '') if baseline else ''
            
            # Get response lengths for comparison
            response_length = len(response_body)
            baseline_length = len(baseline_body)
            
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
                'mysql',
                'sqlserver',
                'sqlite3',
                'mariadb',
            ]
            
            # Look for SQL errors in response
            for pattern in sql_error_patterns:
                if pattern in response_body_lower and len(response_body) < 10000:
                    # use base helper to construct vulnerability correctly
                    findings.append(self.create_vulnerability(
                        vuln_type=VulnerabilityType.SQL_INJECTION,
                        target_url=target_url,
                        title='SQL Injection - Error-Based',
                        description=f'SQL error message exposed: {pattern}',
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        evidence_data=evidence,
                        affected_parameter=injection_point or 'unknown',
                    ))
                    return findings
            
            # Boolean-based detection with baseline comparison
            if isinstance(payload_used, str) and ("'" in payload_used or '"' in payload_used or 'or' in payload_used.lower()):
                # Compare response with baseline
                length_diff = abs(response_length - baseline_length) if baseline_length > 0 else 0
                
                # If response differs significantly from baseline, might be vulnerable
                if length_diff > 50:  # Significant difference
                    # Check for content changes that indicate successful injection
                    if response_body != baseline_body:
                        # Additional check: look for data patterns
                        if response_status == 200 and response_length > 100:
                            findings.append(self.create_vulnerability(
                                vuln_type=VulnerabilityType.SQL_INJECTION,
                                target_url=target_url,
                                title='SQL Injection - Boolean-Based',
                                description='Response behavior differs from baseline, indicating possible boolean-based SQL injection',
                                severity=Severity.HIGH,
                                confidence=0.75,
                                evidence_data=evidence,
                                affected_parameter=injection_point,
                            ))
            
            # Check for successful UNION SELECT
            if 'union' in payload_used.lower() and 'select' in payload_used.lower():
                # Look for data patterns that indicate successful UNION
                if response_status == 200 and len(response_body) > 200:
                    # Check if response looks like valid data (not an error)
                    if not any(err in response_body_lower for err in ['error', 'warning', 'exception']):
                        findings.append(self.create_vulnerability(
                            vuln_type=VulnerabilityType.SQL_INJECTION,
                            target_url=target_url,
                            title='SQL Injection - UNION-Based',
                            description='UNION SELECT payload returned what appears to be valid data',
                            severity=Severity.CRITICAL,
                            confidence=0.80,
                            evidence_data=evidence,
                        ))
            
            # Check for time-based (blind) SQL injection indicators
            time_payloads = ['sleep', 'waitfor', 'benchmark', 'delay']
            if any(tp in payload_used.lower() for tp in time_payloads):
                findings.append(self.create_vulnerability(
                    vuln_type=VulnerabilityType.SQL_INJECTION,
                    target_url=target_url,
                    title='SQL Injection - Time-Based (Potential)',
                    description='Time-based SQL injection payload detected. Manual verification recommended.',
                    severity=Severity.MEDIUM,
                    confidence=0.60,
                    evidence_data=evidence,
                ))
                    
        except Exception as e:
            logger.debug(f"SQL injection detection error: {e}")
            
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
        "admin'--",
        "' OR 1=1--",
        "'; return db.users.find({})//",
    ]
    
    # MongoDB specific error patterns
    MONGO_ERROR_PATTERNS = [
        'mongo',
        'BSON',
        'ObjectId',
        'duplicate key',
        'not authorized',
        'not master',
        'failed to decode',
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
        
        try:
            response_body = evidence.get('response_body', '')
            response_body_lower = response_body.lower()
            response_status = evidence.get('response_status', 0)
            payload_used = evidence.get('payload_used', '')
            injection_point = evidence.get('injection_point', '')
            baseline = evidence.get('baseline_response', {})
            baseline_body = baseline.get('body', '') if baseline else ''
            
            # Check for MongoDB or NoSQL error messages
            for pattern in self.MONGO_ERROR_PATTERNS:
                if pattern in response_body_lower:
                    findings.append(self.create_vulnerability(
                        vuln_type=VulnerabilityType.NOSQL_INJECTION,
                        target_url=target_url,
                        title='NoSQL Injection - Error-Based',
                        description=f'NoSQL/MongoDB error message exposed: {pattern}',
                        severity=Severity.HIGH,
                        confidence=0.90,
                        evidence_data=evidence,
                    ))
                    return findings
            
            # Compare with baseline for response differences
# Compare with baseline for response differences
            if baseline_body:
                if response_body != baseline_body and response_status == 200:
                    # Check for data exposure patterns
                    if any(indicator in response_body_lower for indicator in ["\"_id\"", "\"username\"", "\"email\"", "\"password\"", 'objectid']):
                        findings.append(self.create_vulnerability(
                            vuln_type=VulnerabilityType.NOSQL_INJECTION,
                            target_url=target_url,
                            title='NoSQL Injection - Data Exposure',
                            description='Response contains NoSQL-like data structures, possible injection success',
                            severity=Severity.HIGH,
                            confidence=0.75,
                            evidence_data=evidence,
                        ))
            
            # Check for NoSQL-specific injection patterns in payload
            nosql_patterns = ['$ne', '$gt', '$lt', '$regex', '$where', 'ObjectId']
            if any(pattern in payload_used for pattern in nosql_patterns):
                if response_status == 200:
                    findings.append(self.create_vulnerability(
                        vuln_type=VulnerabilityType.NOSQL_INJECTION,
                        target_url=target_url,
                        title='NoSQL Injection - Operator Injection',
                        description='NoSQL operator injection payload detected',
                        severity=Severity.MEDIUM,
                        confidence=0.65,
                        evidence_data=evidence,
                    ))
                    
        except Exception as e:
            logger.debug(f"NoSQL injection detection error: {e}")
            
        return findings
