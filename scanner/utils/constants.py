"""Constants and enumeration definitions for the scanner."""

from enum import Enum
from typing import Dict


class VulnerabilityType(Enum):
    """Enumeration of supported vulnerability types."""
    
    # Injection attacks
    SQL_INJECTION = "SQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    COMMAND_INJECTION = "Command Injection"
    LDAP_INJECTION = "LDAP Injection"
    SSTI = "Server-Side Template Injection"
    
    # Cross-Site Scripting
    REFLECTED_XSS = "Reflected XSS"
    STORED_XSS = "Stored XSS"
    DOM_XSS = "DOM-based XSS"
    MUTATION_XSS = "mXSS"
    
    # Authentication & Session
    WEAK_SESSION_COOKIE = "Weak Session Cookie"
    SESSION_FIXATION = "Session Fixation"
    JWT_MISCONFIGURATION = "JWT Misconfiguration"
    MISSING_TOKEN_VALIDATION = "Missing Token Validation"
    
    # Access Control
    IDOR = "Insecure Direct Object Reference"
    BROKEN_ACCESS_CONTROL = "Broken Access Control"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    
    # Security Misconfig
    MISSING_SECURITY_HEADERS = "Missing Security Headers"
    CORS_MISCONFIGURATION = "CORS Misconfiguration"
    DIR_INDEXING = "Directory Indexing"
    DEBUG_ENDPOINT = "Debug Endpoint Exposure"
    HTTP_METHOD_ABUSE = "HTTP Method Abuse"
    
    # Business Logic
    PRICE_MANIPULATION = "Price Manipulation"
    WORKFLOW_BYPASS = "Workflow Bypass"
    RATE_LIMIT_BYPASS = "Rate Limit Bypass"
    
    # Other
    OPEN_REDIRECT = "Open Redirect"
    XXE = "XML External Entity"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    SSRF = "Server-Side Request Forgery"


class Severity(Enum):
    """Risk severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(Enum):
    """Confidence levels for vulnerability detection."""
    DEFINITE = 0.95  # Confirmed vulnerability
    HIGH = 0.85      # Strong evidence
    MEDIUM = 0.7     # Good evidence
    LOW = 0.5        # Weak evidence
    UNCERTAIN = 0.3  # Possible vulnerability


# OWASP Top 10 mapping (2021)
OWASP_TOP_10_MAPPING: Dict[VulnerabilityType, str] = {
    VulnerabilityType.SQL_INJECTION: "A03:2021 – Injection",
    VulnerabilityType.REFLECTED_XSS: "A03:2021 – Injection",
    VulnerabilityType.STORED_XSS: "A03:2021 – Injection",
    VulnerabilityType.BROKEN_ACCESS_CONTROL: "A01:2021 – Broken Access Control",
    VulnerabilityType.CORS_MISCONFIGURATION: "A01:2021 – Broken Access Control",
    VulnerabilityType.MISSING_SECURITY_HEADERS: "A05:2021 – Security Misconfiguration",
    VulnerabilityType.DIR_INDEXING: "A05:2021 – Security Misconfiguration",
}

# Security headers that should be present
REQUIRED_SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
]

# Common CMS and framework detection patterns
FRAMEWORK_DETECTION_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-admin", r"wp-includes"],
    "Drupal": [r"sites/default", r"modules/", r"themes/"],
    "Magento": [r"media/", r"var/", r"skin/"],
    "Joomla": [r"components/", r"modules/", r"templates/"],
}
