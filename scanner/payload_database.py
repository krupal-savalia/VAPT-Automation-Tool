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

    # Directory traversal probes (trying to reach sensitive files)
    "dir_traversal": [
        "../",  # relative traversal
        "..\\",  # windows style
        "../../etc/passwd",
        "..%2F..%2Fetc%2Fpasswd",
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
