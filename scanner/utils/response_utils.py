import re
import hashlib
from typing import Dict, Any, List, Optional, Tuple

# patterns that often change between requests
_DYNAMIC_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",  # ISO timestamps
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",  # UUIDs
    r"\b\d{6,}\b",  # long numeric ids
]
_CSRF_PATTERN = re.compile(r'(?:name|id)=["\']csrf_token["\']\s+value=["\'][^"\']+["\']', re.IGNORECASE)
_NONCE_PATTERN = re.compile(r'nonce=["\'][^"\']+["\']', re.IGNORECASE)

# SQL error patterns for validation
SQL_ERROR_PATTERNS = [
    r"sql\s+syntax.*error",
    r"mysql.*error",
    r"postgresql.*error",
    r"ORA-\d{5}",
    r"Microsoft SQL Native Error",
    r"SQLServer.*error",
    r"sqlite3.*error",
    r"unterminated.*string",
    r"unexpected.*token",
    r"SQL.*warning",
    r"database.*error",
    r"table.*doesn't exist",
    r"column.*not found",
    r"Operand type clash",
]

# XSS execution context markers
XSS_EXECUTION_CONTEXTS = [
    '<script',
    'onerror=',
    'onload=',
    'onclick=',
    'onmouseover=',
    'alert(',
    'confirm(',
    'prompt(',
    'javascript:',
    'eval(',
    'innerHTML',
    'insertAdjacentHTML',
    'document.write',
]

# HTML tag contexts that are NOT executable
XSS_SAFE_CONTEXTS = [
    '<textarea',
    '<title>',
    '<iframe>',  # would need src=javascript which is separate
    '<comment>',
    '<noscript>',
    '<style>',
]


def normalize_response(body: str) -> str:
    """Normalize response text to strip dynamic content and whitespace.

    The goal is to make structural comparisons meaningful by removing
    timestamps, uuids, CSRF tokens, nonces, and collapsing whitespace.
    """
    text = body or ""
    for pat in _DYNAMIC_PATTERNS:
        text = re.sub(pat, '', text)
    text = _CSRF_PATTERN.sub('', text)
    text = _NONCE_PATTERN.sub('', text)
    # normalize whitespace
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def hash_response(body: str) -> str:
    """Return SHA256 hash of body after normalization."""
    normalized = normalize_response(body)
    return hashlib.sha256(normalized.encode('utf-8', errors='ignore')).hexdigest()


def capture_baseline(resp: Dict[str, Any]) -> Dict[str, Any]:
    """Convert bare response dict to a stored baseline record.

    Only stores summary information not full body to save memory.
    """
    import time

    body = resp.get('body', '')
    start = time.monotonic()
    status = resp.get('status', 0)
    headers = resp.get('headers', {})
    length = len(body)
    resp_hash = hash_response(body)
    elapsed = time.monotonic() - start
    # keep small snippet so detectors can check for patterns without holding
    # entire content (truncate to 1k characters)
    snippet = body[:1024] if isinstance(body, str) else ''

    return {
        'url': resp.get('url'),
        'status': status,
        'hash': resp_hash,
        'length': length,
        'time': elapsed,
        'headers': headers,
        'body_snippet': snippet,
    }


# ============================================================================
# SQL ERROR VALIDATION HELPERS
# ============================================================================

def validate_sql_error(
    response_body: str,
    baseline_body: Optional[str] = None,
    baseline_status: Optional[int] = None,
    response_status: Optional[int] = None
) -> Tuple[bool, str]:
    """Validate SQL error pattern to reduce false positives.
    
    Returns: (is_valid, reason)
    
    Rules:
    - Error pattern must NOT appear in baseline
    - If baseline is 500 and response is 500, assume generic crash (invalid)
    - Must detect at least one SQL error pattern
    """
    if not response_body:
        return False, "Empty response body"
    
    response_lower = response_body.lower()
    
    # Check if error appears in baseline
    if baseline_body:
        baseline_lower = baseline_body.lower()
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, response_lower, re.IGNORECASE):
                # Check if same pattern exists in baseline
                if re.search(pattern, baseline_lower, re.IGNORECASE):
                    return False, "SQL error pattern already present in baseline"
    
    # Check for generic 500 crash - if both baseline and response are 500,
    # it's likely a generic application crash, not SQL injection
    if baseline_status == 500 and response_status == 500:
        return False, "Both baseline and response are 500 (generic crash)"
    
    # Check if any SQL error pattern exists in response
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, response_lower, re.IGNORECASE):
            return True, f"Valid SQL error pattern found: {pattern}"
    
    return False, "No SQL error pattern detected"


def check_generic_500_crash(
    baseline_status: int,
    response_status: int,
    baseline_body: str = "",
    response_body: str = ""
) -> bool:
    """Check if response is a generic 500 crash rather than SQL injection.
    
    Returns True if this appears to be a generic crash (should not report).
    """
    # Both are 500 - likely generic
    if baseline_status == 500 and response_status == 500:
        return True
    
    # If response is 500 but similar error content in both, generic crash
    if response_status == 500 and baseline_body and response_body:
        baseline_lower = baseline_body.lower()
        resp_lower = response_body.lower()
        
        # Check if same error message appears in both
        error_keywords = ['error', 'exception', 'warning', 'fatal']
        for keyword in error_keywords:
            if keyword in baseline_lower and keyword in resp_lower:
                # Check if error message is similar (within 50% similarity)
                from .base import InjectionDetector
                sim = InjectionDetector().calculate_response_difference(
                    baseline_body[:500], response_body[:500]
                )
                if sim > 0.7:  # High similarity = generic error
                    return True
    
    return False


# ============================================================================
# XSS REFLECTION VALIDATION HELPERS
# ============================================================================

def validate_xss_reflection(
    response_body: str,
    payload: str,
    content_type: str = "",
    csp_headers: Optional[Dict[str, str]] = None
) -> Tuple[bool, str]:
    """Validate XSS reflection to ensure it's exploitable.
    
    Returns: (is_valid, reason)
    
    Rules:
    - Payload must be reflected (not HTML-encoded)
    - Content-Type must be text/html
    - Must not be in safe context (<textarea>, <title>, etc.)
    - Check CSP headers if present
    - Should be in executable context (<script>, event handlers, etc.)
    """
    if not response_body or not payload:
        return False, "Empty response or payload"
    
    # Require HTML content type
    if 'html' not in content_type.lower():
        return False, f"Content-Type is not HTML: {content_type}"
    
    normalized = normalize_response(response_body)
    normalized_lower = normalized.lower()
    
    # Check if payload is HTML-encoded (not exploitable if encoded)
    if '<' in normalized_lower or '>' in normalized_lower:
        # Check if payload appears as encoded only
        encoded_payload = payload.replace('<', '<').replace('>', '>')
        if encoded_payload in normalized_lower:
            return False, "Payload is HTML-encoded (not executable)"
    
    # Check if payload is in safe (non-executable) context
    for safe_ctx in XSS_SAFE_CONTEXTS:
        if safe_ctx in normalized_lower:
            # Check if payload appears inside this safe context
            # This is a simplified check - full HTML parsing would be better
            return False, f"Payload appears inside safe context: {safe_ctx}"
    
    # Check CSP headers
    if csp_headers:
        csp = csp_headers.get('Content-Security-Policy', '') or \
              csp_headers.get('Content-Security-Policy-Report-Only', '')
        
        # Check for restrictive CSP that blocks XSS
        if csp:
            # Check for 'unsafe-inline' which would allow XSS
            if 'unsafe-inline' not in csp.lower():
                # Check if script-src is restrictive
                if 'script-src' in csp.lower():
                    # Has script-src but no unsafe-inline - likely blocked
                    return False, f"CSP restricts script execution: {csp[:100]}"
    
    # Check if payload is reflected at all
    if payload not in normalized:
        # Try URL-decoded version
        from urllib.parse import unquote
        decoded = unquote(payload)
        if decoded not in normalized:
            return False, "Payload not reflected in response"
    
    # Check for execution context
    has_execution_ctx = any(ctx in normalized_lower for ctx in XSS_EXECUTION_CONTEXTS)
    
    if has_execution_ctx:
        return True, "Payload reflected in executable context"
    
    # If no execution context found but payload is reflected,
    # this is medium confidence (reflection without proof of execution)
    return True, "Payload reflected but no clear execution context"


def check_csp_protection(headers: Dict[str, str]) -> Tuple[bool, str]:
    """Check if CSP headers provide XSS protection.
    
    Returns: (is_protected, details)
    """
    csp = headers.get('Content-Security-Policy', '') or \
          headers.get('Content-Security-Policy-Report-Only', '')
    
    if not csp:
        return False, "No CSP header present"
    
    csp_lower = csp.lower()
    
    # Check for unsafe-inline (XSS vulnerable)
    if 'unsafe-inline' in csp_lower:
        return False, "CSP allows unsafe-inline"
    
    # Check for script-src
    if 'script-src' in csp_lower:
        # Has restrictive script-src
        return True, f"CSP restricts script-src: {csp[:100]}"
    
    # Default deny
    return True, "CSP header present"


def compare_responses_for_boolean_sqli(
    true_response: Dict[str, Any],
    false_response: Dict[str, Any],
    baseline_response: Optional[Dict[str, Any]] = None,
    length_threshold: int = 50
) -> Tuple[bool, str]:
    """Compare true/false responses for boolean-based SQL injection.
    
    Returns: (is_valid_sqli, reason)
    
    Validates:
    - True response != False response (different behavior)
    - True response ≈ baseline (true condition doesn't break query)
    - False response differs significantly (false condition affects output)
    """
    true_body = true_response.get('body', '')
    false_body = false_response.get('body', '')
    
    true_hash = hash_response(true_body)
    false_hash = hash_response(false_body)
    
    # Condition 1: True and False responses must differ
    if true_hash == false_hash:
        return False, "True and false responses are identical"
    
    # Condition 2: True response should be similar to baseline
    if baseline_response:
        baseline_body = baseline_response.get('body', '')
        baseline_hash = hash_response(baseline_body)
        
        true_len = len(true_body)
        baseline_len = len(baseline_body)
        len_diff = abs(true_len - baseline_len)
        
        # True should be close to baseline in length
        if len_diff > length_threshold * 2:
            return False, f"True response differs too much from baseline (len diff: {len_diff})"
        
        # True and baseline should have similar hash (or at least similar content)
        if true_hash != baseline_hash:
            # Check if difference is significant
            from .base import InjectionDetector
            similarity = InjectionDetector().calculate_response_difference(
                normalize_response(baseline_body[:1000]),
                normalize_response(true_body[:1000])
            )
            if similarity < 0.7:
                return False, f"True response significantly differs from baseline (similarity: {similarity:.2f})"
    
    # Condition 3: False response should differ significantly from baseline
    if baseline_response:
        baseline_body = baseline_response.get('body', '')
        false_len = len(false_body)
        baseline_len = len(baseline_body)
        len_diff = abs(false_len - baseline_len)
        
        if len_diff < length_threshold:
            return False, f"False response too similar to baseline (len diff: {len_diff})"
    
    return True, "Boolean-based SQL injection pattern confirmed"
