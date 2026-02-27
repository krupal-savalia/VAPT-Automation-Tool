"""Utilities for analysing HTTP responses and extracting features.

The AI selector depends on structured features about how the application
responded to a test payload.  This module encapsulates logic for
extracting those characteristics (reflection, error messages, timing
changes, etc.) so that the rest of the scanner can remain clean.
"""

import re
from typing import Dict, Any, Optional, List

# common error signatures we look for when probing for SQLi / other
# injection issues.  The list is deliberately short but can be
# extended/overridden by consumers if needed.
_ERROR_PATTERNS = [
    r"syntax error", r"unclosed quotation", r"sql syntax", r"exception",
    r"traceback", r"not found", r"denied",
]


class ResponseAnalyzer:
    """Analyse responses and produce structured feature dictionaries."""

    def analyze(
        self,
        response: Dict[str, Any],
        baseline: Optional[Dict[str, Any]] = None,
        injected_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return a feature dict suitable for the AI selector.

        Parameters
        ----------
        response : dict
            The response received after sending a payload.
        baseline : dict, optional
            A baseline response from the same URL without any injection.
        injected_value : str, optional
            The value that was injected into the request (if any).

        The returned dictionary always contains the keys listed in the
        project specification.  Missing or unknown values are filled with
        sensible defaults.
        """
        features: Dict[str, Any] = {
            "reflection": False,
            "encoding": "none",
            "context": "body",
            "status_change": False,
            "error_patterns": [],
            "content_length_delta": 0.0,
            "response_time_delta": 0.0,
        }

        if not response:
            return features

        body = response.get("body", "") or ""
        status = response.get("status", 0)
        elapsed = response.get("elapsed", 0.0)

        # reflection check
        if injected_value and injected_value in body:
            features["reflection"] = True

            # try to guess encoding/context by some heuristics
            if "<" in injected_value and ">" in injected_value:
                features["encoding"] = "html"
            elif "%" in injected_value:
                features["encoding"] = "url"
            elif "\"" in injected_value or "'" in injected_value:
                features["encoding"] = "json"

            # guess context by looking at surrounding tags if available
            idx = body.find(injected_value)
            if idx != -1:
                snippet = body[max(0, idx - 20) : idx + len(injected_value) + 20]
                if "<script" in snippet.lower():
                    features["context"] = "javascript"
                elif "=" in snippet and "\"" in snippet:
                    features["context"] = "attribute"
                else:
                    features["context"] = "body"

        # status change
        if baseline and status != baseline.get("status"):
            features["status_change"] = True

        # error patterns
        for pat in _ERROR_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                features["error_patterns"].append(pat)

        # length delta
        if baseline:
            base_length = len(baseline.get("body", "") or "")
            features["content_length_delta"] = len(body) - base_length
            features["response_time_delta"] = elapsed - baseline.get("elapsed", 0.0)

        return features
