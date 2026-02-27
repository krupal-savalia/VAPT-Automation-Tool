"""Interface to AI payload recommendation with multiple backends.

Supports:
1. Ollama (local, free) - requires `ollama run mistral` or similar
2. Gemini API (cloud, needs API key)
3. Heuristic-based fallback (built-in, always works)

The selector sends response features and receives JSON guidance on vulnerability
type, payload category, mutation strategies and priority score.

Usage example::

    selector = AISelector()  # Uses heuristics or Ollama if available
    decision = selector.select({
        "reflection": True,
        "encoding": "html",
        "context": "body",
        "status_change": False,
        "error_patterns": ["sql"],
        "content_length_delta": 120,
        "response_time_delta": 0.05,
    })

Returned ``decision`` structure::

    {
        "vulnerability_type": "xss",
        "payload_category": "xss",
        "mutation_strategies": ["url_encode", "case_mutation"],
        "priority_score": 0.72
    }
"""

import os
import json
import logging
from typing import Dict, Any, Optional

import requests

logger = logging.getLogger(__name__)

# Environment configuration
AI_BACKEND = os.environ.get("AI_BACKEND", "heuristic")  # heuristic, ollama, or gemini
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
GEMINI_API_KEY = os.environ.get("GOOGLE_API_KEY", None)


class LocalHeuristicAI:
    """Smart heuristic-based AI using built-in rules (no API needed)."""

    def analyze(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Classify features and suggest mutations based on heuristics."""
        reflection = features.get("reflection", False)
        encoding = features.get("encoding", "none")
        context = features.get("context", "body")
        status_change = features.get("status_change", False)
        error_patterns = features.get("error_patterns", [])
        time_delta = features.get("response_time_delta", 0.0)
        length_delta = abs(features.get("content_length_delta", 0))

        vuln_type = "other_safe"
        payload_cat = "other_safe"
        mutations = []
        priority = 0.1

        # SQL Injection detection
        if any(pat in str(error_patterns).lower() for pat in ["sql", "syntax", "database"]):
            vuln_type = "sqli"
            payload_cat = "sqli_error"
            priority = 0.85
            mutations = ["url_encode", "double_encode", "case_mutation"]
        # Timing-based SQL injection
        elif time_delta > 2.0 and not reflection:
            vuln_type = "sqli"
            payload_cat = "sqli_boolean"
            priority = 0.75
            mutations = ["whitespace_injection"]
        # XSS detection
        elif reflection and context in ("body", "attribute"):
            vuln_type = "xss"
            payload_cat = "xss"
            priority = 0.8 if encoding == "none" else 0.6
            mutations = ["case_mutation", "unicode_encode"] if encoding in ("html", "url") else []
        # DOM-based XSS
        elif context == "javascript" and reflection:
            vuln_type = "xss"
            payload_cat = "xss"
            priority = 0.7
            mutations = ["url_encode"]
        # Directory traversal
        elif length_delta > 500 and not reflection:
            vuln_type = "directory_traversal"
            payload_cat = "dir_traversal"
            priority = 0.65
            mutations = []
        # Status change indicates possible issue
        elif status_change and reflection:
            vuln_type = "xss"
            payload_cat = "xss"
            priority = 0.6
            mutations = ["url_encode", "case_mutation"]
        
        return {
            "vulnerability_type": vuln_type,
            "payload_category": payload_cat,
            "mutation_strategies": mutations,
            "priority_score": priority,
        }


class OllamaAI:
    """Use Ollama for local AI inference (no API key needed)."""

    def __init__(self, base_url: str = OLLAMA_URL):
        self.base_url = base_url
        self.model = "mistral"  # or neural-chat, llama2, etc.

    def analyze(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Query Ollama model for recommendations."""
        try:
            prompt = (
                "Classify web vulnerability from these response features and suggest exploitation strategies. "
                "Respond with ONLY valid JSON (no markdown, no explanation): "
                "{ \"vulnerability_type\": (xss|sqli|directory_traversal|open_redirect|other_safe), "
                "\"payload_category\": <category>, \"mutation_strategies\": [<list>], \"priority_score\": <0-1> }\n"
                f"Features: {json.dumps(features)}"
            )

            resp = requests.post(
                f"{self.base_url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=15,
            )
            
            if resp.status_code != 200:
                logger.debug(f"Ollama returned {resp.status_code}")
                return None

            result = resp.json()
            text = result.get("response", "")

            # Extract JSON
            import re
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                data = json.loads(match.group())
                # Validate
                for key in ["vulnerability_type", "payload_category", "mutation_strategies", "priority_score"]:
                    if key not in data:
                        return None
                return data
        except Exception as e:
            logger.debug(f"Ollama error: {e}")
        return None


class GeminiAI:
    """Use Google Gemini API for AI recommendations."""

    def __init__(self, api_key: str = GEMINI_API_KEY):
        self.api_key = api_key
        self.model = "gemini-1.5-flash"

    def analyze(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Query Gemini API for recommendations."""
        if not self.api_key:
            logger.debug("Gemini API key not configured")
            return None

        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
            headers = {"Content-Type": "application/json"}
            
            prompt = (
                "Classify web application vulnerability from response features. "
                "Output ONLY JSON: {\"vulnerability_type\": (xss|sqli|directory_traversal|open_redirect|other_safe), "
                "\"payload_category\": <str>, \"mutation_strategies\": [<list>], \"priority_score\": <0-1>}\n"
                f"Features: {json.dumps(features)}"
            )

            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.1,
                    "maxOutputTokens": 300,
                },
            }

            resp = requests.post(url, headers=headers, json=payload, timeout=20, verify=False)
            
            if resp.status_code != 200:
                logger.debug(f"Gemini API error {resp.status_code}: {resp.text[:100]}")
                return None

            data = resp.json()
            if "error" in data:
                logger.debug(f"Gemini error: {data['error'].get('message')}")
                return None

            # Extract text from response
            if "candidates" in data and data["candidates"]:
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                import re
                match = re.search(r"\{.*\}", text, re.DOTALL)
                if match:
                    result = json.loads(match.group())
                    for key in ["vulnerability_type", "payload_category", "mutation_strategies", "priority_score"]:
                        if key not in result:
                            return None
                    return result
        except Exception as e:
            logger.debug(f"Gemini error: {e}")
        return None


class AISelector:
    """Unified AI selector with fallback chain: Ollama > Gemini > Heuristic."""

    def __init__(self, backend: str = AI_BACKEND):
        self.backend = backend.lower()
        self.heuristic = LocalHeuristicAI()
        self.ollama = OllamaAI() if self.backend in ("auto", "ollama") else None
        self.gemini = GeminiAI() if self.backend in ("auto", "gemini") or GEMINI_API_KEY else None

    def select(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Route to appropriate AI backend with fallback chain."""
        # Try backends in order based on configuration
        if self.backend == "heuristic":
            return self.heuristic.analyze(features)
        elif self.backend == "ollama":
            result = self.ollama.analyze(features) if self.ollama else None
            return result or self.heuristic.analyze(features)
        elif self.backend == "gemini":
            result = self.gemini.analyze(features) if self.gemini else None
            return result or self.heuristic.analyze(features)
        else:  # "auto" or unknown
            # Try Ollama first (local, fastest)
            if self.ollama:
                result = self.ollama.analyze(features)
                if result:
                    logger.debug("Used Ollama AI")
                    return result
            # Try Gemini next (cloud)
            if self.gemini:
                result = self.gemini.analyze(features)
                if result:
                    logger.debug("Used Gemini AI")
                    return result
            # Fall back to heuristic
            logger.debug("Using local heuristic AI")
            return self.heuristic.analyze(features)
