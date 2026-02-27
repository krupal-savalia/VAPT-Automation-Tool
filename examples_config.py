#!/usr/bin/env python
"""
Example configuration files for CSEH Scanner.

Copy the JSON configuration you want to a file and use it with:
    python cli.py --config your_config.json
"""

import json
from pathlib import Path

# Basic scan configuration
BASIC_CONFIG = {
    "target_url": "https://example.com",
    "max_depth": 2,
    "max_urls": 500,
    "use_javascript": False,
    "timeout": 30,
    "log_level": "INFO"
}

# Deep/thorough scan configuration
DEEP_CONFIG = {
    "target_url": "https://example.com",
    "max_depth": 5,
    "max_urls": 5000,
    "use_javascript": True,
    "timeout": 60,
    "log_level": "INFO",
    "crawler": {
        "max_concurrent": 20,
        "rate_limit": 0.2,
        "respect_robots_txt": True,
    },
    "detectors": {
        "enabled": [
            "sql_injection",
            "nosql_injection",
            "xss",
            "security_headers",
            "cors",
            "directory_indexing",
        ]
    },
    "scanning": {
        "test_all_parameters": True,
        "test_cookies": True,
        "test_headers": True,
    }
}

# API-focused scan configuration
API_CONFIG = {
    "target_url": "https://api.example.com",
    "max_depth": 1,
    "max_urls": 200,
    "use_javascript": False,
    "timeout": 30,
    "crawler": {
        "max_concurrent": 10,
    },
    "detectors": {
        "enabled": [
            "sql_injection",
            "nosql_injection",
            "xss",
        ]
    },
    "scanning": {
        "test_all_parameters": True,
    }
}

# Strict security policy
POLICY_STRICT = {
    "fail_on_critical": True,
    "fail_on_high": True,
    "max_medium": 0,
}

# Moderate security policy
POLICY_MODERATE = {
    "fail_on_critical": True,
    "fail_on_high": False,
    "max_medium": 20,
}

def save_config(name: str, config: dict):
    """Save configuration to file."""
    filename = f"{name}_config.json"
    Path(filename).write_text(json.dumps(config, indent=2))
    print(f"Saved {filename}")

if __name__ == "__main__":
    # Save all example configurations
    save_config("basic", BASIC_CONFIG)
    save_config("deep", DEEP_CONFIG)
    save_config("api", API_CONFIG)
    
    print("\nConfiguration files created. Use with:")
    print("  python cli.py --config basic_config.json")
