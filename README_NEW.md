# CSEH Scanner v2.0 - Enterprise Security Scanner

An advanced, modular, AI-powered web vulnerability scanner designed to detect and assess security vulnerabilities in modern web applications with enterprise-grade capabilities.

## Features

### 🎯 Core Capabilities

- **Advanced Web Crawling**
  - Asynchronous multi-threaded crawling
  - JavaScript rendering support (Selenium/Playwright)
  - Form detection and extraction
  - API endpoint discovery
  - SPA route detection
  - Configurable depth and URL limits

- **Intelligent Vulnerability Detection**
  - SQL Injection (error-based, boolean, blind, time-based)
  - NoSQL Injection
  - Cross-Site Scripting (Reflected, DOM-based)
  - Security Misconfiguration (headers, CORS, directory indexing)
  - Command Injection (planned)
  - SSTI/Template Injection (planned)
  - LDAP Injection (planned)

- **Smart Payload Generation**
  - Context-aware payload selection
  - Multiple encoding strategies (URL, Base64, HTML, Unicode)
  - WAF detection and evasion
  - Adaptive fuzzing
  - Grammar-based payload generation

- **AI-Powered Analysis**
  - Anomaly detection (Isolation Forest)
  - False positive reduction
  - Multi-signal vulnerability confirmation
  - Response baseline learning
  - Statistical deviation analysis

- **Advanced Risk Scoring**
  - CVSS v3.1 base score calculation
  - Dynamic risk adjustment
  - Severity classification
  - Exploitability estimation
  - Reachability scoring

- **Attack Path Modeling**
  - Vulnerability chain detection
  - Privilege escalation path finding
  - Critical node identification
  - GraphML/DOT export

- **Professional Reporting**
  - JSON technical reports
  - HTML executive summaries
  - Visual representations
  - Remediation guidance
  - OWASP Top 10 mapping

## Installation

### Requirements
- Python 3.8+
- pip

### Setup

```bash
# Clone repository
cd cseh

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Basic Scan

```bash
python cli.py https://example.com
```

### Advanced Scan

```bash
# Deep crawl with JavaScript
python cli.py https://example.com --depth 5 --js

# Custom output and logging
python cli.py https://example.com -o report.json -f both -l DEBUG

# Load configuration file
python cli.py --config scan_config.json

# Generate both JSON and HTML reports
python cli.py https://example.com -f both --report-dir ./reports
```

### Configuration File

Create `scan_config.json`:

```json
{
  "target_url": "https://example.com",
  "max_depth": 3,
  "max_urls": 1000,
  "use_javascript": true,
  "timeout": 30,
  "log_level": "INFO",
  "crawler": {
    "max_concurrent": 10,
    "rate_limit": 0.5,
    "respect_robots_txt": true
  },
  "detectors": {
    "enabled": [
      "sql_injection",
      "xss",
      "security_headers",
      "cors",
      "directory_indexing"
    ]
  }
}
```

Then run:
```bash
python cli.py --config scan_config.json
```

## CLI Usage

```
usage: cli.py [-h] [-d DEPTH] [-u MAX_URLS] [--js] [-t TIMEOUT] 
              [-o OUTPUT] [-f {json,html,both}] [--report-dir REPORT_DIR]
              [-l {DEBUG,INFO,WARNING,ERROR}] [--config CONFIG]
              [--save-config SAVE_CONFIG]
              [target]

CSEH: Advanced Web Vulnerability Scanner

positional arguments:
  target                Target URL to scan

options:
  -d, --depth           Maximum crawl depth (default: 3)
  -u, --max-urls        Maximum URLs to discover (default: 1000)
  --js                  Enable JavaScript rendering
  -t, --timeout         Request timeout in seconds (default: 30)
  -o, --output          Output report file
  -f, --format          Report format: json, html, both (default: json)
  --report-dir          Report output directory
  -l, --log-level       Logging level (default: INFO)
  --config              Load configuration from file
  --save-config         Save configuration to file
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed architecture documentation.

### Key Modules

```
scanner/
├── core.py                 # Main scanner orchestrator
├── config.py              # Configuration management
├── crawler/               # Advanced crawling engine
├── detector/              # Vulnerability detectors
├── payload_engine/        # Intelligent payload generation
├── ai_engine/             # ML-based anomaly detection
├── analyzer/              # Result analysis
├── reporting/             # Report generation
├── risk_engine/           # CVSS scoring
├── attack_graph/          # Attack path modeling
└── utils/                 # Utilities
```

## Phases

### ✅ Phase 1: Core Scanner (COMPLETE)
- [x] Modular architecture
- [x] Advanced crawling engine
- [x] Basic vulnerability detectors (SQL, XSS, headers)
- [x] Risk scoring (CVSS v3)
- [x] Report generation
- [x] Configuration management

### ✅ Phase 2: Intelligent Payload Engine (COMPLETE)
- [x] Context-aware payload generation
- [x] Multiple encoding strategies
- [x] WAF detection
- [x] Payload mutation
- [x] Fuzzing engine

### ✅ Phase 3: AI Anomaly Detection (COMPLETE)
- [x] Response analysis
- [x] Isolation Forest anomaly detection
- [x] Multi-signal confirmation
- [x] False positive reduction

### ✅ Phase 4: Attack Graph Modeling (COMPLETE)
- [x] Vulnerability relationship mapping
- [x] Attack path enumeration
- [x] Critical node identification
- [x] GraphML export

### 🔄 Phase 5: Advanced Features (IN PROGRESS)
- [ ] Stored XSS detection
- [ ] Authentication module
- [ ] Business logic testing
- [ ] GraphQL support
- [ ] API fuzzing
- [ ] Distributed scanning
- [ ] CI/CD integration

## Vulnerability Types

### Supported
- SQL Injection
- NoSQL Injection
- Reflected XSS
- DOM-based XSS
- Missing Security Headers
- CORS Misconfiguration
- Directory Indexing

### Planned
- Stored XSS
- Command Injection
- SSTI
- LDAP Injection
- CSRF
- Weak Cryptography
- Information Disclosure
- Authentication Issues
- Session Management
- Privilege Escalation

## Performance

- **Crawl Speed**: ~100-500 URLs/min (depends on target)
- **Scan Speed**: ~50-200 payloads/min per detector
- **Memory Footprint**: ~200-500 MB typical
- **Scalability**: Single machine supports 10-100 concurrent requests

## Report Example

### JSON Report Structure

```json
{
  "metadata": {
    "generator": "CSEH Scanner v2.0",
    "generated_at": "2026-02-26T12:00:00"
  },
  "scan": {
    "target_url": "https://example.com",
    "scan_start_time": "2026-02-26T12:00:00",
    "discovered_urls": [...],
    "vulnerabilities": [
      {
        "type": "SQL Injection",
        "target_url": "https://example.com/search?q=...",
        "title": "SQL Injection in search parameter",
        "severity": "High",
        "cvss_score": 8.5,
        "confidence": 0.95,
        "evidence": [...],
        "remediation": "Use parameterized queries..."
      }
    ],
    "summary": {
      "critical": 2,
      "high": 5,
      "medium": 12,
      "low": 8,
      "info": 3
    }
  }
}
```

## Security & Ethics

⚠️ **IMPORTANT**: Always obtain written authorization before scanning any target.

- ✅ Legal disclaimer included in reports
- ✅ Scope restriction enforcement
- ✅ Domain validation checks
- ✅ Rate limiting to prevent DoS
- ✅ Safe testing mode option

## Advanced Usage

### Programmatic API

```python
from scanner.core import VulnerabilityScanner
from scanner.utils.logging_util import setup_logging

# Setup logging
logger = setup_logging(level="INFO")

# Create scanner
scanner = VulnerabilityScanner(
    target_url="https://example.com",
    max_depth=5,
    use_js=True,
    timeout=30,
)

# Run scan
result = scanner_scan()

# Access results
for vuln in result.vulnerabilities:
    print(f"{vuln.title}: {vuln.severity.value}")
```

### Custom Detector Module

```python
from scanner.detector.base import BaseDetector
from scanner.utils.models import Vulnerability
from scanner.utils.constants import VulnerabilityType, Severity

class CustomDetector(BaseDetector):
    def __init__(self):
        super().__init__("CustomDetector")
    
    async def detect(self, target_url, evidence):
        findings = []
        # Custom detection logic
        return findings
```

## Debugging

Enable debug logging:

```bash
python cli.py https://example.com -l DEBUG
```

Or in code:
```python
logger = setup_logging(level="DEBUG", log_file="scan.log")
```

## Troubleshooting

### ModuleNotFoundError
```bash
pip install -r requirements.txt
```

### Chrome/Chromium Not Found (for --js option)
The scanner will automatically download ChromeDriver. If you have issues:
```bash
python -m webdriver_manager chrome --download
```

### SSL Certificate Errors
Some targets use self-signed certs. The scanner handles this, but for additional control:
```python
# In code, modify HTTP client settings
http_client.verify_ssl = False
```

## Contributing

Contributions are welcome! Areas for improvement:

- [ ] Additional detector modules
- [ ] Performance optimizations
- [ ] UI/dashboard
- [ ] Distributed scanning
- [ ] API authentication modules
- [ ] Exploitation simulation

## License

Proprietary Research Tool - Not for public redistribution

## Disclaimer

This tool is designed for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain written permission before scanning.

## Support

For issues, feature requests, or questions:
- Review [ARCHITECTURE.md](ARCHITECTURE.md)
- Check existing GitHub issues
- Consult the documentation

---

**Version**: 2.0  
**Last Updated**: 2026-02-26  
**Maintained By**: CSEH Security Team
