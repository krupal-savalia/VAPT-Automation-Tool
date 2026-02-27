# CSEH Scanner v2.0 - Architecture Documentation

## Overview

CSEH (Comprehensive Security Enterprise for Hacking) is an enterprise-grade, AI-powered web vulnerability scanner designed to detect and assess security vulnerabilities in modern web applications.

## Project Structure

```
scanner/
├── __init__.py
├── core.py                          # Main scanner orchestrator
├── config.py                        # Configuration management
│
├── crawler/                         # Advanced crawling engine
│   ├── __init__.py
│   └── advanced_crawler.py          # Async crawler with JS support
│
├── detector/                        # Vulnerability detection modules
│   ├── __init__.py
│   ├── base.py                      # Base detector classes
│   ├── injection.py                 # SQL/NoSQL/Command injection
│   ├── xss.py                       # XSS detection
│   ├── security_config.py           # Security header misconfig
│   └── [future modules]
│
├── payload_engine/                  # Intelligent payload generation
│   ├── __init__.py
│   ├── generator.py                 # Context-aware payload generation
│   ├── waf_detector.py              # WAF fingerprinting & detection
│   └── fuzzer.py                    # Fuzzing & mutation engine
│
├── ai_engine/                       # ML-based analysis & detection
│   ├── __init__.py
│   └── anomaly_detector.py          # Anomaly detection & confirmation
│
├── analyzer/                        # Result analysis & correlation
│   └── [analyzer modules]           # (Phase 3)
│
├── reporting/                       # Report generation
│   ├── __init__.py
│   └── reporters.py                 # JSON/HTML report generators
│
├── risk_engine/                     # Risk scoring
│   ├── __init__.py
│   └── cvss_engine.py              # CVSS v3 scoring
│
├── attack_graph/                    # Attack path modeling
│   └── [graph modules]              # (Phase 4)
│
└── utils/                           # Utilities & helpers
    ├── __init__.py
    ├── constants.py                 # Enums & constants
    ├── models.py                    # Data models
    ├── logging_util.py              # Logging configuration
    └── http_client.py               # HTTP client utilities
```

## Key Components

### 1. Advanced Crawler (Phase 1)
**Location:** `scanner/crawler/advanced_crawler.py`

Features:
- Asynchronous crawling with configurable concurrency
- Form detection and extraction
- Query parameter analysis
- Same-domain validation
- Configurable depth and URL limits

### 2. Vulnerability Detectors (Phase 1)
**Location:** `scanner/detector/`

Implemented:
- **injection.py**: SQL Injection, NoSQL Injection
- **xss.py**: Reflected XSS, DOM-based XSS
- **security_config.py**: Security headers, CORS, Directory indexing

All detectors inherit from `BaseDetector` for consistency.

### 3. Intelligent Payload Engine (Phase 2)
**Location:** `scanner/payload_engine/`

Components:
- **generator.py**: Context-aware payload generation with multiple encoding strategies
- **waf_detector.py**: WAF/IDS fingerprinting
- **fuzzer.py**: Adaptive fuzzing and mutation

Features:
- Payload categorization (SQL, XSS, Command, LDAP, SSTI, etc.)
- Multiple encoding strategies (URL, Base64, HTML, Unicode, etc.)
- Context awareness (JSON APIs, HTML attributes, forms)
- WAF detection and evasion
- Grammar-based fuzzing

### 4. AI Anomaly Detection (Phase 3)
**Location:** `scanner/ai_engine/anomaly_detector.py`

Components:
- **ResponseAnalyzer**: Baseline response analysis
- **AnomalyDetector**: Isolation Forest-based detection
- **VulnerabilityConfirmer**: Multi-signal vulnerability confirmation

Reduces false positives through:
- Response entropy analysis
- Statistical deviation detection
- Error pattern matching
- Multi-signal confirmation

### 5. Risk Scoring (Phase 1)
**Location:** `scanner/risk_engine/cvss_engine.py`

Features:
- CVSS v3.1 base score calculation
- Dynamic risk adjustment based on:
  - Exploitability score
  - Reachability
  - Detection confidence
- Vulnerability prioritization

### 6. Reporting (Phase 1)
**Location:** `scanner/reporting/reporters.py`

Formats:
- JSON: Detailed technical report
- HTML: Executive summary with visualizations

### 7. Configuration Management (Phase 1)
**Location:** `scanner/config.py`

Supports:
- JSON/YAML configuration files
- Command-line argument override
- Default configuration fallback

## Scanning Workflow

```
┌─────────────────────────────────────────────┐
│ 1. Crawling & Discovery                     │
│    - Discover URLs, forms, parameters       │
│    - Extract API endpoints                  │
│    - Analyze DOM & JavaScript               │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│ 2. Response Baseline                        │
│    - Collect normal responses               │
│    - Train anomaly detector                 │
│    - Analyze response patterns              │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│ 3. Active Vulnerability Testing             │
│    - For each detector module:              │
│      • Generate payloads (context-aware)    │
│      • Send test requests                   │
│      • Analyze responses                    │
│      • Detect anomalies                     │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│ 4. Confirmation & Correlation               │
│    - Use AI to confirm findings             │
│    - Reduce false positives                 │
│    - Correlate related vulnerabilities      │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│ 5. Risk Scoring                             │
│    - Calculate CVSS scores                  │
│    - Assign severity levels                 │
│    - Prioritize findings                    │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│ 6. Reporting                                │
│    - Generate JSON/HTML reports             │
│    - Create executive summary               │
│    - Export findings                        │
└─────────────────────────────────────────────┘
```

## Vulnerability Types Supported

### Current (Phase 1-2)
- SQL Injection (error-based, boolean, time-based, blind)
- NoSQL Injection
- Reflected XSS
- DOM-based XSS
- Missing Security Headers
- CORS Misconfiguration
- Directory Indexing
- XX E (parsing support)

### Planned (Phase 3-5)
- Stored XSS
- LDAP Injection
- Command Injection
- SSTI (Server-Side Template Injection)
- CSRF Token Validation
- Session Management Issues
- Authentication Bypass
- Privilege Escalation
- Business Logic Flaws
- Open Redirect
- Information Disclosure

## Payload Generation Strategy

### Context Types
1. **Parameter**: URL query string or POST form field
2. **Cookie**: HTTP Cookie header
3. **Header**: Custom HTTP header
4. **Path**: URL path component
5. **JSON**: JSON API payload
6. **Attribute**: HTML attribute context

### Encoding Strategies
1. **Plain**: No encoding
2. **URL Encode**: %XX encoding
3. **Double URL Encode**: Encoded twice  
4. **HTML Encode**: &entity; format
5. **Base64**: Base64 encoding
6. **Unicode**: \uXXXX format
7. **PHP Filter**: php://filter wrapper
8. **Case Variation**: Alternating case

### WAF Evasion
- WAF product detection (ModSecurity, Cloudflare, AWS WAF, etc.)
- Payload mutation based on blocked patterns
- Encoding variation based on detected WAF

## Configuration Example

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
  },
  
  "scanning": {
    "test_all_parameters": true,
    "test_cookies": true,
    "test_headers": true,
    "test_api_endpoints": true
  },
  
  "reporting": {
    "format": "json",
    "output_dir": "./reports"
  }
}
```

## CLI Usage

```bash
# Basic scan
python cli.py https://example.com

# Custom depth and output
python cli.py https://example.com -d 5 -o report.json

# With JavaScript rendering
python cli.py https://example.com --js

# Load configuration
python cli.py --config scan_config.json

# Generate both JSON and HTML reports
python cli.py https://example.com -f both

# Debug logging
python cli.py https://example.com -l DEBUG
```

## Performance Considerations

- **Concurrency**: Default 10 concurrent requests
- **Rate Limiting**: Configurable per-domain limit
- **Timeout**: Configurable (default 30 seconds)
- **Memory**: Optimized for single-machine deployment
- **Scalability**: Designed for horizontal scaling (Phase 5)

## AI/ML Features

### Anomaly Detection
- Isolation Forest algorithm
- Response length & entropy analysis
- Statistical deviation detection
- Multi-signal correlation

### False Positive Reduction
- Baseline response comparison
- Error pattern matching
- Injection-specific signature detection
- Confidence scoring refinement

### Adaptive Testing
- Dynamic payload mutation based on responses
- WAF detection and evasion
- Context-aware payload selection

## Future Phases (3-5)

### Phase 3: Advanced AI & Analysis
- Behavioral analysis of vulnerability chains
- Automatic exploitation attempt simulation
- False positive machine learning model
- Risk prediction using historical data

### Phase 4: Attack Graph Modeling
- Vulnerability relationship mapping
- Attack path enumeration
- Privilege escalation chain detection
- Visualization and export

### Phase 5: Advanced Reporting & DevSecOps
- CI/CD integration
- Automated remediation suggestions
- Policy enforcement
- Distributed scanning
- Real-time collaboration features

## Security & Ethics

CSEH Scanner includes:
- Legal disclaimer in reports
- Scope restriction enforcement
- Domain validation checks
- Rate limiting to prevent DoS
- Safe testing mode toggle

Always obtain written permission before scanning any target.

---

**Version**: 2.0  
**License**: Proprietary Research Tool  
**Last Updated**: 2026-02-26
