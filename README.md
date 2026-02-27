# CSEH Scanner v2.0

## Overview  
The CSEH Scanner v2.0 is an enterprise-grade scanning tool designed to assess system vulnerabilities and compliance with security standards. Built with scalability and reliability in mind, it provides comprehensive insights into your infrastructure's security posture.

## Architecture  
The system is designed using a microservices architecture that allows for efficient processing and scalability. Each component communicates through RESTful APIs, ensuring seamless interaction and integration. 

### Components:
- **Scanner Module:** Performs the actual scanning and data collection.
- **Data Processor:** Analyses the collected data and generates reports.
- **User Interface:** A web-based portal for users to interact with the scanner and view results.

## Features

- Asynchronous crawling and scanning with `aiohttp` (JavaScript support via Selenium optional).
- Plug‑in AI analyzer using `scikit-learn`.
- Configurable severity thresholds.
- JSON/CSV reporting with summary.
- CLI interface with `argparse`.
- Reflected XSS detection now exercises a list of common payloads (configurable via `VulnerabilityScanner`).
- Built‑in tests leveraging `pytest` and `aiohttp`.

## Installation  
To install the CSEH Scanner, follow these steps:
1. Clone the repository:
   ```bash
   git clone https://github.com/krupal-savalia/VAPT-Automation-Tool.git
   cd VAPT-Automation-Tool
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Configure the scanner:
   Update the configuration file as per your infrastructure requirements.
4. Start the application:
   ```bash
   npm start
   ```

## Usage

```bash
# normal (fast) crawler
python main.py https://example.com --depth 3 -f csv -o output.csv

# enable JS rendering when scanning single-page apps
python main.py https://example.com --depth 3 -j -f csv -o output.csv
```

> **Warning**: Only scan targets you have permission to test.

## Development

Run tests:

```bash
pytest
```

Configure logging, extend scanners, and add new AI models by editing the modules in
`cseh/`.

### Extending XSS Checks

The scanner class accepts an optional `xss_payloads` list; you can provide
additional or more aggressive vectors when creating
``python
from cseh.scanner import VulnerabilityScanner
scanner = VulnerabilityScanner(xss_payloads=["<svg/onload=alert(1)>", ...])
```
This makes it easier to verify vulnerabilities with multiple proof-of-concept
strings.

The command‑line tool also exposes a `--xss-payload` argument which can be
specified multiple times.  Extra payloads given on the command line are
appended to the built‑in set before scanning:

```bash
python main.py http://example.com --xss-payload "<img src=x onerror=alert(1)>" \
    --xss-payload "'><script>alert(1)</script>" 
```
