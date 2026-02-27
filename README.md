# AI-Enhanced Web Vulnerability Scanner

This project scans a target website for basic security issues, runs anomaly detection on
results using a simple machine learning model, assigns severity levels, and generates a report.

## Features

- Asynchronous crawling and scanning with `aiohttp` (JavaScript support via Selenium optional).
- Plug‑in AI analyzer using `scikit-learn`.
- Configurable severity thresholds.
- JSON/CSV reporting with summary.
- CLI interface with `argparse`.
- Reflected XSS detection now exercises a list of common payloads (configurable via `VulnerabilityScanner`).
- Built‑in tests leveraging `pytest` and `aiohttp`.

## Installation

```bash
python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt
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
