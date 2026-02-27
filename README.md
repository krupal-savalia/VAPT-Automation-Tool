# AI-Enhanced Web Vulnerability Scanner

This project scans a target website for basic security issues, runs anomaly detection on
results using a simple machine learning model, assigns severity levels, and generates a report.

## Features

- Asynchronous crawling and scanning with `aiohttp` (JavaScript support via Selenium optional).
- Hybrid payload engine combining curated safe payloads with AI‑assisted
  selection and mutation.
- Response analysis module that extracts features (reflection, errors,
  timing deltas) for use by an external model.
- `payload_database` holding categorised, non-destructive probes
  (XSS, SQLi, directory traversal, open redirect, etc.).
- `ai_selector` module to call a remote model which returns **strict JSON**
  guidance on payload category, vulnerability type, mutation strategies and
  priority score.
- `mutation_engine` that can transform payloads (URL‑encode, case changes,
  whitespace injection, etc.) based on AI recommendations.
- Modular detectors for existing checks; new AI suggestion info is attached
  to each finding and can influence priority scoring.
- Enhanced reporting with detailed payload/evidence/priority information.
- Example usage script demonstrating the advanced workflow.
- Unit tests covering new components, written with `pytest`.

Next sections remain unchanged but may have additional notes below.

## Installation

```bash
python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

## Usage

You can run the CLI (`cli.py`) as before.  To take advantage of the
AI-assistance, set the `AI_API_URL` environment variable to point at your
inference service and optionally `AI_API_KEY` for authentication.  The
service **must** return JSON only, with the following fields:

```json
{
  "vulnerability_type": "xss",
  "payload_category": "xss",
  "mutation_strategies": ["url_encode","case_mutation"],
  "priority_score": 0.65
}
```

Example CLI invocation:

```bash
set AI_API_URL=https://model.company.local/predict
set AI_API_KEY=secret123
python cli.py https://example.com --depth 2 -f both -o reports/report
```

You can also run the demonstration script:

```bash
python example_usage.py https://example.com
```

> **Warning**: Only scan targets you have permission to test.  AI payloads
> are designed to be safe/probing but may still trigger alarms.

## Development

Run tests:

```bash
pytest
```

Configure logging, extend scanners, and add new AI models by editing the modules in
`cseh/`.

### Extending XSS Checks

Under the new architecture XSS payloads are managed via the
`payload_database` module and the scanner exposes a convenient
`xss_payloads` parameter on construction.  You can supply your own list
or modify the database directly:

```python
from scanner import VulnerabilityScanner
from scanner.payload_database import get_payloads

custom = ["<svg/onload=alert(1)>"]
scanner = VulnerabilityScanner(target_url="https://foo", xss_payloads=custom)
``` 

The built‑in command‑line tool still supports `--xss-payload` to append
extra payloads on the fly; they are combined with the default safe set.

For more comprehensive control you may import `PAYLOAD_DB` and alter
entries prior to scanning:

```python
from scanner.payload_database import PAYLOAD_DB
PAYLOAD_DB['xss'].append("<img src=x onerror=alert('pwn')>")
```