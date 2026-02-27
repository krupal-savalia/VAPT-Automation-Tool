"""Demonstration script showing how to run the enhanced scanner.

This is not part of the core library; it's intended as a simple
`python example_usage.py` invocation to illustrate the new AI-assisted
workflow and payload database.

Before running you should set `AI_API_URL` and optionally `AI_API_KEY` so
the AI selector can contact a model.  The environment variables are read by
`scanner.ai_selector.AISelector`.

Example:

    set AI_API_URL=https://my.ai.endpoint/v1/predict
    set AI_API_KEY=secret123
    python example_usage.py https://example.com

The script will perform a quick scan and print a summary of any
vulnerabilities along with priority scores.  It uses the same
`VulnerabilityScanner` class under the hood.
"""

import argparse
import asyncio
from pathlib import Path

from scanner import VulnerabilityScanner
from scanner.reporting.reporters import JSONReporter


def main():
    parser = argparse.ArgumentParser(description="Example run of the AI-assisted scanner")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("-o", "--output", default="example_report.json",
                        help="JSON output file")
    args = parser.parse_args()

    scanner = VulnerabilityScanner(target_url=args.target, log_level="DEBUG")
    result = asyncio.run(scanner.scan())

    print(f"Scan completed: {len(result.vulnerabilities)} issues found")
    for v in result.vulnerabilities:
        print(f" - {v.title} ({v.severity.value}) priority={v.metadata.get('priority_score')}")
    JSONReporter().generate(result, args.output)
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
