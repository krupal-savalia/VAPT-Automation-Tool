import sys, os

root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, root)

import os
import json
import csv

import pytest

from cseh.report_generator import ReportGenerator


def sample_results():
    return [
        {"url": "http://a", "severity": "High"},
        {"url": "http://b", "severity": "Low"},
    ]


def test_generate_json(tmp_path):
    rg = ReportGenerator()
    results = sample_results()
    path = tmp_path / "out.json"
    written = rg.generate_report(results, filename=str(path), fmt="json")
    assert written == str(path)
    data = json.loads(path.read_text())
    assert data == results


def test_generate_csv(tmp_path):
    rg = ReportGenerator()
    results = sample_results()
    path = tmp_path / "out.csv"
    written = rg.generate_report(results, filename=str(path), fmt="csv")
    assert written == str(path)
    # verify CSV header
    with open(path) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert rows[0]["url"] == "http://a"


def test_generate_csv_includes_extra_keys(tmp_path):
    # results may contain arbitrary keys such as ``payload`` added by the
    # XSS scanner.  The CSV generator should include them in the header.
    rg = ReportGenerator()
    results = [
        {"url": "http://a", "severity": "High", "payload": "<x>"},
    ]
    path = tmp_path / "out.csv"
    rg.generate_report(results, filename=str(path), fmt="csv")
    with open(path) as f:
        reader = csv.DictReader(f)
        assert "payload" in reader.fieldnames
        rows = list(reader)
    assert rows[0]["payload"] == "<x>"


def test_summary():
    rg = ReportGenerator()
    summary = rg.summary(sample_results())
    assert summary["total"] == 2
    assert summary["high"] == 1
    assert summary["low"] == 1


def make_vuln(type_str, url):
    from scanner.utils.models import Vulnerability, Severity, Evidence
    from scanner.utils.constants import VulnerabilityType
    # allow passing either enum or raw value string
    if isinstance(type_str, VulnerabilityType):
        type_enum = type_str
    else:
        type_enum = VulnerabilityType(type_str)
    # simple vuln with minimal fields
    return Vulnerability(
        type=type_enum,
        target_url=url,
        title=type_enum.value,
        description="desc",
        severity=Severity.MEDIUM,
        confidence=0.5,
        evidence=[Evidence(request_url=url)]
    )

@pytest.mark.asyncio
async def test_html_report_groups_duplicates(tmp_path):
    # create a fake ScanResult with duplicate vulnerabilities
    from scanner.utils.models import ScanResult
    from scanner.reporting.reporters import HTMLReporter

    scan = ScanResult(target_url="http://example")
    # two identical vulnerabilities should be grouped into one entry with count
    scan.vulnerabilities.append(make_vuln("Reflected XSS", "http://example/page"))
    scan.vulnerabilities.append(make_vuln("Reflected XSS", "http://example/page"))  # duplicate
    scan.scan_start_time = scan.scan_start_time  # ensure attribute exists

    reporter = HTMLReporter()
    html = reporter._build_vulnerabilities_html(scan)
    # should mention that there are 2 similar findings grouped
    assert "2 similar" in html or "occurrences" in html

@pytest.mark.asyncio
async def test_json_report_includes_occurrences(tmp_path):
    from scanner.utils.models import ScanResult
    from scanner.reporting.reporters import JSONReporter

    scan = ScanResult(target_url="http://example")
    # use a valid VulnerabilityType value; 'XSS' alone isn't defined
    scan.vulnerabilities.append(make_vuln("Reflected XSS", "http://example/page"))
    scan.vulnerabilities.append(make_vuln("Reflected XSS", "http://example/page"))

    reporter = JSONReporter()
    path = tmp_path / "out.json"
    reporter.generate(scan, str(path))
    data = json.loads(path.read_text())
    # grouped findings should have an occurrence count of 2
    grouped = data["scan"].get("grouped_findings", [])
    assert grouped and grouped[0].get("occurrences") == 2
