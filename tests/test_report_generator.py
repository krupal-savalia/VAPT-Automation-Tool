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
