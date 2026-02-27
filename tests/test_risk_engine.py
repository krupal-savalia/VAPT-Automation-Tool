import sys, os

root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, root)

import pytest

from cseh.risk_engine import RiskEngine


def test_assign_severity_default():
    engine = RiskEngine()
    results = [{"confidence": 0.9}, {"confidence": 0.7}, {"confidence": 0.5}]
    out = engine.assign_severity(results)
    assert out[0]["severity"] == "High"
    assert out[1]["severity"] == "Medium"
    assert out[2]["severity"] == "Low"


def test_assign_severity_custom():
    engine = RiskEngine(high_threshold=0.95, medium_threshold=0.5)
    results = [{"confidence": 0.9}, {"confidence": 0.6}]
    out = engine.assign_severity(results)
    assert out[0]["severity"] == "Medium"
    assert out[1]["severity"] == "Medium"