import sys, os

# ensure parent directory of package root is on path so `import cseh` works
root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, root)

import numpy as np
from cseh.ai_analyzer import AIAnalyzer


def test_analyze_empty():
    ai = AIAnalyzer()
    assert ai.analyze([]) == []


def test_analyze_basic():
    ai = AIAnalyzer()
    # two identical points should not be anomalies
    results = [
        {"response_time": 1, "response_length": 100, "confidence": 0.5},
        {"response_time": 1, "response_length": 100, "confidence": 0.5},
    ]
    out = ai.analyze(results)
    assert all(r.get("ai_anomaly") == "No" for r in out)


def test_save_load(tmp_path):
    ai = AIAnalyzer()
    ai.save_model(str(tmp_path / "model.joblib"))
    ai2 = AIAnalyzer()
    ai2.load_model(str(tmp_path / "model.joblib"))
    assert ai2.model is not None
