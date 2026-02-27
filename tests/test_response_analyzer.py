import pytest

from scanner.response_analyzer import ResponseAnalyzer


def make_resp(body="", status=200, elapsed=0.0):
    return {"body": body, "status": status, "elapsed": elapsed}


def test_reflection_detected():
    analyzer = ResponseAnalyzer()
    features = analyzer.analyze(make_resp("hello <script>alert(1)</script>"), None, "<script>alert(1)</script>")
    assert features["reflection"]
    assert features["encoding"] == "html"
    assert features["context"] in ("body", "javascript")


def test_status_change_and_error_pattern():
    baseline = make_resp("normal", status=200, elapsed=0.1)
    resp = make_resp("sql syntax error occurred", status=500, elapsed=0.2)
    features = ResponseAnalyzer().analyze(resp, baseline, "' OR '1'='1")
    assert features["status_change"]
    assert "sql syntax" in features["error_patterns"]
    assert features["content_length_delta"] == len(resp["body"]) - len(baseline["body"]) 
    assert features["response_time_delta"] == pytest.approx(0.1)
