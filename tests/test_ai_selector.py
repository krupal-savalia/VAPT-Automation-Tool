import pytest
import json

from scanner.ai_selector import AISelector


class DummyResponse:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status

    def raise_for_status(self):
        if not (200 <= self.status_code < 300):
            raise Exception("Bad status")

    def json(self):
        return self._data


def test_selector_fallback(monkeypatch):
    # simulate requests.post raising
    def fake_post(*args, **kwargs):
        raise Exception("network")
    monkeypatch.setattr('scanner.ai_selector.requests.post', fake_post)

    sel = AISelector(api_url="http://dummy")
    out = sel.select({})
    assert out['vulnerability_type'] == 'other_safe'
    assert out['mutation_strategies'] == []
    assert out['priority_score'] == 0.0


def test_selector_happy_path(monkeypatch):
    response_data = {
        "vulnerability_type": "xss",
        "payload_category": "xss",
        "mutation_strategies": ["url_encode"],
        "priority_score": 0.5,
    }
    def fake_post(url, headers, data, timeout):
        return DummyResponse(response_data)
    monkeypatch.setattr('scanner.ai_selector.requests.post', fake_post)

    sel = AISelector(api_url="http://dummy")
    out = sel.select({})
    assert out == response_data
