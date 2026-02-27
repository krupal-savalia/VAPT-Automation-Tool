import pytest

from scanner.payload_database import get_payloads, PAYLOAD_DB


def test_get_known_category():
    assert "xss" in PAYLOAD_DB
    xss_list = get_payloads("xss")
    assert isinstance(xss_list, list)
    # modifications to returned list should not affect original
    xss_list.append("foo")
    assert "foo" not in PAYLOAD_DB["xss"]


def test_get_unknown_category():
    assert get_payloads("nonexistent") == []
