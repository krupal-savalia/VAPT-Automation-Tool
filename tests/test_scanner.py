import sys, os

root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, root)

import asyncio
import pytest
from aiohttp import web

from scanner.core import VulnerabilityScanner

@pytest.mark.asyncio
async def test_scan_basic(aiohttp_client):
    async def handler(request):
        if request.path == "/headers":
            return web.Response(text="ok", headers={})
        if request.path == "/sql":
            return web.Response(text="SQL syntax error")
        if request.path == "/xss":
            return web.Response(text=request.query.get("q", ""))
        return web.Response(text="hello")

    app = web.Application()
    app.router.add_get("/headers", handler)
    app.router.add_get("/sql", handler)
    app.router.add_get("/xss", handler)
    client = await aiohttp_client(app)

    scanner = VulnerabilityScanner(target_url=str(client.make_url("")))
    result = await scanner.scan()

    types = {v.type.value for v in result.vulnerabilities}
    assert "Missing Security Headers" in types
    assert any("SQL" in v.type.value for v in result.vulnerabilities)
    assert any("XSS" in v.type.value for v in result.vulnerabilities)
    # ensure metadata priority exists
    for v in result.vulnerabilities:
        assert isinstance(v.metadata.get('priority_score', 0.0), float)


@pytest.mark.asyncio
async def test_ai_integration(aiohttp_client, monkeypatch):
    async def handler(request):
        return web.Response(text=request.query.get("q", ""))

    app = web.Application()
    app.router.add_get("/test", handler)
    client = await aiohttp_client(app)
    base = str(client.make_url("/"))

    # stub AISelector
    from scanner import ai_selector

    class Dummy:
        def select(self, features):
            return {
                "vulnerability_type": "xss",
                "payload_category": "xss",
                "mutation_strategies": ["case_mutation"],
                "priority_score": 0.9,
            }
    monkeypatch.setattr(ai_selector, 'AISelector', lambda *args, **kwargs: Dummy())

    scanner = VulnerabilityScanner(target_url=base)
    result = await scanner.scan()
    xss = [v for v in result.vulnerabilities if "XSS" in v.type.value]
    assert xss
    for v in xss:
        assert v.metadata.get('priority_score') == 0.9
        assert v.evidence and v.evidence[0].payload_used


# keep existing parameter mutation test unchanged


@pytest.mark.asyncio
async def test_scan_with_custom_xss_payloads(aiohttp_client):
    # server echoes whatever is provided, same handler as above
    async def handler(request):
        if request.path == "/xss":
            return web.Response(text=request.query.get("q", ""))
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/xss", handler)
    client = await aiohttp_client(app)
    base = str(client.make_url(""))
    if not base.endswith("/"):
        base += "/"

    # create scanner with custom payloads only
    custom = ["ONE", "TWO"]
    scanner = VulnerabilityScanner(target_url=base, xss_payloads=custom)
    # bypass crawler by injecting discovered URL directly
    scanner.scan_result.discovered_urls = [base + "xss"]
    await scanner._detect_vulnerabilities()
    xss_findings = [v for v in scanner.scan_result.vulnerabilities if "XSS" in v.type.value]
    assert len(xss_findings) == len(custom)
    assert {v.evidence[0].payload_used for v in xss_findings} == set(custom)


@pytest.mark.asyncio
async def test_param_mutation_used(aiohttp_client):
    # ensure that when the input URL already has a query parameter the scanner
    # injects the payload into that parameter rather than always using ``?q=``
    async def handler(request):
        if request.path == "/xss":
            # return the value of the first query key, regardless of name
            # this simulates a vulnerable endpoint that reflects parameter values
            return web.Response(text=list(request.query.values())[0])
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/xss", handler)
    client = await aiohttp_client(app)
    base = str(client.make_url(""))
    if not base.endswith("/"):
        base += "/"

    scanner = VulnerabilityScanner(target_url=base)
    url_with_param = base + "xss?search=foo"
    scanner.scan_result.discovered_urls = [url_with_param]
    await scanner._detect_vulnerabilities()
    xss_findings = [v for v in scanner.scan_result.vulnerabilities if "XSS" in v.type.value]

    # we should get one finding per default payload and each test URL should
    # still include the original parameter name ‘search’
    assert len(xss_findings) == len(scanner.xss_payloads)
    from urllib.parse import urlparse, parse_qs, unquote_plus

    for v in xss_findings:
        assert "search=" in v.evidence[0].request_url
        parsed = urlparse(v.evidence[0].request_url)
        qs = parse_qs(parsed.query)
        value = qs.get("search", [""])[0]
        assert unquote_plus(value) == v.evidence[0].payload_used
