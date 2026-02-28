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
            # echo back the first query parameter value, regardless of its name
            return web.Response(text=next(iter(request.query.values()), ""))

    # set up aiohttp application and attach single handler for all
    app = web.Application()
    app.router.add_get("/headers", handler)
    app.router.add_get("/sql", handler)
    app.router.add_get("/xss", handler)
    client = await aiohttp_client(app)

    scanner = VulnerabilityScanner(target_url=str(client.make_url("")))
    # bypass crawling by providing explicit URLs to evaluate
    base = str(client.make_url(""))
    if not base.endswith("/"):
        base += "/"
    scanner.scan_result.discovered_urls = [
        base + "headers",
        base + "sql?foo=1",
        base + "xss?foo=1",
    ]
    # run detection and risk scoring manually (scan() orchestrates these steps)
    await scanner._detect_vulnerabilities()
    scanner.scan_result.vulnerabilities = scanner.risk_engine.assign_severity(
        scanner.scan_result.vulnerabilities
    )
    scanner.scan_result.vulnerabilities = scanner.risk_engine.prioritize(
        scanner.scan_result.vulnerabilities
    )
    scanner._update_summary()
    # ensure baseline responses were recorded correctly (necessary for dedup)
    for clean, resp in scanner._baseline_responses.items():
        assert resp, f"Baseline for {clean} should not be empty"
        assert 'url' in resp, "Baseline entry missing url key"
    result = scanner.scan_result

    types = {v.type.value for v in result.vulnerabilities}
    assert "Missing Security Headers" in types
    assert any("SQL" in v.type.value for v in result.vulnerabilities)
    assert any("XSS" in v.type.value for v in result.vulnerabilities)
    # ensure we report the headers issue once per unique endpoint (three URLs were tested)
    headers_findings = [v for v in result.vulnerabilities if "Security Headers" in v.type.value]
    assert len(headers_findings) == 3
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
    # ensure the scanner actually tests the /test endpoint with a parameter so
    # the XSS detector has something to work with (the crawler doesn't add
    # query strings automatically).  bypass normal crawl since we're setting
    # discovered URLs directly and later running _detect_vulnerabilities().
    scanner.scan_result.discovered_urls = [base + "test?q=hello"]
    # run detection and scoring manually, similar to earlier helper test
    await scanner._detect_vulnerabilities()
    scanner.scan_result.vulnerabilities = scanner.risk_engine.assign_severity(
        scanner.scan_result.vulnerabilities
    )
    scanner.scan_result.vulnerabilities = scanner.risk_engine.prioritize(
        scanner.scan_result.vulnerabilities
    )
    scanner._update_summary()
    result = scanner.scan_result
    xss = [v for v in result.vulnerabilities if "XSS" in v.type.value]
    # at least one finding should exist and priority score set by our dummy
    assert xss, "AI integration should result in at least one XSS finding"
    for v in xss:
        # priority score should be non-zero (dummy selector provided a value)
        assert v.metadata.get('priority_score', 0) > 0
        # payload may appear in evidence
        assert v.evidence and v.evidence[0].payload_used


# keep existing parameter mutation test unchanged


@pytest.mark.asyncio
async def test_security_header_deduplication(aiohttp_client):
    # simulate a target that always returns no security headers, even when
    # queried with different parameters.  the scanner may exercise multiple
    # payloads/params but we should only see one "Missing Security Headers"
    async def handler(request):
        return web.Response(text="ok", headers={})

    app = web.Application()
    app.router.add_get("/test", handler)
    client = await aiohttp_client(app)
    base = str(client.make_url(""))

    scanner = VulnerabilityScanner(target_url=base)
    # manually inject two discovered URLs with different query strings
    if not base.endswith("/"):
        base += "/"
    scanner.scan_result.discovered_urls = [
        base + "test?foo=1",
        base + "test?bar=2",
    ]
    await scanner._detect_vulnerabilities()

    headers = [v for v in scanner.scan_result.vulnerabilities if "Security Headers" in v.type.value]
    assert len(headers) == 1, "Should only report missing security headers once per base endpoint"


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

    # create scanner with custom payloads (include at least one valid XSS)
    custom = ["<script>alert(1)</script>", "OTHER"]
    scanner = VulnerabilityScanner(target_url=base, xss_payloads=custom)
    # bypass crawler by injecting discovered URL directly (include a query
    # parameter so that the scanner knows which field to inject payloads into)
    scanner.scan_result.discovered_urls = [base + "xss?q=1"]
    await scanner._detect_vulnerabilities()
    xss_findings = [v for v in scanner.scan_result.vulnerabilities if "XSS" in v.type.value]
    # deduplication may collapse multiple payloads into a single finding, but
    # at least one should exist and the evidence should contain one of our
    # custom payloads
    assert xss_findings, "Expected at least one XSS finding"
    seen_payloads = {v.evidence[0].payload_used for v in xss_findings if v.evidence}
    assert seen_payloads & set(custom), "Payloads from custom list should be used"


@pytest.mark.asyncio
async def test_param_mutation_used(aiohttp_client):
    # ensure that when the input URL already has a query parameter the scanner
    # injects the payload into that parameter rather than always using ``?q=``
    async def handler(request):
        if request.path == "/xss":
            # return the value of the first query key, regardless of name
            # this simulates a vulnerable endpoint that reflects parameter values
            if request.query:
                return web.Response(text=list(request.query.values())[0])
            else:
                return web.Response(text="")
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

    # at least one finding should be present and the request url should still
    # contain the original parameter name ‘search’
    assert xss_findings, "Expected at least one XSS finding"
    from urllib.parse import urlparse, parse_qs, unquote_plus
    for v in xss_findings:
        assert "search=" in v.evidence[0].request_url
        parsed = urlparse(v.evidence[0].request_url)
        qs = parse_qs(parsed.query)
        value = qs.get("search", [""])[0]
        assert unquote_plus(value) == v.evidence[0].payload_used
