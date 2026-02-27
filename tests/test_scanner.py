import sys, os

root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, root)

import asyncio
import pytest
from aiohttp import web

from cseh.scanner import VulnerabilityScanner

@pytest.mark.asyncio
async def test_scan(aiohttp_client):
    async def handler(request):
        # simple responses depending on path
        if request.path == "/headers":
            return web.Response(text="ok", headers={})
        if request.path == "/sql":
            return web.Response(text="SQL syntax error")
        if request.path == "/xss":
            # echo back the ``q`` query parameter so that every payload is
            # reflected and can be detected by the scanner.
            return web.Response(text=request.query.get("q", ""))
        return web.Response(text="hello")

    app = web.Application()
    app.router.add_get("/headers", handler)
    app.router.add_get("/sql", handler)
    app.router.add_get("/xss", handler)
    client = await aiohttp_client(app)

    scanner = VulnerabilityScanner()
    base = str(client.make_url(""))
    # make sure there is a trailing slash so concatenation works
    if not base.endswith("/"):
        base += "/"
    urls = [base + "headers", base + "sql", base + "xss"]
    results = await scanner.scan(urls)
    # should produce at least one finding for each type
    types = {r["type"] for r in results}
    assert "Missing Security Headers" in types
    assert "Potential SQL Injection" in types
    assert "Reflected XSS" in types

    # because the /xss handler echoes whatever is supplied, we expect one
    # finding per configured payload (default 3).  The scanner should include
    # a ``payload`` key in the results to make confirmation easier.
    xss_findings = [r for r in results if r["type"] == "Reflected XSS"]
    assert len(xss_findings) == len(scanner.xss_payloads)
    for f in xss_findings:
        assert "payload" in f
        assert f["payload"] in scanner.xss_payloads


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
    scanner = VulnerabilityScanner(xss_payloads=custom)
    results = await scanner.scan([base + "xss"])
    xss_findings = [r for r in results if r["type"] == "Reflected XSS"]
    assert len(xss_findings) == len(custom)
    assert {f["payload"] for f in xss_findings} == set(custom)


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

    scanner = VulnerabilityScanner()
    url_with_param = base + "xss?search=foo"
    results = await scanner.scan([url_with_param])
    xss_findings = [r for r in results if r["type"] == "Reflected XSS"]

    # we should get one finding per default payload and each test URL should
    # still include the original parameter name ‘search’
    assert len(xss_findings) == len(scanner.xss_payloads)
    from urllib.parse import urlparse, parse_qs, unquote_plus

    for f in xss_findings:
        assert "search=" in f["url"]
        # decode the query value and ensure it matches the payload we recorded
        parsed = urlparse(f["url"])
        qs = parse_qs(parsed.query)
        # there should be exactly one value for search
        value = qs.get("search", [""])[0]
        # parsing may URL‑encode characters
        assert unquote_plus(value) == f["payload"]
