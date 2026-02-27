import sys, os

root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, root)

import pytest
from aiohttp import web

from cseh.crawler import WebCrawler

@pytest.mark.asyncio
async def test_crawl(aiohttp_client):
    # create two pages linking to each other
    async def page1(request):
        return web.Response(text='<a href="/page2">link</a>')

    async def page2(request):
        return web.Response(text='<a href="/page1">back</a>')

    app = web.Application()
    app.router.add_get("/", page1)
    app.router.add_get("/page2", page2)
    client = await aiohttp_client(app)

    base = str(client.make_url(""))
    crawler = WebCrawler(base_url=base, max_depth=2)
    urls = await crawler.crawl()
    # should contain both pages
    assert any("page2" in u for u in urls)
    assert any(u.rstrip("/") == base.rstrip("/") for u in urls)


@pytest.mark.asyncio
async def test_crawl_js_mode(monkeypatch):
    # simulate selenium browser collecting links
    fake_urls = {"https://example.com/", "https://example.com/foo"}
    expected = {u.rstrip('/') for u in fake_urls}

    class DummyDriver:
        def __init__(self, *args, **kwargs):
            pass
        def get(self, url):
            pass
        def find_elements(self, by, value):
            class Link:
                def __init__(self, href):
                    self.href = href
                def get_attribute(self, name):
                    return self.href
            return [Link(u) for u in fake_urls]
        def quit(self):
            pass

    # insert a fake `selenium` package into sys.modules so the crawler's
    # `from selenium import webdriver` import resolves to our dummy driver.
    import types

    fake_selenium = types.ModuleType("selenium")

    # create selenium.webdriver module and nested submodules used by crawler
    webdriver_mod = types.ModuleType("selenium.webdriver")
    # minimal 'common.by' to satisfy imports
    common_mod = types.ModuleType("selenium.webdriver.common")
    by_mod = types.ModuleType("selenium.webdriver.common.by")
    # provide a dummy By constant
    setattr(by_mod, "By", types.SimpleNamespace(TAG_NAME="tag name"))
    common_mod.by = by_mod

    # chrome service module with Service placeholder
    chrome_mod = types.ModuleType("selenium.webdriver.chrome")
    chrome_service_mod = types.ModuleType("selenium.webdriver.chrome.service")
    class Service:
        def __init__(self, *args, **kwargs):
            pass
    chrome_service_mod.Service = Service

    # expose Chrome as our DummyDriver class
    webdriver_mod.Chrome = DummyDriver
    # minimal ChromeOptions implementation
    class ChromeOptions:
        def __init__(self):
            self._args = []
        def add_argument(self, a):
            self._args.append(a)
    webdriver_mod.ChromeOptions = ChromeOptions
    webdriver_mod.common = common_mod
    webdriver_mod.chrome = chrome_mod

    # insert modules into sys.modules so `from selenium.webdriver.chrome.service import Service` works
    monkeypatch.setitem(sys.modules, "selenium", fake_selenium)
    monkeypatch.setitem(sys.modules, "selenium.webdriver", webdriver_mod)
    monkeypatch.setitem(sys.modules, "selenium.webdriver.common", common_mod)
    monkeypatch.setitem(sys.modules, "selenium.webdriver.common.by", by_mod)
    monkeypatch.setitem(sys.modules, "selenium.webdriver.chrome", chrome_mod)
    monkeypatch.setitem(sys.modules, "selenium.webdriver.chrome.service", chrome_service_mod)

    # minimal webdriver-manager fake
    wm_mod = types.ModuleType("webdriver_manager.chrome")
    class ChromeDriverManager:
        def install(self):
            return "chromedriver"
    wm_mod.ChromeDriverManager = ChromeDriverManager
    monkeypatch.setitem(sys.modules, "webdriver_manager.chrome", wm_mod)

    crawler = WebCrawler(base_url="https://example.com", use_selenium=True)
    # since our dummy driver returns fake_urls
    result = await crawler.crawl()
    assert set(result) >= expected
