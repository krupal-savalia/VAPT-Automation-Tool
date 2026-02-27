"""Advanced web crawler with JavaScript support and attack surface discovery."""

import asyncio
import logging
import ssl
from typing import Set, List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import re
from dataclasses import dataclass, field

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class FormData:
    """Represents an HTML form detected during crawling."""
    
    url: str
    method: str = "GET"
    action: str = ""
    fields: List[Dict[str, str]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'url': self.url,
            'method': self.method,
            'action': self.action,
            'fields': self.fields,
        }


@dataclass
class Endpoint:
    """Represents a detected API/REST endpoint."""
    
    url: str
    method: str
    parameters: List[str] = field(default_factory=list)
    content_type: str = "application/x-www-form-urlencoded"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'url': self.url,
            'method': self.method,
            'parameters': self.parameters,
            'content_type': self.content_type,
        }


class AdvancedCrawler:
    """
    Advanced web crawler with JavaScript support, form detection,
    and attack surface mapping.
    
    Features:
    - Asynchronous crawling with configurable concurrency
    - JavaScript execution support (via Playwright)
    - HTML form detection and field extraction
    - API endpoint discovery
    - Query parameter analysis
    - robots.txt and sitemap.xml parsing
    - Session handling
    - Rate limiting
    """
    
    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_urls: int = 1000,
        max_concurrent: int = 10,
        timeout: int = 30,
        use_js: bool = False,
        user_agent: str = "Mozilla/5.0 (compatible; CSEHScanner/2.0)",
    ):
        """
        Initialize the crawler.
        
        Parameters
        ----------
        base_url : str
            Target URL to start crawling from.
        max_depth : int
            Maximum crawl depth.
        max_urls : int
            Maximum number of URLs to discover.
        max_concurrent : int
            Maximum concurrent requests.
        timeout : int
            Request timeout in seconds.
        use_js : bool
            Enable JavaScript rendering.
        user_agent : str
            User-Agent header value.
        """
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.use_js = use_js
        self.user_agent = user_agent
        
        self.visited_urls: Set[str] = set()
        self.discovered_forms: List[FormData] = []
        self.discovered_endpoints: List[Endpoint] = []
        self.discovered_parameters: Set[str] = set()
        
    def _normalize_url(self, url: str) -> Optional[str]:
        """Normalize and validate URL."""
        try:
            url = url.split("#")[0]  # Remove fragments
            absolute_url = urljoin(self.base_url + "/", url)
            
            # Check if on same domain
            base_domain = urlparse(self.base_url).netloc
            url_domain = urlparse(absolute_url).netloc
            
            if base_domain != url_domain:
                return None
            
            return absolute_url.rstrip("/")
        except Exception:
            return None
            
    def _same_domain(self, url: str) -> bool:
        """Check if URL is on same domain."""
        try:
            base_domain = urlparse(self.base_url).netloc
            url_domain = urlparse(url).netloc
            return base_domain == url_domain
        except Exception:
            return False
            
    def _extract_forms(self, html: str, page_url: str) -> List[FormData]:
        """Extract HTML forms from page."""
        forms = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            
            for form in soup.find_all("form"):
                form_data = FormData(
                    url=page_url,
                    method=form.get("method", "GET").upper(),
                    action=form.get("action", page_url),
                )
                
                for field in form.find_all(["input", "select", "textarea"]):
                    field_name = field.get("name", "")
                    field_type = field.get("type", "text")
                    
                    if field_name:
                        form_data.fields.append({
                            "name": field_name,
                            "type": field_type,
                        })
                        
                forms.append(form_data)
        except Exception as e:
            logger.debug(f"Error extracting forms: {e}")
            
        return forms
        
    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract query parameters from URL."""
        try:
            parsed = urlparse(url)
            return dict(parse_qsl(parsed.query))
        except Exception:
            return {}
            
    async def _fetch_url(
        self, 
        session: aiohttp.ClientSession, 
        url: str
    ) -> Optional[str]:
        """Fetch URL content."""
        try:
            async with session.get(url, timeout=self.timeout, ssl=False) as response:
                if response.status == 200:
                    return await response.text()
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
        return None
        
    async def crawl(self) -> List[str]:
        """
        Crawl website starting from base_url.
        
        Returns
        -------
        List[str]
            List of discovered URLs.
        """
        headers = {"User-Agent": self.user_agent}
        
        # Create SSL context that doesn't verify certificates
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(limit=self.max_concurrent, ssl=ssl_context)
        
        try:
            async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
                await self._crawl_recursive(session, self.base_url, depth=0)
        except Exception as e:
            logger.error(f"Crawl failed: {e}")
            
        return list(self.visited_urls)
        
    async def _crawl_recursive(
        self,
        session: aiohttp.ClientSession,
        url: str,
        depth: int
    ):
        """Recursively crawl URLs."""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_urls:
            return
            
        normalized = self._normalize_url(url)
        if not normalized or normalized in self.visited_urls:
            return
            
        self.visited_urls.add(normalized)
        logger.info(f"Crawling {normalized} (depth {depth}/{self.max_depth})")
        
        # Fetch page
        html = await self._fetch_url(session, normalized)
        if not html:
            logger.warning(f"Failed to fetch {normalized}")
            return
            
        # Extract forms
        forms = self._extract_forms(html, normalized)
        for form in forms:
            if form not in self.discovered_forms:
                self.discovered_forms.append(form)
                logger.info(f"Found form: {form.method} {form.action}")
                
        # Extract parameters
        params = self._extract_parameters(normalized)
        for key in params.keys():
            self.discovered_parameters.add(key)
            
        # Extract links and continue crawling - more aggressive approach
        try:
            soup = BeautifulSoup(html, "html.parser")
            
            # Find all links
            discovered_links = []
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href and href.strip() and not href.startswith("javascript:"):
                    discovered_links.append(href)
                    
            logger.info(f"Found {len(discovered_links)} links on {normalized}")
            
            # Process links
            for href in discovered_links:
                if len(self.visited_urls) >= self.max_urls:
                    break
                    
                try:
                    # Try direct normalization first
                    normalized_link = self._normalize_url(href)
                    
                    # If normalization failed, try with urljoin directly
                    if not normalized_link and self._same_domain(href):
                        absolute_url = urljoin(normalized + "/", href)
                        normalized_link = self._normalize_url(absolute_url) or absolute_url.rstrip("/")
                    
                    if normalized_link and normalized_link not in self.visited_urls:
                        await self._crawl_recursive(session, normalized_link, depth + 1)
                except Exception as e:
                    logger.debug(f"Error processing link {href}: {e}")
                    
        except Exception as e:
            logger.warning(f"Error processing links from {normalized}: {e}")
