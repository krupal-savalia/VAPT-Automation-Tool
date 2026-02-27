"""HTTP client utilities and response analysis."""

import asyncio
from typing import Optional, Dict, Any
from urllib.parse import urlencode
import aiohttp
import logging

logger = logging.getLogger(__name__)


class HTTPClient:
    """Async HTTP client with extended functionality."""
    
    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        backoff_factor: float = 0.3,
        user_agent: str = "Mozilla/5.0 (compatible; CSEHScanner/2.0)",
    ):
        """Initialize HTTP client."""
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.user_agent = user_agent
        
    async def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Make HTTP request with retry logic.
        
        Parameters
        ----------
        url : str
            Target URL
        method : str
            HTTP method (GET, POST, etc.)
        headers : Dict[str, str], optional
            Request headers
        data : Dict[str, Any], optional
            Form data for POST requests
        params : Dict[str, str], optional
            Query parameters for GET requests
        cookies : Dict[str, str], optional
            Cookies to include
        
        Returns
        -------
        Dict[str, Any]
            Response data including status, headers, and body.
        """
        if headers is None:
            headers = {}
            
        if 'User-Agent' not in headers:
            headers['User-Agent'] = self.user_agent
        
        # Handle form data encoding
        request_kwargs = dict(kwargs)
        
        if method.upper() == "POST" and data:
            # Encode form data
            if isinstance(data, dict):
                request_kwargs['data'] = data
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
            else:
                request_kwargs['data'] = data
        
        if method.upper() == "GET" and params:
            request_kwargs['params'] = params
            
        attempt = 0
        last_error = None
        
        while attempt < self.max_retries:
            try:
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.request(
                        method, 
                        url,
                        headers=headers,
                        cookies=cookies,
                        **request_kwargs
                    ) as response:
                        body = await response.text()
                        
                        return {
                            'status': response.status,
                            'headers': dict(response.headers),
                            'body': body,
                            'url': str(response.url),
                        }
            except asyncio.TimeoutError:
                attempt += 1
                last_error = "Timeout"
                if attempt < self.max_retries:
                    await asyncio.sleep(self.backoff_factor * (2 ** attempt))
            except aiohttp.ClientError as e:
                attempt += 1
                last_error = str(e)
                if attempt < self.max_retries:
                    await asyncio.sleep(self.backoff_factor * (2 ** attempt))
            except Exception as e:
                logger.error(f"Request failed for {url}: {e}")
                return {
                    'status': 0,
                    'headers': {},
                    'body': '',
                    'error': str(e),
                }
                
        logger.warning(f"Max retries exceeded for {url}: {last_error}")
        return {
            'status': 0,
            'headers': {},
            'body': '',
            'error': last_error,
        }
