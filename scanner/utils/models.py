"""Data models for vulnerability findings and scanner results."""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
from .constants import VulnerabilityType, Severity, Confidence


@dataclass
class Evidence:
    """Evidence supporting a vulnerability finding."""
    
    request_url: str
    request_method: str = "GET"
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: int = 200
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_length: int = 0
    injection_point: Optional[str] = None
    payload_used: Optional[str] = None
    detection_method: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    
    # Core identification
    type: VulnerabilityType
    target_url: str
    title: str
    description: str
    
    # Assessment
    severity: Severity
    confidence: float  # 0.0 - 1.0
    exploitability: float = 0.5  # 0.0 - 1.0
    reachability: float = 1.0  # 0.0 - 1.0
    
    # Evidence & details
    evidence: List[Evidence] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # Metadata
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: float = 0.0
    affected_parameter: Optional[str] = None
    affected_headers: List[str] = field(default_factory=list)
    
    # Discovery details
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    scanner_module: str = ""
    iterations: int = 1  # Number of test attempts
    metadata: Dict[str, Any] = field(default_factory=dict)  # AI/priority info
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        data = asdict(self)
        data['type'] = self.type.value
        data['severity'] = self.severity.value
        data['discovered_at'] = self.discovered_at.isoformat()
        data['evidence'] = [e.to_dict() for e in self.evidence]
        return data


@dataclass
class ScanResult:
    """Complete scan result with metrics."""
    
    target_url: str
    scan_start_time: datetime = field(default_factory=datetime.utcnow)
    scan_end_time: Optional[datetime] = None
    
    # Discovered assets
    discovered_urls: List[str] = field(default_factory=list)
    discovered_forms: List[Dict[str, Any]] = field(default_factory=list)
    discovered_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    
    # Findings
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    
    # Scan metrics
    crawl_depth_reached: int = 0
    total_urls_scanned: int = 0
    total_endpoints_tested: int = 0
    total_payloads_sent: int = 0
    
    # Summary statistics
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'target_url': self.target_url,
            'scan_start_time': self.scan_start_time.isoformat(),
            'scan_end_time': self.scan_end_time.isoformat() if self.scan_end_time else None,
            'discovered_urls': self.discovered_urls,
            'discovered_forms': self.discovered_forms,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'metrics': {
                'crawl_depth': self.crawl_depth_reached,
                'urls_scanned': self.total_urls_scanned,
                'endpoints_tested': self.total_endpoints_tested,
                'payloads_sent': self.total_payloads_sent,
            },
            'summary': {
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
                'info': self.info_count,
            }
        }
