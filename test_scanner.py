"""Quick test to verify scanner functionality."""

import asyncio
import sys
sys.path.insert(0, '.')

from scanner.core import VulnerabilityScanner


async def test_scan():
    """Quick test scan on a known vulnerable site."""
    scanner = VulnerabilityScanner(
        target_url="http://testphp.vulnweb.com/",
        max_depth=1,
        max_urls=10,
        log_level="DEBUG"
    )
    
    print("Starting test scan...")
    result = await scanner.scan()
    
    print(f"\n=== SCAN RESULTS ===")
    print(f"Total vulnerabilities found: {len(result.vulnerabilities)}")
    print(f"Critical: {result.critical_count}")
    print(f"High: {result.high_count}")
    print(f"Medium: {result.medium_count}")
    print(f"Low: {result.low_count}")
    
    for vuln in result.vulnerabilities:
        print(f"\n- {vuln.title}")
        print(f"  URL: {vuln.target_url}")
        print(f"  Severity: {vuln.severity.value}")
        print(f"  Confidence: {vuln.confidence}")
        print(f"  Detection Confidence: {vuln.detection_confidence}")
    
    return result


if __name__ == "__main__":
    asyncio.run(test_scan())
