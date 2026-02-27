"""Command-line interface for the CSEH vulnerability scanner."""

import argparse
import logging
import asyncio
import json
from pathlib import Path
from typing import Optional

from scanner.core import VulnerabilityScanner
from scanner.reporting.reporters import JSONReporter, HTMLReporter
from scanner.config import ScannerConfig
from scanner.utils.logging_util import setup_logging


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="CSEH: Advanced Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with default settings
  python cli.py https://example.com
  
  # Deep crawl with JavaScript rendering
  python cli.py https://example.com --depth 5 --js
  
  # Custom output and logging
  python cli.py https://example.com -o report.json -l DEBUG
  
  # Load configuration from file
  python cli.py --config scan_config.json
        """
    )
    
    # Target
    parser.add_argument(
        "target",
        nargs="?",
        help="Target URL to scan (can be overridden with --config)"
    )
    
    # Scanning options
    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=3,
        help="Maximum crawl depth (default: 3)"
    )
    parser.add_argument(
        "-u", "--max-urls",
        type=int,
        default=1000,
        help="Maximum URLs to discover (default: 1000)"
    )
    parser.add_argument(
        "--js",
        action="store_true",
        help="Enable JavaScript rendering with headless browser"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)"
    )
    
    # Output options
    parser.add_argument(
        "-o", "--output",
        default="report.json",
        help="Output report file (default: report.json)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["json", "html", "both"],
        default="html",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--report-dir",
        default="./reports",
        help="Report output directory (default: ./reports)"
    )
    
    # Logging
    parser.add_argument(
        "-l", "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)"
    )
    
    # Configuration
    parser.add_argument(
        "--config",
        help="Load configuration from file (JSON or YAML)"
    )
    parser.add_argument(
        "--save-config",
        help="Save current configuration to file"
    )
    
    return parser


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Load configuration if provided
    config = ScannerConfig()
    if args.config:
        config.load(args.config)
    
    # Override with CLI arguments
    if args.target:
        config.set('target_url', args.target)
    config.set('max_depth', args.depth)
    config.set('max_urls', args.max_urls)
    config.set('use_javascript', args.js)
    config.set('timeout', args.timeout)
    config.set('log_level', args.log_level)
    
    # Save config if requested
    if args.save_config:
        config.save(args.save_config)
        print(f"Configuration saved to {args.save_config}")
    
    # Validate target
    target_url = config.get('target_url')
    if not target_url or target_url == 'http://localhost':
        if not args.target:
            parser.error("No target URL provided. Use positional argument or --config.")
    
    # Setup logging
    logger = setup_logging(
        level=args.log_level,
        name="cseh_cli"
    )
    
    logger.info("=" * 70)
    logger.info("CSEH - Advanced Web Vulnerability Scanner v2.0")
    logger.info("=" * 70)
    logger.info(f"Target: {target_url}")
    logger.info(f"Max Depth: {args.depth}")
    logger.info(f"Max URLs: {args.max_urls}")
    logger.info(f"JavaScript: {'Enabled' if args.js else 'Disabled'}")
    logger.info("=" * 70)
    
    try:
        # Create and run scanner
        scanner = VulnerabilityScanner(
            target_url=target_url,
            max_depth=args.depth,
            max_urls=args.max_urls,
            use_js=args.js,
            timeout=args.timeout,
            log_level=args.log_level,
        )
        
        # Run scan
        scan_result = asyncio.run(scanner.scan())
        
        # Generate reports
        Path(args.report_dir).mkdir(parents=True, exist_ok=True)
        
        if args.format in ["json", "both"]:
            json_reporter = JSONReporter()
            json_file = str(Path(args.report_dir) / "report.json")
            json_reporter.generate(scan_result, json_file)
            logger.info(f"JSON report saved: {json_file}")
            
        if args.format in ["html", "both"]:
            html_reporter = HTMLReporter()
            html_file = str(Path(args.report_dir) / "report.html")
            html_reporter.generate(scan_result, html_file)
            logger.info(f"HTML report saved: {html_file}")
        
        # Print summary
        logger.info("=" * 70)
        logger.info("SCAN SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Total URLs discovered: {len(scan_result.discovered_urls)}")
        logger.info(f"Total forms found: {len(scan_result.discovered_forms)}")
        logger.info(f"Vulnerabilities found: {len(scan_result.vulnerabilities)}")
        logger.info(f"  Critical: {scan_result.critical_count}")
        logger.info(f"  High: {scan_result.high_count}")
        logger.info(f"  Medium: {scan_result.medium_count}")
        logger.info(f"  Low: {scan_result.low_count}")
        logger.info(f"  Info: {scan_result.info_count}")
        logger.info("=" * 70)
        
        return 0
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())
