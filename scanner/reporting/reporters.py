"""JSON report generation."""

import json
from typing import Dict, Any
from datetime import datetime
from pathlib import Path
from ..utils.models import ScanResult


class JSONReporter:
    """Generate JSON reports from scan results."""
    
    def generate(self, scan_result: ScanResult, output_file: str) -> str:
        """
        Generate JSON report.
        
        Parameters
        ----------
        scan_result : ScanResult
            Complete scan results.
        output_file : str
            Path to output file.
            
        Returns
        -------
        str
            Path to generated report.
        """
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        report_data = {
            'metadata': {
                'generator': 'CSEH Scanner v2.0',
                'generated_at': datetime.utcnow().isoformat(),
            },
            'scan': scan_result.to_dict(),
        }
        # add a convenience section with the most relevant fields for each
        # finding, as requested by the enhancement requirements.
        report_data['scan']['detailed_findings'] = []
        for vuln in report_data['scan']['vulnerabilities']:
            entry = {
                'vulnerability_type': vuln.get('type'),
                'severity': vuln.get('severity'),
                'priority_score': vuln.get('metadata', {}).get('priority_score'),
                'tested_payload': None,
                'evidence': vuln.get('evidence'),
            }
            # try to pull payload from first evidence item
            if vuln.get('evidence') and isinstance(vuln['evidence'], list):
                entry['tested_payload'] = vuln['evidence'][0].get('payload_used')
            report_data['scan']['detailed_findings'].append(entry)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
        return output_file


class HTMLReporter:
    """Generate HTML reports from scan results."""
    
    def generate(self, scan_result: ScanResult, output_file: str) -> str:
        """Generate HTML report."""
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        html = self._build_html(scan_result)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
            
        return output_file
        
    def _build_html(self, scan_result: ScanResult) -> str:
        """Build HTML content."""
        criticality_badge = self._get_criticality_badge(scan_result)
        vulnerabilities_html = self._build_vulnerabilities_html(scan_result)
        # priority and payload details will be included in _build_vulnerabilities_html
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan_result.target_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
        header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        header p {{ opacity: 0.9; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }}
        .summary-card.critical {{ border-left-color: #e53e3e; }}
        .summary-card.high {{ border-left-color: #ed8936; }}
        .summary-card.medium {{ border-left-color: #f6ad55; }}
        .summary-card.low {{ border-left-color: #68d391; }}
        .summary-card h3 {{ color: #666; font-size: 12px; text-transform: uppercase; margin-bottom: 10px; }}
        .summary-card .value {{ font-size: 32px; font-weight: bold; }}
        .vulnerabilities {{ background: white; border-radius: 8px; padding: 20px; }}
        .vulnerability {{ border-bottom: 1px solid #eee; padding: 15px 0; }}
        .vulnerability:last-child {{ border-bottom: none; }}
        .vulnerability.critical {{ border-left: 4px solid #e53e3e; padding-left: 15px; }}
        .vulnerability.high {{ border-left: 4px solid #ed8936; padding-left: 15px; }}
        .vulnerability.medium {{ border-left: 4px solid #f6ad55; padding-left: 15px; }}
        .vulnerability.low {{ border-left: 4px solid #68d391; padding-left: 15px; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge.critical {{ background: #fff5f5; color: #e53e3e; }}
        .badge.high {{ background: #fffaf0; color: #ed8936; }}
        .badge.medium {{ background: #fffbf0; color: #c05621; }}
        .badge.low {{ background: #f0fff4; color: #22543d; }}
        .vulnerability h3 {{ font-size: 16px; margin-bottom: 10px; }}
        .vulnerability p {{ font-size: 14px; color: #666; line-height: 1.5; }}
        footer {{ text-align: center; color: #999; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Vulnerability Assessment Report</h1>
            <p>Target: {scan_result.target_url}</p>
            <p>Scan Date: {scan_result.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="summary">
            {criticality_badge}
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="value">{scan_result.critical_count}</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="value">{scan_result.high_count}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="value">{scan_result.medium_count}</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="value">{scan_result.low_count}</div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>Vulnerabilities Found ({len(scan_result.vulnerabilities)})</h2>
            {vulnerabilities_html}
        </div>
        
        <footer>
            <p>Generated by CSEH Scanner v2.0 | Enterprise Security Assessment Tool</p>
        </footer>
    </div>
</body>
</html>
"""
        
    def _get_criticality_badge(self, scan_result: ScanResult) -> str:
        """Determine overall criticality."""
        if scan_result.critical_count > 0:
            criticality = "Critical"
            color = "critical"
        elif scan_result.high_count > 0:
            criticality = "High Risk"
            color = "high"
        elif scan_result.medium_count > 0:
            criticality = "Medium Risk"
            color = "medium"
        else:
            criticality = "Low Risk"
            color = "low"
            
        return f'<div class="summary-card {color}"><h3>Overall Risk</h3><div class="value">{criticality}</div></div>'
        
    def _build_vulnerabilities_html(self, scan_result: ScanResult) -> str:
        """Build vulnerabilities HTML."""
        if not scan_result.vulnerabilities:
            return "<p>No vulnerabilities found.</p>"
            
        html = ""
        for vuln in scan_result.vulnerabilities:
            severity_lower = vuln.severity.value.lower()
            # grab tested payload if available
            tested = None
            if vuln.evidence:
                tested = vuln.evidence[0].payload_used
            priority = vuln.metadata.get('priority_score', None) if hasattr(vuln, 'metadata') else None
            html += f"""
            <div class="vulnerability {severity_lower}">
                <span class="badge {severity_lower}">{vuln.severity.value}</span>
                <h3>{vuln.title}</h3>
                <p><strong>URL:</strong> {vuln.target_url}</p>
                {f'<p><strong>Payload:</strong> {tested}</p>' if tested else ''}
                {f'<p><strong>Priority Score:</strong> {priority}</p>' if priority is not None else ''}
                <p><strong>Description:</strong> {vuln.description}</p>
                <p><strong>CVSS Score:</strong> {vuln.cvss_score} | <strong>Confidence:</strong> {vuln.confidence:.1%}</p>
                {f'<p><strong>Remediation:</strong> {vuln.remediation}</p>' if vuln.remediation else ''}
            </div>
            """
        
        return html
