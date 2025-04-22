# src/scanner/report_generator.py
import json
import os
import uuid
from typing import Dict, Any, List
from datetime import datetime
from tqdm import tqdm

from src.mcp.client import MCPClient

class ReportGenerator:
    def __init__(self, mcp_url: str = "http://localhost:8000", api_key: str = None):
        # Use provided API key or try to get from environment, or use a test key for development
        api_key = api_key or os.environ.get("MCP_API_KEY", "test_development_key")
        self.mcp_client = MCPClient(mcp_url, api_key=api_key)
    
    def generate_html_report(self, context_id: str, output_file: str) -> None:
        """
        Generate an HTML report from the scan results
        
        Args:
            context_id: ID of the context containing scan results
            output_file: Path to the output HTML file
        """
        # Create a context ID for the report generation process
        report_id = str(uuid.uuid4())
        
        # Create a report generation context to track progress
        self.mcp_client.create_context(
            model_name="report_generator",
            data={
                "original_context_id": context_id,
                "report_id": report_id,
                "status": "started",
                "progress": 0,
                "progress_message": "Starting report generation..."
            },
            metadata={
                "timestamp": datetime.now().isoformat(),
                "type": "report_generation"
            }
        )
        
        try:
            # Update progress - Fetching data
            self._update_progress(report_id, context_id, 10, "Fetching scan data...")
            
            # Get the scan results from MCP
            scan_result = self.mcp_client.get_context(context_id)
            
            if scan_result['data']['status'] != "completed":
                self._update_progress(report_id, context_id, 0, 
                                     f"Error: Cannot generate report - scan status is {scan_result['data']['status']}")
                raise ValueError(f"Cannot generate report: scan status is {scan_result['data']['status']}")
            
            # Update progress - Generating HTML
            self._update_progress(report_id, context_id, 30, "Processing vulnerability data...")
            
            # Generate HTML
            with tqdm(total=100, desc="Generating Report") as pbar:
                pbar.update(30)
                
                # Process data
                total_vulns = 0
                if "vulnerabilities" in scan_result['data']:
                    total_vulns = len(scan_result['data']['vulnerabilities'])
                
                self._update_progress(report_id, context_id, 50, 
                                    f"Processing {total_vulns} vulnerabilities...")
                pbar.update(20)
                
                # Generate HTML content
                html = self._generate_html(scan_result)
                
                self._update_progress(report_id, context_id, 80, "Finalizing report...")
                pbar.update(30)
                
                # Write to file
                with open(output_file, 'w') as f:
                    f.write(html)
                
                self._update_progress(report_id, context_id, 100, "Report generated successfully")
                pbar.update(20)
            
            print(f"Report generated: {output_file}")
            
        except Exception as e:
            # Update progress with error
            self._update_progress(report_id, context_id, 0, f"Error generating report: {str(e)}")
            raise
            
    def _update_progress(self, report_id, context_id, progress, message):
        """Update the progress of report generation in the MCP context"""
        try:
            self.mcp_client.update_context(
                context_id=report_id,
                model_name="report_generator",
                data={
                    "original_context_id": context_id,
                    "report_id": report_id,
                    "status": "generating" if progress < 100 else "completed",
                    "progress": progress,
                    "progress_message": message
                },
                metadata={
                    "timestamp": datetime.now().isoformat(),
                    "type": "report_generation"
                }
            )
        except Exception as e:
            # Don't let progress updates cause the report generation to fail
            print(f"Error updating report progress: {str(e)}")
    
    def _generate_html(self, scan_result: Dict[str, Any]) -> str:
        """
        Generate HTML report content
        
        Args:
            scan_result: Scan result data from MCP
            
        Returns:
            HTML content as string
        """
        image_name = scan_result['data']['image_name']
        scan_id = scan_result['data']['scan_id']
        vulnerabilities = scan_result['data']['vulnerabilities']
        summary = scan_result['data']['summary']
        
        # Calculate total vulnerabilities
        total_vulns = sum(summary.values())
        
        # Format timestamp
        timestamp = scan_result['metadata'].get('timestamp', '')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                formatted_time = timestamp
        else:
            formatted_time = "Unknown"
        
        # Generate HTML
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vulnerability Scan Report - {image_name}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                h1, h2, h3 {{
                    color: #2c3e50;
                }}
                .report-header {{
                    background-color: #f8f9fa;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .summary-box {{
                    display: flex;
                    justify-content: space-between;
                    margin: 20px 0;
                }}
                .summary-item {{
                    padding: 15px;
                    border-radius: 5px;
                    text-align: center;
                    flex: 1;
                    margin: 0 5px;
                }}
                .critical {{
                    background-color: #ffdddd;
                    color: #d63031;
                }}
                .high {{
                    background-color: #ffeaa7;
                    color: #fdcb6e;
                }}
                .medium {{
                    background-color: #81ecec;
                    color: #00cec9;
                }}
                .low {{
                    background-color: #dfe6e9;
                    color: #636e72;
                }}
                .unknown {{
                    background-color: #b2bec3;
                    color: #2d3436;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                th, td {{
                    padding: 12px 15px;
                    border-bottom: 1px solid #ddd;
                    text-align: left;
                }}
                th {{
                    background-color: #f8f9fa;
                }}
                tr:hover {{
                    background-color: #f5f5f5;
                }}
                .severity-tag {{
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-size: 0.8em;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <div class="report-header">
                <h1>Vulnerability Scan Report</h1>
                <p><strong>Image:</strong> {image_name}</p>
                <p><strong>Scan ID:</strong> {scan_id}</p>
                <p><strong>Timestamp:</strong> {formatted_time}</p>
                <p><strong>Total Vulnerabilities:</strong> {total_vulns}</p>
            </div>
            
            <h2>Vulnerability Summary</h2>
            <div class="summary-box">
                <div class="summary-item critical">
                    <h3>Critical</h3>
                    <p>{summary.get('CRITICAL', 0)}</p>
                </div>
                <div class="summary-item high">
                    <h3>High</h3>
                    <p>{summary.get('HIGH', 0)}</p>
                </div>
                <div class="summary-item medium">
                    <h3>Medium</h3>
                    <p>{summary.get('MEDIUM', 0)}</p>
                </div>
                <div class="summary-item low">
                    <h3>Low</h3>
                    <p>{summary.get('LOW', 0)}</p>
                </div>
                <div class="summary-item unknown">
                    <h3>Unknown</h3>
                    <p>{summary.get('UNKNOWN', 0)}</p>
                </div>
            </div>
            
            <h2>Vulnerability Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Severity</th>
                        <th>Package</th>
                        <th>Current Version</th>
                        <th>Fixed Version</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # Sort vulnerabilities by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "UNKNOWN": 4
            }.get(x['severity'], 5)
        )
        
        # Add vulnerability rows
        for vuln in sorted_vulns:
            severity_class = vuln['severity'].lower() if vuln['severity'].lower() in ['critical', 'high', 'medium', 'low'] else 'unknown'
            
            html += f"""
                <tr>
                    <td>{vuln['id']}</td>
                    <td><span class="severity-tag {severity_class}">{vuln['severity']}</span></td>
                    <td>{vuln['package_name']}</td>
                    <td>{vuln['package_version']}</td>
                    <td>{vuln['fixed_version'] or 'Not fixed'}</td>
                    <td>{vuln['description'][:100] + '...' if len(vuln['description']) > 100 else vuln['description']}</td>
                </tr>
            """
        
        # Close the HTML
        html += """
                </tbody>
            </table>
        </body>
        </html>
        """
        
        return html