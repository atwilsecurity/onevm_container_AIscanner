# examples/scan_image.py
import sys
import os
import json
from datetime import datetime

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanner.vulnerability_scanner import VulnerabilityScanner
from src.mcp.client import MCPClient

def main():
    # Get the image name from command line or use a default
    image_name = sys.argv[1] if len(sys.argv) > 1 else "ubuntu:latest"
    
    print(f"Scanning Docker image: {image_name}")
    
    # Create scanner and scan the image
    scanner = VulnerabilityScanner()
    context_id = scanner.scan_image(image_name)
    
    # Retrieve and display the final scan results
    mcp_client = MCPClient()
    scan_result = mcp_client.get_context(context_id)
    
    print("\nScan Results:")
    print(f"Image: {scan_result['data']['image_name']}")
    print(f"Status: {scan_result['data']['status']}")
    
    if scan_result['data']['status'] == "completed":
        print("\nVulnerability Summary:")
        for severity, count in scan_result['data']['summary'].items():
            print(f"  {severity}: {count}")
        
        if scan_result['data']['vulnerabilities']:
            print("\nTop 5 Critical/High Vulnerabilities:")
            # Sort vulnerabilities by severity and display top ones
            top_vulns = sorted(
                scan_result['data']['vulnerabilities'],
                key=lambda x: {
                    "CRITICAL": 0,
                    "HIGH": 1,
                    "MEDIUM": 2,
                    "LOW": 3,
                    "UNKNOWN": 4
                }.get(x['severity'], 5)
            )[:5]
            
            for vuln in top_vulns:
                print(f"\n  {vuln['id']} ({vuln['severity']})")
                print(f"  Package: {vuln['package_name']} {vuln['package_version']}")
                print(f"  Fixed in: {vuln['fixed_version'] or 'Not fixed'}")
                description = vuln['description']
                if len(description) > 100:
                    description = description[:100] + "..."
                print(f"  Description: {description}")
                if vuln.get('cvss_score'):
                    print(f"  CVSS Score: {vuln['cvss_score']}")
        else:
            print("\nNo vulnerabilities found!")
    
    print(f"\nFull scan context ID: {context_id}")
    print("You can retrieve this context later using the MCP client")

if __name__ == "__main__":
    main()