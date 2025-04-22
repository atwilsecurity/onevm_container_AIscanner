# examples/generate_report.py
import sys
import os
import argparse

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanner.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description='Generate a vulnerability report from scan results')
    parser.add_argument('context_id', help='Context ID of the scan results')
    parser.add_argument('--output', '-o', default='vulnerability_report.html',
                        help='Output HTML file path (default: vulnerability_report.html)')
    
    args = parser.parse_args()
    
    print(f"Generating report for scan context: {args.context_id}")
    
    # Create report generator and generate the report
    generator = ReportGenerator()
    generator.generate_html_report(args.context_id, args.output)
    
    print(f"Report generated successfully: {args.output}")
    print(f"Open this file in a web browser to view the report")

if __name__ == "__main__":
    main()