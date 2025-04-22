# src/ai/claude_client.py
import os
from typing import Dict, List, Any
import anthropic
from datetime import datetime

from src.mcp.client import MCPClient

class ClaudeAnalyzer:
    def __init__(self, api_key=None, mcp_url: str = "http://localhost:8000"):
        # Get API key from environment variable if not provided
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("Anthropic API key is required. Set ANTHROPIC_API_KEY environment variable or pass as parameter.")
        
        # Initialize Claude client
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.mcp_client = MCPClient(mcp_url)
    
    def analyze_vulnerabilities(self, context_id: str) -> str:
        """
        Use Claude to analyze vulnerabilities from a scan context
        
        Args:
            context_id: ID of the scan context
            
        Returns:
            New context ID with Claude's analysis
        """
        # Get the scan results from MCP
        scan_result = self.mcp_client.get_context(context_id)
        
        if scan_result['data']['status'] != "completed":
            raise ValueError(f"Cannot analyze: scan status is {scan_result['data']['status']}")
        
        # Prepare data for Claude
        vulnerabilities = scan_result['data']['vulnerabilities']
        image_name = scan_result['data']['image_name']
        
        if not vulnerabilities:
            # Create a new context with Claude's analysis for no vulnerabilities
            analysis_context = self.mcp_client.create_context(
                model_name="claude_analyzer",
                data={
                    "image_name": image_name,
                    "original_context_id": context_id,
                    "analysis": "No vulnerabilities were found in this image.",
                    "recommendations": ["The image appears to be secure based on the scan results."],
                    "analyzed_at": datetime.now().isoformat()
                },
                metadata={
                    "timestamp": datetime.now().isoformat(),
                    "analysis_type": "vulnerability_analysis"
                }
            )
            return analysis_context["context_id"]
        
        # Prepare a prompt for Claude with the top 10 most severe vulnerabilities
        top_vulnerabilities = sorted(
            vulnerabilities,
            key=lambda x: {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "UNKNOWN": 4
            }.get(x.get('severity', 'UNKNOWN'), 5)
        )[:10]
        
        # Create a structured message for Claude
        prompt = f"""I need you to analyze these security vulnerabilities found in the Docker image {image_name}.
        
Here are the top vulnerabilities:

"""
        
        for i, vuln in enumerate(top_vulnerabilities, 1):
            prompt += f"""
{i}. {vuln['id']} ({vuln['severity']})
   Package: {vuln['package_name']} {vuln['package_version']}
   Fixed Version: {vuln['fixed_version'] or 'Not fixed'}
   Description: {vuln['description']}
"""
        
        prompt += """
Please provide:
1. A summary of the security risks
2. Explanation of the most serious vulnerabilities
3. Recommended actions to mitigate these vulnerabilities
4. General best practices for container security

Format your response in JSON with the following structure:
{
  "summary": "overall summary text",
  "detailed_analysis": [
    {
      "id": "vulnerability ID",
      "explanation": "detailed explanation",
      "impact": "potential impact",
      "mitigation": "how to fix"
    },
    ...
  ],
  "recommendations": [
    "recommendation 1",
    "recommendation 2",
    ...
  ],
  "best_practices": [
    "practice 1",
    "practice 2",
    ...
  ]
}
"""
        
        # Send request to Claude
        try:
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20240620",
                max_tokens=4000,
                system="You are a container security expert. You analyze vulnerabilities in Docker images and provide clear explanations and remediation advice.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Extract Claude's response
            analysis_text = response.content[0].text
            
            # Try to parse as JSON but have fallback
            try:
                import json
                analysis_data = json.loads(analysis_text)
                
                # Create a new context with Claude's analysis
                analysis_context = self.mcp_client.create_context(
                    model_name="claude_analyzer",
                    data={
                        "image_name": image_name,
                        "original_context_id": context_id,
                        "summary": analysis_data.get("summary", ""),
                        "detailed_analysis": analysis_data.get("detailed_analysis", []),
                        "recommendations": analysis_data.get("recommendations", []),
                        "best_practices": analysis_data.get("best_practices", []),
                        "raw_response": analysis_text,
                        "analyzed_at": datetime.now().isoformat()
                    },
                    metadata={
                        "timestamp": datetime.now().isoformat(),
                        "analysis_type": "vulnerability_analysis"
                    }
                )
                
            except json.JSONDecodeError:
                # If JSON parsing fails, store the raw text
                analysis_context = self.mcp_client.create_context(
                    model_name="claude_analyzer",
                    data={
                        "image_name": image_name,
                        "original_context_id": context_id,
                        "raw_analysis": analysis_text,
                        "analyzed_at": datetime.now().isoformat()
                    },
                    metadata={
                        "timestamp": datetime.now().isoformat(),
                        "analysis_type": "vulnerability_analysis"
                    }
                )
            
            return analysis_context["context_id"]
            
        except Exception as e:
            print(f"Error with Claude analysis: {str(e)}")
            
            # Create a context with the error
            error_context = self.mcp_client.create_context(
                model_name="claude_analyzer",
                data={
                    "image_name": image_name,
                    "original_context_id": context_id,
                    "error": str(e),
                    "analyzed_at": datetime.now().isoformat()
                },
                metadata={
                    "timestamp": datetime.now().isoformat(),
                    "analysis_type": "vulnerability_analysis_error"
                }
            )
            
            return error_context["context_id"]
