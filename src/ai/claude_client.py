# src/ai/claude_client.py
import os
from typing import Dict, List, Any
import anthropic
from datetime import datetime

from src.mcp.client import MCPClient

class ClaudeAnalyzer:
    def __init__(self, api_key=None, mcp_url: str = "http://localhost:8000", mcp_api_key=None):
        # Get API key from environment variable if not provided
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("Anthropic API key is required. Set ANTHROPIC_API_KEY environment variable or pass as parameter.")
        
        # Initialize Claude client
        self.client = anthropic.Anthropic(api_key=self.api_key)
        
        # Use MCP API key from parameter, environment, or test key
        mcp_api_key = mcp_api_key or os.environ.get("MCP_API_KEY", "test_development_key")
        self.mcp_client = MCPClient(mcp_url, api_key=mcp_api_key)
    
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
        prompt = f"""I need you to analyze these specific security vulnerabilities found in the Docker image {image_name}.
        
Here are the top vulnerabilities that need detailed analysis:

"""
        
        for i, vuln in enumerate(top_vulnerabilities, 1):
            prompt += f"""
{i}. {vuln['id']} ({vuln['severity']})
   Package: {vuln['package_name']} {vuln['package_version']}
   Fixed Version: {vuln['fixed_version'] or 'Not fixed'}
   Description: {vuln['description']}
"""
        
        prompt += """
IMPORTANT: Provide a tailored analysis that addresses these SPECIFIC vulnerabilities (by ID) found in the scan results above. Do not give generic vulnerability descriptions.

Please provide:
1. A specific summary of the security risks in THIS container
2. Detailed explanation of each of the listed vulnerabilities above, addressing them by ID
3. Specific recommended actions to mitigate THESE vulnerabilities
4. Container security best practices relevant to these findings

Format your response in JSON with the following structure:
{
  "summary": "overall summary based specifically on the identified vulnerabilities",
  "detailed_analysis": [
    {
      "id": "exact vulnerability ID as shown above",
      "explanation": "detailed explanation of this specific vulnerability",
      "impact": "potential impact of this particular vulnerability",
      "mitigation": "specific instructions to fix this vulnerability"
    },
    ...
  ],
  "recommendations": [
    "recommendation 1 relevant to these findings",
    "recommendation 2 relevant to these findings",
    ...
  ],
  "best_practices": [
    "practice 1 focused on these types of vulnerabilities",
    "practice 2 focused on these types of vulnerabilities",
    ...
  ]
}
"""
        
        # Send request to Claude
        try:
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20240620",
                max_tokens=4000,
                system="You are a container security expert specializing in detailed vulnerability analysis. Analyze only the specific vulnerabilities provided in the input. Provide concrete, practical remediation advice for each vulnerability by ID. Focus on actionable, specific mitigations rather than generic security practices. Include specific commands or configuration changes when possible.",
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
