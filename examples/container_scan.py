# examples/container_scan.py
import sys
import os
import json
from datetime import datetime

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.mcp.client import MCPClient

def scan_container(container_id: str):
    """Simulate scanning a container and using MCP to store context"""
    
    # Initialize MCP client
    client = MCPClient()
    
    # Create initial context for container scan
    initial_context = client.create_context(
        model_name="container_scanner",
        data={
            "container_id": container_id,
            "scan_status": "started",
            "vulnerabilities": []
        },
        metadata={
            "timestamp": datetime.now().isoformat(),
            "scan_type": "initial"
        }
    )
    
    context_id = initial_context["context_id"]
    print(f"Created initial context for container {container_id} with ID: {context_id}")
    
    # Simulate finding vulnerabilities
    vulnerabilities = [
        {
            "id": "CVE-2023-1234",
            "severity": "critical",
            "description": "Buffer overflow in library X"
        },
        {
            "id": "CVE-2023-5678",
            "severity": "medium",
            "description": "Information disclosure in service Y"
        }
    ]
    
    # Update context with findings
    client.update_context(
        context_id=context_id,
        model_name="vulnerability_analyzer",
        data={
            "container_id": container_id,
            "scan_status": "completed",
            "vulnerabilities": vulnerabilities
        },
        metadata={
            "timestamp": datetime.now().isoformat(),
            "scan_type": "vulnerability_analysis"
        }
    )
    
    print(f"Updated context with vulnerability findings")
    
    # Retrieve the final context
    final_context = client.get_context(context_id)
    print(f"Final context: {json.dumps(final_context, indent=2)}")
    
    return context_id

if __name__ == "__main__":
    # Example usage
    container_id = "test-container-123"
    context_id = scan_container(container_id)
    print(f"Container scan completed with context ID: {context_id}")