# src/mcp/client.py
import json
import requests
from typing import Dict, Any, Optional

class MCPClient:
    """Client for interacting with the Model Context Protocol server"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
    
    def create_context(self, model_name: str, data: Dict[str, Any], 
                      context_id: Optional[str] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a new context in the MCP server"""
        payload = {
            "model_name": model_name,
            "data": data,
            "metadata": metadata or {}
        }
        
        if context_id:
            payload["context_id"] = context_id
        
        response = requests.post(f"{self.base_url}/context", json=payload)
        if response.status_code != 200:
            raise Exception(f"Failed to create context: {response.text}")
        
        return response.json()
    
    def get_context(self, context_id: str) -> Dict[str, Any]:
        """Retrieve a context from the MCP server"""
        response = requests.get(f"{self.base_url}/context/{context_id}")
        if response.status_code != 200:
            raise Exception(f"Failed to get context: {response.text}")
        
        return response.json()
    
    def update_context(self, context_id: str, model_name: str, data: Dict[str, Any],
                      metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Update an existing context in the MCP server"""
        payload = {
            "model_name": model_name,
            "data": data,
            "metadata": metadata or {}
        }
        
        response = requests.put(f"{self.base_url}/context/{context_id}", json=payload)
        if response.status_code != 200:
            raise Exception(f"Failed to update context: {response.text}")
        
        return response.json()
    
    def delete_context(self, context_id: str) -> Dict[str, Any]:
        """Delete a context from the MCP server"""
        response = requests.delete(f"{self.base_url}/context/{context_id}")
        if response.status_code != 200:
            raise Exception(f"Failed to delete context: {response.text}")
        
        return response.json()