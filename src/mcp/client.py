import os
from typing import List, Dict, Optional, Any
import requests

class MCPClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        """
        Initialize the MCP client.
        
        Args:
            base_url: The base URL for the MCP API.
            api_key: The API key for authentication. If not provided, 
                    it will be read from the MCP_API_KEY environment variable.
        """
        self.base_url = base_url
        self.api_key = api_key or os.environ.get("MCP_API_KEY")
        if not self.api_key:
            raise ValueError("API key must be provided either directly or via MCP_API_KEY environment variable")
        
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    def get_model(self, model_name: str) -> Dict[str, Any]:
        """
        Get information about a specific model.
        
        Args:
            model_name: The name of the model to retrieve.
            
        Returns:
            Dictionary containing model information.
        """
        response = requests.get(
            f"{self.base_url}/models/{model_name}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def list_models(self) -> List[Dict[str, Any]]:
        """
        List all available models.
        
        Returns:
            List of dictionaries containing model information.
        """
        response = requests.get(
            f"{self.base_url}/models",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json().get("models", [])
    
    def list_contexts(self, model_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List available contexts, optionally filtered by model name.
        
        Args:
            model_name: Optional. Filter contexts by model name.
            
        Returns:
            List of dictionaries containing context information.
        """
        url = f"{self.base_url}/context"
        if model_name:
            url += f"?model={model_name}"
        
        response = requests.get(
            url,
            headers=self.headers
        )
        response.raise_for_status()
        return response.json().get("contexts", [])
    
    def create_context(self, model_name: str, data: Dict[str, Any] = None, metadata: Dict[str, Any] = None, name: str = None, document_text: str = None) -> Dict[str, Any]:
        """
        Create a new context.
        
        Args:
            model_name: The model to use for this context.
            data: The data object to associate with this context.
            metadata: Metadata to attach to the context.
            name: Optional name for the context.
            document_text: Optional document text to analyze.
            
        Returns:
            Dictionary containing the created context information.
        """
        payload = {
            "model_name": model_name
        }
        
        if name:
            payload["name"] = name
            
        if document_text:
            payload["document_text"] = document_text
            
        if data:
            payload["data"] = data
            
        if metadata:
            payload["metadata"] = metadata
            
        response = requests.post(
            f"{self.base_url}/context",
            headers=self.headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    def delete_context(self, context_id: str) -> None:
        """
        Delete a context.
        
        Args:
            context_id: The ID of the context to delete.
        """
        response = requests.delete(
            f"{self.base_url}/context/{context_id}",
            headers=self.headers
        )
        response.raise_for_status()
    
    def get_context(self, context_id: str) -> Dict[str, Any]:
        """
        Get a context by ID.
        
        Args:
            context_id: The ID of the context to retrieve.
            
        Returns:
            Dictionary containing context information.
        """
        response = requests.get(
            f"{self.base_url}/context/{context_id}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def update_context(self, context_id: str, model_name: str, data: Dict[str, Any] = None, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Update an existing context.
        
        Args:
            context_id: The ID of the context to update.
            model_name: The model to use for this context.
            data: The data object to associate with this context.
            metadata: Metadata to attach to the context.
            
        Returns:
            Dictionary containing the updated context information.
        """
        payload = {
            "model_name": model_name
        }
        
        if data:
            payload["data"] = data
            
        if metadata:
            payload["metadata"] = metadata
            
        response = requests.put(
            f"{self.base_url}/context/{context_id}",
            headers=self.headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()
        
    def scan_vulnerabilities(self, context_id: str, query: str) -> Dict[str, Any]:
        """
        Scan for vulnerabilities using the specified context.
        
        Args:
            context_id: The ID of the context to use.
            query: The query to analyze for vulnerabilities.
            
        Returns:
            Dictionary containing vulnerability scan results.
        """
        payload = {
            "query": query
        }
        response = requests.post(
            f"{self.base_url}/context/{context_id}/scan",
            headers=self.headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()