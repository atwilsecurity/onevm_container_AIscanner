# src/chatbot/bot.py
import os
from typing import Dict, List, Any
import json
from datetime import datetime

# Use your existing Claude client if available, or create a new one
try:
    from src.ai.claude_client import ClaudeAnalyzer
    use_claude = True
except ImportError:
    use_claude = False

class SecurityChatbot:
    def __init__(self, api_key=None):
        """Initialize the security chatbot"""
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        
        if use_claude and self.api_key:
            # Use the Claude client for sophisticated responses
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
                self.available = True
            except Exception as e:
                print(f"Could not initialize Claude client: {str(e)}")
                self.available = False
        else:
            # Fall back to simpler rule-based responses
            self.available = True
            self.knowledge_base = self._load_knowledge_base()
    
    def _load_knowledge_base(self) -> Dict[str, Any]:
        """Load the security knowledge base"""
        # For a simple implementation, we'll use a hardcoded knowledge base
        # In a production system, this could be loaded from a database or files
        return {
            "vulnerabilities": {
                "critical": "Critical vulnerabilities pose a direct threat to your system security and should be addressed immediately.",
                "high": "High severity vulnerabilities should be prioritized and fixed soon.",
                "medium": "Medium severity vulnerabilities should be addressed after critical and high ones.",
                "low": "Low severity vulnerabilities are less urgent but still worth addressing."
            },
            "common_questions": {
                "what is onevm": "OneVM is a container security scanning application that identifies vulnerabilities in Docker images and Kubernetes environments.",
                "how to scan": "To scan a container image, enter the image name on the home page and click 'Scan Image'.",
                "kubernetes": "OneVM can scan Kubernetes namespaces to identify vulnerabilities across all container images."
            }
        }
    
    def get_response(self, message: str, conversation_history: List[Dict[str, str]] = None) -> str:
        """Generate a response to the user's message"""
        if not self.available:
            return "I'm sorry, but the chatbot service is currently unavailable."
        
        if use_claude and self.api_key:
            return self._get_claude_response(message, conversation_history)
        else:
            return self._get_simple_response(message)
    
    def _get_claude_response(self, message: str, conversation_history: List[Dict[str, str]] = None) -> str:
        """Get a response using Claude"""
        if conversation_history is None:
            conversation_history = []
        
        # Prepare system prompt and conversation history for Claude format
        system_prompt = """You are a helpful security assistant for OneVM, a container security scanning application.
            Provide concise, helpful responses about container security, vulnerability management, and how to use the OneVM application.
            Focus on giving practical advice for container security issues."""
            
        messages = []
        
        # Add conversation history
        for entry in conversation_history:
            if entry["role"] == "user":
                messages.append({"role": "user", "content": entry["content"]})
            else:
                messages.append({"role": "assistant", "content": entry["content"]})
        
        # Add current message
        messages.append({"role": "user", "content": message})
        
        try:
            # Call Claude API
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20240620",
                max_tokens=500,
                system_prompt=system_prompt,
                messages=messages
            )
            
            return response.content[0].text
        except Exception as e:
            print(f"Error getting Claude response: {str(e)}")
            return "I'm sorry, I encountered an error. Please try again later."
    
    def _get_simple_response(self, message: str) -> str:
        """Get a simple rule-based response"""
        message = message.lower()
        
        # Check common questions
        for key, response in self.knowledge_base["common_questions"].items():
            if key in message:
                return response
        
        # Check for vulnerability severity questions
        for severity, explanation in self.knowledge_base["vulnerabilities"].items():
            if severity in message:
                return explanation
        
        # Default responses
        if "hello" in message or "hi" in message:
            return "Hello! I'm the OneVM security assistant. How can I help you with container security today?"
        
        if "thank" in message:
            return "You're welcome! Let me know if you have any other questions about container security."
        
        if "help" in message:
            return "I can help with interpreting scan results, understanding vulnerabilities, and using OneVM features. What would you like to know about?"
        
        # Default response
        return "I'm not sure how to help with that. You can ask about container vulnerabilities, scan results, or how to use OneVM features."