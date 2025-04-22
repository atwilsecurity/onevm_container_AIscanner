# src/kubernetes/scanner.py
from typing import Dict, List, Any
import os
import json
from datetime import datetime
import uuid

from src.kubernetes.client import KubernetesClient
from src.scanner.vulnerability_scanner import VulnerabilityScanner
from src.mcp.client import MCPClient

class KubernetesScanner:
    def __init__(self, kubeconfig=None, mcp_url: str = "http://localhost:8000"):
        """
        Initialize the Kubernetes scanner
        
        Args:
            kubeconfig: Path to kubeconfig file
            mcp_url: URL of the MCP server
        """
        self.k8s_client = KubernetesClient(kubeconfig)
        self.vuln_scanner = VulnerabilityScanner(mcp_url)
        self.mcp_client = MCPClient(mcp_url)
    
    def scan_namespace(self, namespace: str = "default") -> str:
        """
        Scan all images in a namespace
        
        Args:
            namespace: Kubernetes namespace to scan
            
        Returns:
            Context ID of the scan results
        """
        # Create a unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Get all images in the namespace
        images = self.k8s_client.get_all_images(namespace)
        
        # Get pods and deployments
        pods = self.k8s_client.list_pods(namespace)
        deployments = self.k8s_client.list_deployments(namespace)
        
        # Create initial context
        context = self.mcp_client.create_context(
            model_name="kubernetes_scanner",
            data={
                "scan_id": scan_id,
                "namespace": namespace,
                "status": "started",
                "pod_count": len(pods),
                "deployment_count": len(deployments),
                "image_count": len(images),
                "images": images,
                "pods": pods,
                "deployments": deployments,
                "scan_results": {},
                "vulnerabilities": []
            },
            metadata={
                "timestamp": datetime.now().isoformat(),
                "scan_type": "kubernetes_namespace_scan"
            }
        )
        
        context_id = context["context_id"]
        print(f"Created scan context for namespace {namespace} with ID: {context_id}")
        
        try:
            # Scan each image
            scan_results = {}
            all_vulnerabilities = []
            
            for image in images:
                try:
                    # Scan the image using the vulnerability scanner
                    image_context_id = self.vuln_scanner.scan_image(image)
                    
                    # Get the scan results
                    image_scan_result = self.mcp_client.get_context(image_context_id)
                    
                    # Add to scan results
                    scan_results[image] = {
                        "context_id": image_context_id,
                        "status": image_scan_result["data"]["status"],
                        "vulnerabilities": len(image_scan_result["data"].get("vulnerabilities", [])),
                        "summary": image_scan_result["data"].get("summary", {})
                    }
                    
                    # Add vulnerabilities to the list
                    if image_scan_result["data"]["status"] == "completed":
                        for vuln in image_scan_result["data"].get("vulnerabilities", []):
                            vuln["image"] = image
                            all_vulnerabilities.append(vuln)
                
                except Exception as e:
                    print(f"Error scanning image {image}: {str(e)}")
                    scan_results[image] = {
                        "status": "error",
                        "error": str(e)
                    }
            
            # Calculate summary
            summary = self._generate_summary(all_vulnerabilities)
            
            # Update context with results
            self.mcp_client.update_context(
                context_id=context_id,
                model_name="kubernetes_scanner",
                data={
                    "scan_id": scan_id,
                    "namespace": namespace,
                    "status": "completed",
                    "pod_count": len(pods),
                    "deployment_count": len(deployments),
                    "image_count": len(images),
                    "images": images,
                    "pods": pods,
                    "deployments": deployments,
                    "scan_results": scan_results,
                    "vulnerabilities": all_vulnerabilities,
                    "summary": summary
                },
                metadata={
                    "timestamp": datetime.now().isoformat(),
                    "scan_type": "kubernetes_namespace_scan"
                }
            )
            
            print(f"Updated context with results for {len(images)} images and {len(all_vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            # Update context with error
            self.mcp_client.update_context(
                context_id=context_id,
                model_name="kubernetes_scanner",
                data={
                    "scan_id": scan_id,
                    "namespace": namespace,
                    "status": "error",
                    "error": str(e)
                },
                metadata={
                    "timestamp": datetime.now().isoformat(),
                    "scan_type": "kubernetes_namespace_scan"
                }
            )
            print(f"Error scanning namespace {namespace}: {str(e)}")
            
        return context_id
    
    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Generate a summary of vulnerabilities by severity
        
        Args:
            vulnerabilities: List of vulnerability objects
            
        Returns:
            Dictionary with count by severity
        """
        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            if severity in summary:
                summary[severity] += 1
            else:
                summary["UNKNOWN"] += 1
                
        return summary
