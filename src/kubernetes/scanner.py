# src/kubernetes/scanner.py
from typing import Dict, List, Any
import os
import json
from datetime import datetime
import uuid
from tqdm import tqdm

from src.kubernetes.client import KubernetesClient
from src.scanner.vulnerability_scanner import VulnerabilityScanner
from src.mcp.client import MCPClient

class KubernetesScanner:
    def __init__(self, kubeconfig=None, mcp_url: str = "http://localhost:8000", api_key: str = None):
        """
        Initialize the Kubernetes scanner
        
        Args:
            kubeconfig: Path to kubeconfig file
            mcp_url: URL of the MCP server
            api_key: API key for MCP authentication
        """
        # Use provided API key or try to get from environment, or use a test key for development
        api_key = api_key or os.environ.get("MCP_API_KEY", "test_development_key")
        self.k8s_client = KubernetesClient(kubeconfig)
        self.vuln_scanner = VulnerabilityScanner(mcp_url, api_key=api_key)
        self.mcp_client = MCPClient(mcp_url, api_key=api_key)
    
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
                "progress": 0,
                "progress_message": "Initializing scan...",
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
            total_images = len(images)
            
            # Update progress - starting scan
            self._update_progress(context_id, scan_id, namespace, 10, f"Starting scan of {total_images} images")
            
            # Create progress bar for images
            for i, image in enumerate(tqdm(images, desc="Scanning Kubernetes images")):
                # Calculate progress percentage based on completed images
                progress_percent = 10 + int((i / total_images) * 80)  # Scale from 10% to 90%
                self._update_progress(context_id, scan_id, namespace, progress_percent, 
                                    f"Scanning image {i+1}/{total_images}: {image}")
                
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
            
            # Update progress - finalizing results
            self._update_progress(context_id, scan_id, namespace, 90, "Generating vulnerability summary...")
            
            # Calculate summary
            summary = self._generate_summary(all_vulnerabilities)
            
            # Final progress update
            self._update_progress(context_id, scan_id, namespace, 95, "Preparing final report...")
            
            # Update context with results
            self.mcp_client.update_context(
                context_id=context_id,
                model_name="kubernetes_scanner",
                data={
                    "scan_id": scan_id,
                    "namespace": namespace,
                    "status": "completed",
                    "progress": 100,
                    "progress_message": "Scan completed",
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
                    "progress": 0,
                    "progress_message": f"Error: {str(e)}",
                    "error": str(e)
                },
                metadata={
                    "timestamp": datetime.now().isoformat(),
                    "scan_type": "kubernetes_namespace_scan"
                }
            )
            print(f"Error scanning namespace {namespace}: {str(e)}")
            
        return context_id
        
    def _update_progress(self, context_id, scan_id, namespace, progress, message):
        """Update the progress in the MCP context"""
        try:
            self.mcp_client.update_context(
                context_id=context_id,
                model_name="kubernetes_scanner",
                data={
                    "scan_id": scan_id,
                    "namespace": namespace,
                    "status": "scanning",
                    "progress": progress,
                    "progress_message": message
                },
                metadata={
                    "timestamp": datetime.now().isoformat(),
                    "scan_type": "kubernetes_namespace_scan"
                }
            )
        except Exception as e:
            # Don't let progress updates cause the scan to fail
            print(f"Error updating progress: {str(e)}")
    
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
