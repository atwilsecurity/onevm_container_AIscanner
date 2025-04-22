# src/kubernetes/client.py
from kubernetes import client, config
from typing import List, Dict, Any
import os

class KubernetesClient:
    def __init__(self, kubeconfig=None):
        """
        Initialize the Kubernetes client
        
        Args:
            kubeconfig: Path to kubeconfig file. If None, tries to load from default location
        """
        self.kubeconfig = kubeconfig
        self.connected = False
        try:
            self._load_config()
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            # Test connection
            self.v1.list_namespace(limit=1)
            self.connected = True
        except Exception as e:
            print(f"Failed to connect to Kubernetes: {str(e)}")
            # Initialize API clients anyway to avoid attribute errors
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
        
    def _load_config(self):
        """Load Kubernetes configuration"""
        try:
            if self.kubeconfig:
                config.load_kube_config(config_file=self.kubeconfig)
            else:
                # Try loading from default location
                config.load_kube_config()
        except Exception:
            # Fallback to in-cluster config for running inside K8s
            try:
                config.load_incluster_config()
            except Exception as e:
                raise RuntimeError(f"Failed to load Kubernetes configuration: {str(e)}")
    
    def _check_connection(self):
        """Check if connected to Kubernetes"""
        if not self.connected:
            raise RuntimeError("Not connected to a Kubernetes cluster")
    
    def list_namespaces(self) -> List[str]:
        """List all namespaces in the cluster"""
        self._check_connection()
        namespaces = self.v1.list_namespace()
        return [ns.metadata.name for ns in namespaces.items]
    
    def list_pods(self, namespace="default") -> List[Dict[str, Any]]:
        """
        List all pods in a namespace
        
        Args:
            namespace: Kubernetes namespace
            
        Returns:
            List of pod information
        """
        self._check_connection()
        pods = self.v1.list_namespaced_pod(namespace)
        return [
            {
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "status": pod.status.phase,
                "containers": [
                    {
                        "name": container.name,
                        "image": container.image,
                    }
                    for container in pod.spec.containers
                ]
            }
            for pod in pods.items
        ]
    
    def list_deployments(self, namespace="default") -> List[Dict[str, Any]]:
        """
        List all deployments in a namespace
        
        Args:
            namespace: Kubernetes namespace
            
        Returns:
            List of deployment information
        """
        self._check_connection()
        deployments = self.apps_v1.list_namespaced_deployment(namespace)
        return [
            {
                "name": dep.metadata.name,
                "namespace": dep.metadata.namespace,
                "replicas": dep.spec.replicas,
                "containers": [
                    {
                        "name": container.name,
                        "image": container.image,
                    }
                    for container in dep.spec.template.spec.containers
                ]
            }
            for dep in deployments.items
        ]
    
    def get_pod_images(self, namespace="default") -> Dict[str, List[str]]:
        """
        Get all container images used by pods in a namespace
        
        Args:
            namespace: Kubernetes namespace
            
        Returns:
            Dictionary mapping pod names to lists of image names
        """
        self._check_connection()
        pods = self.v1.list_namespaced_pod(namespace)
        return {
            pod.metadata.name: [
                container.image
                for container in pod.spec.containers
            ]
            for pod in pods.items
        }
    
    def get_all_images(self, namespace="default") -> List[str]:
        """
        Get all unique container images used in a namespace
        
        Args:
            namespace: Kubernetes namespace
            
        Returns:
            List of unique image names
        """
        self._check_connection()
        pods = self.v1.list_namespaced_pod(namespace)
        images = set()
        
        for pod in pods.items:
            for container in pod.spec.containers:
                images.add(container.image)
        
        return list(images)
