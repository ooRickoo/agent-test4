"""
Mock Internal Resource Graph (IRG) Client for testing.
"""

import json
import ipaddress
from typing import Dict, Any, Optional
import requests
from datetime import datetime, timedelta

class MockIRGClient:
    """Mock client for Internal Resource Graph API."""
    
    def __init__(self, config_path: str = "config/internal_resources.json"):
        """Initialize the mock client with configuration."""
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        # Generate mock data
        self.mock_data = self._generate_mock_data()
    
    def _generate_mock_data(self) -> Dict[str, Any]:
        """Generate mock data for testing."""
        return {
            "ips": {
                "192.168.100.10": {
                    "type": "internal:ip",
                    "hostname": "server1.internal.rickonsecurity.com",
                    "owner": "Infrastructure Team",
                    "department": "IT",
                    "last_seen": (datetime.now() - timedelta(hours=2)).isoformat(),
                    "services": ["http", "ssh", "dns"],
                    "os": "Ubuntu 22.04 LTS",
                    "tags": ["production", "critical"]
                }
            },
            "domains": {
                "app.internal.rickonsecurity.com": {
                    "type": "internal:domain",
                    "ip": "192.168.100.20",
                    "owner": "Application Team",
                    "department": "Engineering",
                    "last_seen": (datetime.now() - timedelta(hours=1)).isoformat(),
                    "services": ["https", "api"],
                    "tags": ["production", "web"]
                }
            },
            "cloud_resources": {
                "azure": {
                    "app1.azure.internal.rickonsecurity.com": {
                        "type": "publiccloud:azure",
                        "resource_id": "/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Web/sites/app1",
                        "owner": "Cloud Team",
                        "department": "Platform",
                        "last_seen": datetime.now().isoformat(),
                        "services": ["https", "api"],
                        "tags": ["production", "azure"]
                    }
                },
                "gcp": {
                    "app1.gcp.internal.rickonsecurity.com": {
                        "type": "publiccloud:gcp",
                        "resource_id": "projects/rickonsecurity/instances/app1",
                        "owner": "Cloud Team",
                        "department": "Platform",
                        "last_seen": datetime.now().isoformat(),
                        "services": ["https", "api"],
                        "tags": ["production", "gcp"]
                    }
                }
            }
        }
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if an IP is in internal network ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.config["internal_networks"]:
                if ip_obj in ipaddress.ip_network(network):
                    return True
            return False
        except ValueError:
            return False
    
    def _is_internal_domain(self, domain: str) -> bool:
        """Check if a domain is internal."""
        domain = domain.lower()
        for pattern in self.config["internal_domains"]:
            if pattern.replace("*", "") in domain:
                return True
        return False
    
    def _get_cloud_provider(self, domain: str) -> Optional[str]:
        """Get cloud provider from domain."""
        domain = domain.lower()
        for provider, pattern in self.config["cloud_domains"].items():
            if pattern.replace("*", "") in domain:
                return provider
        return None
    
    def query_resource(self, resource_type: str, resource_id: str) -> Dict[str, Any]:
        """Query a resource from the mock IRG."""
        try:
            if resource_type == "internal:ip":
                if self._is_internal_ip(resource_id):
                    return self.mock_data["ips"].get(resource_id, {
                        "type": "internal:ip",
                        "error": "Resource not found in IRG"
                    })
            
            elif resource_type == "internal:domain":
                if self._is_internal_domain(resource_id):
                    return self.mock_data["domains"].get(resource_id, {
                        "type": "internal:domain",
                        "error": "Resource not found in IRG"
                    })
            
            elif resource_type.startswith("publiccloud:"):
                provider = resource_type.split(":")[1]
                if provider in self.mock_data["cloud_resources"]:
                    return self.mock_data["cloud_resources"][provider].get(resource_id, {
                        "type": f"publiccloud:{provider}",
                        "error": "Resource not found in IRG"
                    })
            
            return {
                "type": resource_type,
                "error": "Invalid resource type or not found in IRG"
            }
            
        except Exception as e:
            return {
                "type": resource_type,
                "error": f"Error querying IRG: {str(e)}"
            }
    
    def get_resource_type(self, resource_id: str) -> Optional[str]:
        """Determine the resource type based on the resource ID."""
        if self._is_internal_ip(resource_id):
            return "internal:ip"
        
        if self._is_internal_domain(resource_id):
            cloud_provider = self._get_cloud_provider(resource_id)
            if cloud_provider:
                return f"publiccloud:{cloud_provider}"
            return "internal:domain"
        
        return None 