"""
Security Analysis Agent with LangGraph

A modern security analysis tool that implements a multi-agent system for comprehensive security analysis.
"""

import os
import json
import re
import logging
from typing import Dict, List, Any, TypedDict, Annotated, Sequence, Optional, Tuple
from datetime import datetime
import argparse
from dotenv import load_dotenv
from openai import OpenAI
from langgraph.graph import StateGraph, END
import whois
import socket
import yaml
import csv
import ipaddress
import requests
import dns.resolver

# Load environment variables
load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# File handler - always log INFO and above to file
file_handler = logging.FileHandler('security_agent.log')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Console handler - only show WARNING and above by default
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)
console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# Prevent propagation to root logger
logger.propagate = False

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Define state types
class AgentState(TypedDict):
    query: str
    query_type: str
    entities: Dict[str, Any]
    tool_results: Dict[str, Any]
    error: Optional[str]
    needs_tool_retry: Optional[bool]
    tool_retry_count: Optional[int]
    max_retries_reached: Optional[bool]
    final_output: Optional[str]

class GuardrailConfig(TypedDict):
    name: str
    description: str
    patterns: List[Dict[str, str]]

# Load tools configuration from CSV
def load_tools_config() -> Dict[str, Dict[str, Any]]:
    """Load tools configuration from CSV file."""
    tools_config = {}
    try:
        with open("config/tools.csv", "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                tools_config[row["tool_name"]] = {
                    "name": row["tool_name"],
                    "description": row["description"],
                    "input_types": row["input_types"].split(";"),
                    "prompt": row["prompt"],
                    "api_key": os.getenv(row["api_key_env"]),
                    "base_url": row["base_url"]
                }
    except FileNotFoundError:
        logger.error(
            "tools.csv",
            None,
            "error",
            {"error": "Tools configuration file not found"}
        )
        raise
    return tools_config

# Security tools configuration
SECURITY_TOOLS = load_tools_config()

# Expert agent configurations
EXPERT_AGENTS = {
    "supervisor": {
        "name": "Supervisor Agent",
        "description": "Cloud Security and Cyber Security subject matter expert",
        "system_prompt": """You are a Cloud Security and Cyber Security subject matter expert.
        Your role is to:
        1. Analyze and classify security-related queries
        2. Validate input against security guardrails
        3. Coordinate tool selection and execution
        4. Ensure output meets security standards
        5. Provide comprehensive security analysis
        
        You must:
        - Reject non-security related queries
        - Ensure all queries are properly classified
        - Coordinate with tool experts
        - Validate and enhance final output"""
    },
    "tools_expert": {
        "name": "Tools Expert Agent",
        "description": "Security tools selection and coordination expert",
        "system_prompt": """You are a Security Tools Expert.
        Your role is to:
        1. Select appropriate tools based on query classification
        2. Coordinate tool execution
        3. Collect and validate tool outputs
        4. Ensure comprehensive data collection
        
        You must:
        - Select the most relevant tools
        - Handle tool execution errors
        - Ensure complete data collection
        - Coordinate with tool-specific experts"""
    },
    "output_expert": {
        "name": "Output Format Expert",
        "description": "Security analysis output formatting expert",
        "system_prompt": """You are an Output Format Expert.
        Your role is to:
        1. Format tool outputs for clarity
        2. Ensure comprehensive analysis
        3. Highlight key security findings
        4. Maintain security standards
        
        You must:
        - Present information clearly
        - Highlight critical findings
        - Maintain security context
        - Ensure complete analysis"""
    }
}

def load_guardrails() -> Tuple[List[GuardrailConfig], List[GuardrailConfig]]:
    """Load guardrail configurations from YAML file."""
    try:
        config_path = os.path.join(os.path.dirname(__file__), "config", "rails_config.yaml")
        if not os.path.exists(config_path):
            # Return default guardrails if config file doesn't exist
            default_input_guardrails = [
                GuardrailConfig(
                    name="length",
                    description="Query length validation",
                    patterns=[{"min": "3", "max": "500"}]
                ),
                GuardrailConfig(
                    name="regex",
                    description="Query character validation",
                    patterns=[{"pattern": r'^[a-zA-Z0-9\s\.,\?\-_]+$'}]
                )
            ]
            default_output_guardrails = [
                GuardrailConfig(
                    name="regex",
                    description="Output character validation",
                    patterns=[{"pattern": r'^[a-zA-Z0-9\s\.,\?\-_]+$'}]
                )
            ]
            return default_input_guardrails, default_output_guardrails
            
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        # Convert dictionary guardrails to GuardrailConfig objects
        input_guardrails = []
        for guardrail in config.get("input_guardrails", []):
            if isinstance(guardrail, dict):
                input_guardrails.append(GuardrailConfig(**guardrail))
            else:
                input_guardrails.append(guardrail)
                
        output_guardrails = []
        for guardrail in config.get("output_guardrails", []):
            if isinstance(guardrail, dict):
                output_guardrails.append(GuardrailConfig(**guardrail))
            else:
                output_guardrails.append(guardrail)
                
        return input_guardrails, output_guardrails
    except Exception as e:
        logger.error(f"Error loading guardrails: {str(e)}")
        raise

def debug_log(state: AgentState, agent: str, action: str, data: Any = None) -> None:
    """Log debug information if debug mode is enabled."""
    if state.get("debug_mode", False):
        print(f"\n{'='*80}")
        print(f"🔍 {agent} - {action}")
        print(f"{'='*80}")
        if data:
            if isinstance(data, dict):
                print(json.dumps(data, indent=2))
            else:
                print(str(data))
        print(f"{'='*80}\n")

def classify_query(state: Dict[str, Any]) -> Dict[str, Any]:
    """Classify the type of security query."""
    try:
        query = state.get("query", "")
        logger.info(f"Classifying query: {query}")
        
        # Simple classification based on keywords
        query_lower = query.lower()
        if any(word in query_lower for word in ["ip", "address", "location", "where"]):
            state["query_type"] = "ip_analysis"
        elif any(word in query_lower for word in ["domain", "dns", "whois"]):
            state["query_type"] = "domain_analysis"
        else:
            state["query_type"] = "general_security"
            
        logger.info("Query classification complete.")
        return state
        
    except Exception as e:
        logger.error(f"Error in classify_query: {str(e)}")
        state["error"] = f"Query classification error: {str(e)}"
        return state

# Load prompts
def load_prompts() -> Dict[str, Dict[str, str]]:
    """Load prompts from JSON file."""
    try:
        config_path = os.path.join(os.path.dirname(__file__), "config", "prompts.json")
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Prompts configuration file not found at {config_path}")
            
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading prompts: {str(e)}")
        raise

prompts = load_prompts()

def format_classifier_prompt(query: str, prompts: Dict) -> str:
    """Format the classifier prompt using the loaded prompts."""
    try:
        classifier = prompts.get("classifier", {})
        if not classifier:
            return ""
            
        # Build the system message
        system_message = """You are a security query classifier. Your ONLY task is to determine if a query is security-related.
You MUST respond with EXACTLY 'true' or 'false', nothing else.
Do not explain your reasoning.
Do not add any additional text.
Just respond with 'true' or 'false'."""
            
        # Build the prompt sections
        sections = [
            system_message,
            f"\nQuery: {query}",
            "\nA query is security-related if it:",
            *[f"- {criteria}" for criteria in classifier.get("security_criteria", [])],
            "\nA query is NOT security-related if it:",
            *[f"- {criteria}" for criteria in classifier.get("non_security_criteria", [])],
            "\nExamples of security-related queries:",
            *[f"- \"{example}\"" for example in classifier.get("examples", {}).get("security", [])],
            "\nExamples of non-security queries:",
            *[f"- \"{example}\"" for example in classifier.get("examples", {}).get("non_security", [])],
            "\nYour response must be EXACTLY 'true' or 'false':"
        ]
        
        return "\n".join(sections)
        
    except Exception as e:
        return ""

def format_supervisor_prompt(state: AgentState, prompts: Dict) -> str:
    """Format the supervisor prompt using the loaded prompts."""
    supervisor = prompts.get("supervisor", {})
    
    # Build the prompt sections
    sections = [
        supervisor.get("role", ""),
        f"\nAnalysis Results: {state.get('analysis_results', 'No results available')}",
        f"\n{prompts.get('classifier', {}).get('response_format', '')}",
        "\nPlease structure your response with the following sections:",
        *[f"- {section}: {description}" for section, description in supervisor.get("sections", {}).items()],
        "\nFormat your response according to these guidelines:",
        *[f"- {key}: {value}" for key, value in supervisor.get("formatting", {}).items()],
        "\nResponse:"
    ]
    
    return "\n".join(sections)

def is_security_query(query: str) -> bool:
    """Fallback function to determine if a query is security-related."""
    security_indicators = [
        "ip", "domain", "dns", "whois", "security", "network", "threat",
        "vulnerability", "malware", "attack", "breach", "exploit", "firewall",
        "router", "switch", "gateway", "proxy", "vpn", "ssl", "tls", "certificate",
        "encryption", "hash", "password", "authentication", "authorization",
        "access", "permission", "role", "user", "account", "login", "session",
        "token", "key", "credential", "secret", "private", "public", "asn",
        "isp", "organization", "company", "provider", "hosting", "cloud",
        "server", "service", "application", "app", "website", "web", "http",
        "https", "api", "endpoint", "port", "protocol", "tcp", "udp", "icmp",
        "dns", "mx", "spf", "dmarc", "caa", "txt", "a", "aaaa", "cname",
        "ns", "soa", "srv", "ptr", "reverse", "forward", "lookup", "resolve",
        "query", "response", "request", "header", "body", "content", "data",
        "packet", "frame", "segment", "datagram", "message", "stream", "flow",
        "traffic", "bandwidth", "throughput", "latency", "delay", "jitter",
        "packet loss", "error", "drop", "filter", "block", "allow", "deny",
        "accept", "reject", "forward", "redirect", "proxy", "cache", "store",
        "save", "load", "read", "write", "update", "delete", "remove", "add",
        "insert", "modify", "change", "set", "get", "post", "put", "delete",
        "patch", "head", "options", "trace", "connect", "status", "code",
        "error", "success", "failure", "warning", "info", "debug", "log",
        "audit", "monitor", "watch", "observe", "track", "trace", "follow",
        "pursue", "investigate", "examine", "inspect", "check", "verify",
        "validate", "confirm", "test", "probe", "scan", "sweep", "crawl",
        "spider", "bot", "agent", "client", "server", "peer", "node", "host",
        "endpoint", "device", "system", "platform", "environment", "context",
        "scope", "domain", "realm", "zone", "region", "area", "space",
        "location", "position", "coordinate", "address", "route", "path",
        "way", "direction", "vector", "point", "line", "plane", "space",
        "volume", "area", "region", "zone", "domain", "realm", "scope",
        "context", "environment", "platform", "system", "device", "host",
        "node", "peer", "server", "client", "agent", "bot", "spider",
        "crawler", "scanner", "probe", "test", "verify", "validate",
        "confirm", "check", "inspect", "examine", "investigate", "pursue",
        "follow", "trace", "track", "observe", "watch", "monitor", "audit",
        "log", "debug", "info", "warning", "error", "failure", "success",
        "code", "status", "connect", "trace", "options", "head", "patch",
        "delete", "put", "post", "get", "set", "change", "modify", "insert",
        "add", "remove", "delete", "update", "write", "read", "load", "save",
        "store", "cache", "proxy", "redirect", "forward", "reject", "deny",
        "allow", "filter", "block", "drop", "error", "loss", "jitter",
        "delay", "latency", "throughput", "bandwidth", "traffic", "flow",
        "stream", "message", "datagram", "segment", "frame", "packet",
        "data", "content", "body", "header", "request", "response", "query",
        "resolve", "lookup", "forward", "reverse", "ptr", "srv", "soa", "ns",
        "cname", "aaaa", "a", "txt", "caa", "dmarc", "spf", "mx", "dns",
        "icmp", "udp", "tcp", "protocol", "port", "endpoint", "api", "web",
        "website", "app", "application", "service", "server", "hosting",
        "cloud", "provider", "company", "organization", "isp", "asn", "public",
        "private", "secret", "credential", "key", "token", "session", "login",
        "account", "user", "role", "permission", "access", "authorization",
        "authentication", "password", "hash", "encryption", "certificate",
        "tls", "ssl", "vpn", "proxy", "gateway", "switch", "router",
        "firewall", "exploit", "breach", "attack", "malware", "threat",
        "vulnerability", "port", "network", "server", "host", "where",
        "location", "geolocation", "whois", "dns", "domain", "ip", "find",
        "lookup", "investigate", "scan", "check", "analyze", "security"
    ]
    
    query_lower = query.lower()
    return any(indicator in query_lower for indicator in security_indicators)

def validate_input(state: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the input query."""
    try:
        query = state.get("query", "").strip()
        logger.info(f"Validating input: {query}")
        
        if not query:
            state["error"] = "Query cannot be empty"
            return state
            
        if len(query) > 500:
            state["error"] = "Query is too long (max 500 characters)"
            return state
            
        logger.info("Input validation complete.")
        return state
        
    except Exception as e:
        logger.error(f"Error in validate_input: {str(e)}")
        state["error"] = f"Input validation error: {str(e)}"
        return state

# Logging wrappers for workflow steps
def validate_input_with_log(state: dict) -> dict:
    logger.info("Validating input...")
    try:
        result = validate_input(state)
        logger.info("Input validation complete.")
        return result
    except Exception as e:
        logger.error(f"Error during input validation: {e}")
        state["error"] = str(e)
        return state

def classify_query_with_log(state: dict) -> dict:
    logger.info("Classifying query...")
    try:
        result = classify_query(state)
        logger.info("Query classification complete.")
        return result
    except Exception as e:
        logger.error(f"Error during query classification: {e}")
        state["error"] = str(e)
        return state

def extract_entities_with_log(state: dict) -> dict:
    logger.info("Extracting entities...")
    try:
        result = extract_entities(state)
        logger.info("Entity extraction complete.")
        return result
    except Exception as e:
        logger.error(f"Error during entity extraction: {e}")
        state["error"] = str(e)
        return state

def select_tools_with_log(state: dict) -> dict:
    logger.info("Selecting tools...")
    try:
        result = select_tools(state)
        logger.info("Tool selection complete.")
        return result
    except Exception as e:
        logger.error(f"Error during tool selection: {e}")
        state["error"] = str(e)
        return state

def execute_tools_with_log(state: dict) -> dict:
    logger.info("Executing tools...")
    try:
        result = execute_tools(state)
        logger.info("Tool execution complete.")
        return result
    except Exception as e:
        logger.error(f"Error during tool execution: {e}")
        state["error"] = str(e)
        return state

def format_output_with_log(state: dict) -> dict:
    logger.info("Formatting output...")
    try:
        result = format_output(state)
        logger.info("Output formatting complete.")
        return result
    except Exception as e:
        logger.error(f"Error during output formatting: {e}")
        state["error"] = str(e)
        return state

def validate_output(state: AgentState) -> AgentState:
    """Validate output completeness and trigger additional tool execution if needed."""
    try:
        # If max retries reached, proceed to formatting
        if state.get("max_retries_reached", False):
            state["needs_tool_retry"] = False
            return state
            
        # Get query intent
        query_intent = state.get("query_type", "general_analysis")
        entities = state.get("entities", {})
        tool_results = state.get("tool_results", {})
        
        # Check if we need to run more tools
        needs_more_tools = False
        missing_tools = []
        
        for entity_id, entity_data in entities.items():
            entity_type = entity_data.get("type", "")
            if entity_type == "internet:ip":
                if query_intent in ["ip_analysis", "general_analysis"]:
                    required_tools = ["geolocation", "abuseipdb", "shodan", "virustotal"]
                    for tool in required_tools:
                        result_key = f"{entity_id}_{tool}"
                        if result_key not in tool_results or not tool_results[result_key].get("success", False):
                            needs_more_tools = True
                            missing_tools.append(tool)
            elif entity_type == "internet:domain":
                if query_intent in ["domain_analysis", "general_analysis"]:
                    required_tools = ["whois_lookup", "dns_analysis"]
                    for tool in required_tools:
                        result_key = f"{entity_id}_{tool}"
                        if result_key not in tool_results or not tool_results[result_key].get("success", False):
                            needs_more_tools = True
                            missing_tools.append(tool)
        
        # If we need more tools and haven't exceeded retry limit
        if needs_more_tools:
            if "tool_retry_count" not in state:
                state["tool_retry_count"] = 0
                
            if state["tool_retry_count"] < 3:  # Maximum 3 retries
                state["tool_retry_count"] += 1
                state["needs_tool_retry"] = True
                state["error"] = f"Attempt {state['tool_retry_count']} of 3 to retrieve missing data: {', '.join(missing_tools)}"
            else:
                state["error"] = f"Maximum retry attempts reached. Missing data for: {', '.join(missing_tools)}"
                state["needs_tool_retry"] = False
                state["max_retries_reached"] = True
        else:
            state["needs_tool_retry"] = False
            state["error"] = None  # Clear any previous errors
            
        return state
        
    except Exception as e:
        state["error"] = f"Error in output validation: {str(e)}"
        state["needs_tool_retry"] = False
        state["max_retries_reached"] = True
        return state

def execute_tool(tool_name: str, entities: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a specific tool based on its name."""
    try:
        if tool_name == "whois_lookup":
            return whois_lookup(entities)
        elif tool_name == "geolocation":
            return geolocate_ip(entities)
        elif tool_name == "dns_analysis":
            return dns_lookup(entities)
        elif tool_name == "abuseipdb":
            return abuseipdb_lookup(entities)
        elif tool_name == "shodan":
            return shodan_lookup(entities)
        elif tool_name == "virustotal":
            return virustotal_lookup(entities)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    except Exception as e:
        return {"success": False, "error": str(e)}

def select_tools(query_type: str, entities: Dict[str, Any]) -> List[str]:
    """Select appropriate tools based on query type and entities."""
    tools = []
    
    # Add tools based on query type
    if query_type in ["security_posture_ip", "security_posture_domain", "security_posture_fqdn"]:
        tools.extend(["whois_lookup", "dns_analysis", "geolocation", "abuseipdb", "shodan", "virustotal"])
    elif query_type in ["geolocation_ip"]:
        tools.extend(["geolocation", "dns_analysis"])
    elif query_type in ["ownership_network", "ownership_domain"]:
        tools.extend(["whois_lookup", "dns_analysis"])
    
    # Remove duplicate tools
    return list(set(tools))

def log_agent_action(
    agent: str,
    action: str,
    input_data: Dict[str, Any],
    output: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    debug_only: bool = False
) -> None:
    """Log agent actions in a standardized format."""
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "agent": agent,
        "action": action,
        "user": "rick",  # Default user as specified
        "input": input_data,
        "output": output,
        "error": error
    }
    
    # Always write to file
    logger.info(json.dumps(log_entry))
    
    # Print to console only if debug mode is enabled
    if debug_only and logger.level == logging.DEBUG:
        print(f"\n{agent} - {action}:")
        print(f"Input: {json.dumps(input_data, indent=2)}")
        if output:
            print(f"Output: {json.dumps(output, indent=2)}")
        if error:
            print(f"Error: {error}")

def whois_lookup(entities: Dict[str, Any]) -> Dict[str, Any]:
    """Get WHOIS information for a domain or IP using IPAPI."""
    try:
        entity = next(iter(entities.values()))
        entity_type = entity.get("type", "")
        entity_value = entity.get("value", "")
        
        logger.info(f"Performing WHOIS lookup for {entity_type}: {entity_value}")
        
        # Get API key from environment
        api_key = os.getenv("IPAPI_API_KEY")
        if not api_key:
            return {
                "success": True,
                "data": {
                    "error": "IPAPI API key not configured",
                    "raw_data": None
                }
            }
        
        # Prepare headers and endpoint
        headers = {
            'Accept': 'application/json'
        }
        
        # Add access_key as query parameter
        params = {
            'access_key': api_key
        }
        
        # Determine endpoint based on entity type
        if entity_type in ["internet:ip", "IP"]:
            endpoint = f'https://api.ipapi.com/api/{entity_value}'
        elif entity_type in ["internet:domain", "internet:fqdn", "Domain", "FQDN"]:
            endpoint = f'https://api.ipapi.com/api/{entity_value}'
        else:
            return {
                "success": True,
                "data": {
                    "error": f"Unsupported entity type for WHOIS: {entity_type}",
                    "raw_data": None
                }
            }
        
        # Make API request
        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            whois_data = response.json()
            logger.info(f"WHOIS data retrieved: {whois_data}")
            
            if entity_type in ["internet:domain", "internet:fqdn", "Domain", "FQDN"]:
                return {
                    "success": True,
                    "data": {
                        "registrar": whois_data.get("connection", {}).get("organization_type"),
                        "creation_date": whois_data.get("created"),
                        "expiration_date": whois_data.get("expires"),
                        "name_servers": whois_data.get("nameservers", []),
                        "status": whois_data.get("status", []),
                        "registrant": whois_data.get("connection", {}).get("organization"),
                        "admin_email": whois_data.get("admin", {}).get("email"),
                        "tech_email": whois_data.get("tech", {}).get("email")
                    }
                }
            elif entity_type in ["internet:ip", "IP"]:
                connection = whois_data.get("connection", {})
                security = whois_data.get("security", {})
                
                return {
                    "success": True,
                    "data": {
                        "owner": connection.get("organization"),
                        "asn": connection.get("asn"),
                        "hostname": whois_data.get("hostname"),
                        "city": whois_data.get("city"),
                        "region": whois_data.get("region_name"),
                        "country": whois_data.get("country_name"),
                        "loc": f"{whois_data.get('latitude')},{whois_data.get('longitude')}",
                        "postal": whois_data.get("zip"),
                        "timezone": whois_data.get("time_zone", {}).get("id"),
                        "isp": connection.get("isp"),
                        "organization_type": connection.get("organization_type"),
                        "security": {
                            "is_proxy": security.get("is_proxy"),
                            "is_tor": security.get("is_tor"),
                            "threat_level": security.get("threat_level"),
                            "threat_types": security.get("threat_types")
                        }
                    }
                }
                
        except requests.exceptions.Timeout:
            logger.error("WHOIS API request timed out")
            return {
                "success": True,
                "data": {
                    "error": "WHOIS lookup timed out",
                    "raw_data": None
                }
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Error in WHOIS API request: {str(e)}")
            return {
                "success": True,
                "data": {
                    "error": f"WHOIS lookup failed: {str(e)}",
                    "raw_data": None
                }
            }
            
    except Exception as e:
        logger.error(f"Error in WHOIS lookup: {str(e)}")
        return {
            "success": True,
            "data": {
                "error": f"WHOIS lookup failed: {str(e)}",
                "raw_data": None
            }
        }

def geolocate_ip(entities: Dict[str, Any]) -> Dict[str, Any]:
    """Get geolocation information for an IP address."""
    try:
        entity = next(iter(entities.values()))
        if entity.get("type") not in ["internet:ip", "IP"]:
            return {"success": False, "error": "Geolocation only works with IP addresses"}
            
        ip = entity.get("value")
        logger.info(f"Performing geolocation lookup for IP: {ip}")
        
        # Use ip-api.com for geolocation (free tier)
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "success": True,
                    "data": {
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as"),
                        "timezone": data.get("timezone")
                    }
                }
            else:
                return {"success": False, "error": data.get("message", "Unknown error")}
        else:
            return {"success": False, "error": f"HTTP error: {response.status_code}"}
            
    except Exception as e:
        logger.error(f"Error in geolocation lookup: {str(e)}")
        return {"success": False, "error": str(e)}

def dns_lookup(entities: Dict[str, Any]) -> Dict[str, Any]:
    """Perform DNS lookup for domain or IP."""
    try:
        entity = next(iter(entities.values()))
        entity_type = entity.get("type", "")
        entity_value = entity.get("value", "")
        
        logger.info(f"Performing DNS lookup for {entity_type}: {entity_value}")
        
        if entity_type in ["internet:domain", "internet:fqdn", "Domain", "FQDN"]:
            dns_data = {}
            
            # A records
            try:
                a_records = dns.resolver.resolve(entity_value, 'A')
                dns_data['a'] = [str(r) for r in a_records]
            except Exception as e:
                logger.warning(f"No A records found: {str(e)}")
                dns_data['a'] = []
            
            # AAAA records
            try:
                aaaa_records = dns.resolver.resolve(entity_value, 'AAAA')
                dns_data['aaaa'] = [str(r) for r in aaaa_records]
            except Exception as e:
                logger.warning(f"No AAAA records found: {str(e)}")
                dns_data['aaaa'] = []
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(entity_value, 'MX')
                dns_data['mx'] = [str(r.exchange) for r in mx_records]
            except Exception as e:
                logger.warning(f"No MX records found: {str(e)}")
                dns_data['mx'] = []
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(entity_value, 'NS')
                dns_data['ns'] = [str(r) for r in ns_records]
            except Exception as e:
                logger.warning(f"No NS records found: {str(e)}")
                dns_data['ns'] = []
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(entity_value, 'TXT')
                dns_data['txt'] = [str(r) for r in txt_records]
            except Exception as e:
                logger.warning(f"No TXT records found: {str(e)}")
                dns_data['txt'] = []
            
            return {
                "success": True,
                "data": dns_data
            }
            
        elif entity_type in ["internet:ip", "IP"]:
            try:
                ptr_records = dns.resolver.resolve_address(entity_value)
                return {
                    "success": True,
                    "data": {
                        "ptr": [str(r) for r in ptr_records]
                    }
                }
            except Exception as e:
                logger.warning(f"No PTR records found: {str(e)}")
                return {
                    "success": True,
                    "data": {
                        "ptr": []
                    }
                }
        else:
            return {"success": False, "error": f"Unsupported entity type for DNS: {entity_type}"}
            
    except Exception as e:
        logger.error(f"Error in DNS lookup: {str(e)}")
        return {"success": False, "error": str(e)}

def abuseipdb_lookup(entities: Dict[str, Any]) -> Dict[str, Any]:
    """Query AbuseIPDB for IP information."""
    try:
        entity = next(iter(entities.values()))
        if entity.get("type") not in ["internet:ip", "IP"]:
            return {"success": False, "error": "AbuseIPDB only works with IP addresses"}
            
        ip = entity.get("value")
        logger.info(f"Performing AbuseIPDB lookup for IP: {ip}")
        
        # Get API key from environment
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return {"success": False, "error": "AbuseIPDB API key not configured"}
        
        # Query AbuseIPDB API
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
        }
        response = requests.get(
            f'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params={'ipAddress': ip, 'maxAgeInDays': '90'}
        )
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                "success": True,
                "data": {
                    "abuse_confidence_score": data.get('abuseConfidenceScore'),
                    "total_reports": data.get('totalReports'),
                    "last_reported_at": data.get('lastReportedAt'),
                    "country_code": data.get('countryCode'),
                    "usage_type": data.get('usageType'),
                    "domain": data.get('domain')
                }
            }
        else:
            return {"success": False, "error": f"HTTP error: {response.status_code}"}
            
    except Exception as e:
        logger.error(f"Error in AbuseIPDB lookup: {str(e)}")
        return {"success": False, "error": str(e)}

def shodan_lookup(entities: Dict[str, Any]) -> Dict[str, Any]:
    """Query Shodan for IP or domain information."""
    try:
        entity = next(iter(entities.values()))
        entity_type = entity.get("type", "")
        entity_value = entity.get("value", "")
        
        logger.info(f"Performing Shodan lookup for {entity_type}: {entity_value}")
        
        # Get API key from environment
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return {"success": False, "error": "Shodan API key not configured"}
        
        # Query Shodan API
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        
        if entity_type in ["internet:ip", "IP"]:
            response = requests.get(
                f'https://api.shodan.io/shodan/host/{entity_value}',
                headers=headers
            )
        else:
            response = requests.get(
                f'https://api.shodan.io/shodan/domain/{entity_value}',
                headers=headers
            )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "success": True,
                "data": {
                    "ports": data.get('ports', []),
                    "hostnames": data.get('hostnames', []),
                    "os": data.get('os'),
                    "org": data.get('org'),
                    "isp": data.get('isp'),
                    "last_update": data.get('last_update'),
                    "vulns": data.get('vulns', [])
                }
            }
        else:
            return {"success": False, "error": f"HTTP error: {response.status_code}"}
            
    except Exception as e:
        logger.error(f"Error in Shodan lookup: {str(e)}")
        return {"success": False, "error": str(e)}

def virustotal_lookup(entities: Dict[str, Any]) -> Dict[str, Any]:
    """Query VirusTotal for IP or domain information."""
    try:
        entity = next(iter(entities.values()))
        entity_type = entity.get("type", "")
        entity_value = entity.get("value", "")
        
        logger.info(f"Performing VirusTotal lookup for {entity_type}: {entity_value}")
        
        # Get API key from environment
        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            return {"success": False, "error": "VirusTotal API key not configured"}
        
        # Query VirusTotal API
        headers = {
            'x-apikey': api_key
        }
        
        if entity_type in ["internet:ip", "IP"]:
            endpoint = f'https://www.virustotal.com/api/v3/ip_addresses/{entity_value}'
        else:
            endpoint = f'https://www.virustotal.com/api/v3/domains/{entity_value}'
            
        response = requests.get(endpoint, headers=headers)
        
        if response.status_code == 200:
            data = response.json().get('data', {}).get('attributes', {})
            return {
                "success": True,
                "data": {
                    "last_analysis_stats": data.get('last_analysis_stats', {}),
                    "categories": data.get('categories', []),
                    "last_analysis_date": data.get('last_analysis_date'),
                    "reputation": data.get('reputation'),
                    "tags": data.get('tags', [])
                }
            }
        else:
            return {"success": False, "error": f"HTTP error: {response.status_code}"}
            
    except Exception as e:
        logger.error(f"Error in VirusTotal lookup: {str(e)}")
        return {"success": False, "error": str(e)}

def format_output(query: str, query_type: str, tool_results: Dict[str, Any]) -> Dict[str, Any]:
    """Format tool results into a comprehensive security analysis."""
    try:
        # Get the output formatter prompt
        output_formatter_prompt = prompts["output_formatter"]
        
        # Format the prompt with the query and tool results
        formatted_prompt = output_formatter_prompt["user"].format(
            query=query,
            query_type=query_type,
            tool_results=json.dumps(tool_results, indent=2)
        )
        
        # Get the response from the model
        response = call_openai(
            system_prompt=output_formatter_prompt["system"],
            user_prompt=formatted_prompt
        )
        
        # Parse the response as JSON
        try:
            result = json.loads(response)
            if "formatted_output" not in result:
                raise ValueError("Response missing 'formatted_output' key")
            return result
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse output formatter response as JSON: {str(e)}")
            logger.error(f"Raw response: {response}")
            # Try to extract the formatted output from the response
            if "formatted_output" in response:
                return {"formatted_output": response.split('"formatted_output":')[1].strip(' "{}')}
            raise ValueError(f"Invalid JSON response from output formatter: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error in output formatter: {str(e)}")
        raise

def extract_entities(state: Dict[str, Any]) -> Dict[str, Any]:
    """Extract entities from the query."""
    try:
        query = state.get("query", "")
        logger.info(f"Extracting entities from query: {query}")
        
        entities = {}
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.finditer(ip_pattern, query)
        for match in ip_matches:
            ip = match.group()
            try:
                ipaddress.ip_address(ip)
                entities[ip] = {
                    "type": "internet:ip",
                    "value": ip
                }
                logger.info(f"Extracted IP address: {ip}")
            except ValueError:
                continue
        
        # Extract domains - improved pattern to better handle domain names
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        domain_matches = re.finditer(domain_pattern, query)
        for match in domain_matches:
            domain = match.group().lower()  # Convert to lowercase
            # Clean up the domain (remove any trailing punctuation)
            domain = domain.rstrip('.,;:!?')
            entities[domain] = {
                "type": "internet:domain",
                "value": domain
            }
            logger.info(f"Extracted domain: {domain}")
        
        state["entities"] = entities
        logger.info(f"Extracted entities: {entities}")
        logger.info("Entity extraction complete.")
        return state
        
    except Exception as e:
        logger.error(f"Error in extract_entities: {str(e)}")
        state["error"] = f"Entity extraction error: {str(e)}"
        return state

def call_openai(system_prompt: str, user_prompt: str) -> str:
    """Call OpenAI API with the given prompts."""
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3,
            max_tokens=2000,
            top_p=0.95,
            frequency_penalty=0.0,
            presence_penalty=0.0
        )
        return response.choices[0].message.content
    except Exception as e:
        raise Exception(f"Error calling OpenAI API: {str(e)}")

def parse_llm_response(response: str) -> Dict[str, Any]:
    """Parse the LLM response into a structured format."""
    try:
        # Try to parse as JSON
        return json.loads(response)
    except json.JSONDecodeError:
        # If not JSON, try to extract JSON from text
        try:
            # Look for JSON-like structure in the text
            json_str = re.search(r'\{.*\}', response, re.DOTALL)
            if json_str:
                return json.loads(json_str.group())
            else:
                raise Exception("No valid JSON found in response")
        except Exception as e:
            raise Exception(f"Error parsing LLM response: {str(e)}")

def supervisor_node(state: AgentState) -> AgentState:
    """Supervisor node that validates input and manages the workflow."""
    try:
        # Log input
        log_agent_action(
            agent="supervisor",
            action="start",
            input_data={"query": state["query"]},
            debug_only=True
        )
        
        # First, check if it's a security-related query
        security_check = call_openai(
            system_prompt="""You are a security query classifier. Your task is to determine if a query is security-related.
A query is security-related if it involves:
- Network security
- Domain/IP analysis
- Security threats
- Vulnerabilities
- Security posture
- Security ownership
- Security incidents
- Security tools or services

Respond with a JSON object containing:
{
    "valid_cs_question": true/false,
    "reason": "explanation if false"
}""",
            user_prompt=f"Query: {state['query']}\nIs this a security-related query? Respond with JSON only."
        )
        
        try:
            security_result = json.loads(security_check)
            if not security_result.get("valid_cs_question", False):
                state["error"] = security_result.get("reason", "Not a security-related query")
                state["final_output"] = state["error"]
                state["query_type"] = ""  # Clear query type to trigger early exit
                return state
        except json.JSONDecodeError:
            logger.error(f"Failed to parse security check response: {security_check}")
            state["error"] = "Failed to validate query"
            state["final_output"] = state["error"]
            state["query_type"] = ""  # Clear query type to trigger early exit
            return state
        
        # If it's a security query, proceed with classification
        classification_result = call_openai(
            system_prompt=prompts["classifier"]["system"],
            user_prompt=prompts["classifier"]["user"].format(query=state["query"])
        )
        
        try:
            validation_result = json.loads(classification_result)
            state["query_type"] = validation_result.get("search_classification", "general_security")
            entities = validation_result.get("entities", {})
            
            # Normalize entity types
            for entity_id, entity_data in entities.items():
                entity_type = entity_data.get("type", "").lower()
                if entity_type == "domain":
                    entity_data["type"] = "internet:domain"
                elif entity_type == "ip":
                    entity_data["type"] = "internet:ip"
                elif entity_type == "fqdn":
                    entity_data["type"] = "internet:fqdn"
            
            state["entities"] = entities
            
            log_agent_action(
                agent="supervisor",
                action="complete",
                input_data={"query": state["query"]},
                output=validation_result,
                debug_only=True
            )
            
            return state
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse classification response: {classification_result}")
            state["error"] = "Failed to classify query"
            state["final_output"] = state["error"]
            state["query_type"] = ""  # Clear query type to trigger early exit
            return state
        
    except Exception as e:
        error_msg = f"Error in supervisor: {str(e)}"
        log_agent_action(
            agent="supervisor",
            action="error",
            input_data={"query": state["query"]},
            error=error_msg,
            debug_only=True
        )
        state["error"] = error_msg
        state["final_output"] = error_msg
        state["query_type"] = ""  # Clear query type to trigger early exit
        return state

def tools_expert_node(state: AgentState) -> AgentState:
    """Tools expert node that selects and executes appropriate tools."""
    try:
        log_agent_action(
            agent="tools_expert",
            action="start",
            input_data={"query": state["query"], "query_type": state["query_type"]},
            debug_only=True
        )
        
        # Select tools based on query type and entities
        selected_tools = select_tools(state["query_type"], state["entities"])
        
        # Execute tools
        tool_results = {}
        for tool in selected_tools:
            try:
                result = execute_tool(tool, state["entities"])
                tool_results[f"{tool}"] = result
            except Exception as e:
                tool_results[f"{tool}"] = {"success": False, "error": str(e)}
        
        state["tool_results"] = tool_results
        
        log_agent_action(
            agent="tools_expert",
            action="complete",
            input_data={"query": state["query"], "query_type": state["query_type"]},
            output=tool_results,
            debug_only=True
        )
        
        return state
        
    except Exception as e:
        error_msg = f"Error in tools expert: {str(e)}"
        log_agent_action(
            agent="tools_expert",
            action="error",
            input_data={"query": state["query"]},
            error=error_msg,
            debug_only=True
        )
        state["error"] = error_msg
        return state

def output_format_node(state: AgentState) -> AgentState:
    """Output format node that formats the final response."""
    try:
        log_agent_action(
            agent="output_formatter",
            action="start",
            input_data={"query": state["query"], "tool_results": state["tool_results"]},
            debug_only=True
        )
        
        # If there's an error or no query type, return the error message directly
        if state.get("error"):
            state["final_output"] = state["error"]
            log_agent_action(
                agent="output_formatter",
                action="complete",
                input_data={"query": state["query"]},
                output={"formatted_output": state["error"]},
                debug_only=True
            )
            return state
            
        # If no tools were run (non-security query), return a clear message
        if not state.get("query_type"):
            state["final_output"] = "This query is not security-related and cannot be processed by the security analysis tools."
            log_agent_action(
                agent="output_formatter",
                action="complete",
                input_data={"query": state["query"]},
                output={"formatted_output": state["final_output"]},
                debug_only=True
            )
            return state
        
        # Format output for security queries
        result = format_output(state["query"], state["query_type"], state["tool_results"])
        
        state["final_output"] = result.get("formatted_output", "Error formatting output")
        
        log_agent_action(
            agent="output_formatter",
            action="complete",
            input_data={"query": state["query"]},
            output=result,
            debug_only=True
        )
        
        return state
        
    except Exception as e:
        error_msg = f"Error in output formatter: {str(e)}"
        log_agent_action(
            agent="output_formatter",
            action="error",
            input_data={"query": state["query"]},
            error=error_msg,
            debug_only=True
        )
        state["error"] = error_msg
        state["final_output"] = error_msg
        return state

def create_graph() -> StateGraph:
    """Create the LangGraph workflow."""
    # Create the workflow
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("tools_expert", tools_expert_node)
    workflow.add_node("output_format", output_format_node)
    
    # Add conditional routing
    def should_continue(state: AgentState) -> str:
        """Determine the next node based on state."""
        if state.get("error"):
            return "output_format"
        if not state.get("query_type"):
            return "output_format"
        return "tools_expert"
    
    # Add edges with conditional routing
    workflow.add_conditional_edges(
        "supervisor",
        should_continue,
        {
            "tools_expert": "tools_expert",
            "output_format": "output_format"
        }
    )
    workflow.add_edge("tools_expert", "output_format")
    workflow.add_edge("output_format", END)
    
    # Set entry point
    workflow.set_entry_point("supervisor")
    
    return workflow

def main():
    """Main function to run the security agent."""
    parser = argparse.ArgumentParser(description="Security Analysis Agent")
    parser.add_argument("query", help="The query to analyze")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    
    # Set debug level if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        # Update console handler to show DEBUG level
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.DEBUG)
    
    # Create initial state
    initial_state = {
        "query": args.query,
        "query_type": "",
        "entities": {},
        "tool_results": {},
        "error": None,
        "needs_tool_retry": False,
        "tool_retry_count": 0,
        "max_retries_reached": False,
        "final_output": None,
        "debug_mode": args.debug
    }
    
    # Create and run the graph
    graph = create_graph()
    app = graph.compile()
    
    # Run the graph
    result = app.invoke(initial_state)
    
    # Print results
    if args.debug:
        print("\nDebug Information:")
        print(f"Query Type: {result['query_type']}")
        print(f"Entities: {json.dumps(result['entities'], indent=2)}")
        print(f"Tool Results: {json.dumps(result['tool_results'], indent=2)}")
        if result.get("error"):
            print(f"Error: {result['error']}")
    
    # Always print final output
    print("\nFinal Output:")
    print(result["final_output"])

if __name__ == "__main__":
    main() 