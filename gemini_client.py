"""
Google Gemini client for different model interactions.
"""

import os
import json
import logging
import base64
import time
from typing import Dict, Any, Optional
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)

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

def load_tools() -> Dict[str, Dict[str, Any]]:
    """Load security tools configuration from JSON file."""
    try:
        config_path = os.path.join(os.path.dirname(__file__), "config", "tools.json")
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Tools configuration file not found at {config_path}")
            
        with open(config_path, "r") as f:
            return json.load(f)["security_tools"]
    except Exception as e:
        logger.error(f"Error loading tools configuration: {str(e)}")
        raise

class TokenManager:
    """Manages OAuth token lifecycle and refresh."""
    
    def __init__(self):
        """Initialize the token manager."""
        self.token = None
        self.token_expiry = 0
        self.token_url = "https://apigw-dev.internal.rickonsecurity.com/oauth/token"
        self.consumer_key = os.getenv("APIGW_CONSUMER_KEY")
        self.consumer_secret = os.getenv("APIGW_CONSUMER_SECRET")
        
        if not self.consumer_key or not self.consumer_secret:
            raise ValueError("APIGW_CONSUMER_KEY and APIGW_CONSUMER_SECRET must be set")
        
        # Create base64 encoded credentials
        credentials = f"{self.consumer_key}:{self.consumer_secret}"
        self.basic_auth = base64.b64encode(credentials.encode()).decode()
    
    def get_token(self) -> str:
        """Get a valid OAuth token, refreshing if necessary."""
        current_time = time.time()
        
        # If token is expired or doesn't exist, get a new one
        if not self.token or current_time >= self.token_expiry:
            self._refresh_token()
        
        return self.token
    
    def _refresh_token(self) -> None:
        """Refresh the OAuth token."""
        try:
            headers = {
                "Authorization": f"Basic {self.basic_auth}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "grant_type": "client_credentials"
            }
            
            response = requests.post(
                self.token_url,
                headers=headers,
                json=payload
            )
            
            response.raise_for_status()
            token_data = response.json()
            
            self.token = token_data["access_token"]
            # Set expiry to 5 minutes before actual expiry to ensure we refresh early
            self.token_expiry = time.time() + token_data.get("expires_in", 3600) - 300
            
            logger.info("Successfully refreshed OAuth token")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to refresh OAuth token: {str(e)}")
            raise

class GeminiClient:
    """Client for interacting with different Gemini models through API gateway."""
    
    def __init__(self):
        """Initialize the Gemini client with API gateway configuration."""
        # API Gateway configuration
        self.api_gateway_url = "https://apigw-dev.internal.rickonsecurity.com/analytics/aiml/chat/v1/search"
        
        # Initialize token manager
        self.token_manager = TokenManager()
        
        # Required headers (excluding Authorization which will be added dynamically)
        self.headers = {
            "x-rv-client-id": os.getenv("RV_CLIENT_ID"),
            "x-rv-api-key": os.getenv("RV_API_KEY"),
            "x-rv-usecase-id": "testing",
            "Content-Type": "application/json"
        }
        
        # Load prompts and tools
        self.prompts = load_prompts()
        self.tools = load_tools()
        
        # Validate required environment variables
        self._validate_config()
    
    def _validate_config(self):
        """Validate that all required environment variables are set."""
        required_vars = [
            "RV_CLIENT_ID",
            "RV_API_KEY",
            "APIGW_CONSUMER_KEY",
            "APIGW_CONSUMER_SECRET"
        ]
        
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    def _make_request(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """Make a request to the API gateway with OAuth token handling."""
        max_retries = 2
        retry_count = 0
        
        while retry_count <= max_retries:
            try:
                # Get fresh token for each request
                headers = self.headers.copy()
                headers["Authorization"] = f"Bearer {self.token_manager.get_token()}"
                
                payload = {
                    "prompt": prompt,
                    "model": "gemini-2.5-flash-preview-04-17"
                }
                
                if system_prompt:
                    payload["system_prompt"] = system_prompt
                
                response = requests.post(
                    self.api_gateway_url,
                    headers=headers,
                    json=payload
                )
                
                # If unauthorized, refresh token and retry
                if response.status_code == 401 and retry_count < max_retries:
                    logger.warning("Token expired, refreshing and retrying...")
                    self.token_manager._refresh_token()
                    retry_count += 1
                    continue
                
                response.raise_for_status()
                return response.json()
                
            except requests.exceptions.RequestException as e:
                if retry_count == max_retries:
                    logger.error(f"API Gateway request failed after {max_retries} retries: {str(e)}")
                    raise
                retry_count += 1
                continue
    
    def classify_query(self, query: str) -> Dict[str, Any]:
        """Classify a security query using the classification model."""
        try:
            gemini_prompts = self.prompts["gemini"]["classifier"]
            system_prompt = gemini_prompts["system"]
            user_prompt = gemini_prompts["user"].format(query=query)
            
            response = self._make_request(user_prompt, system_prompt)
            return self._extract_json_from_response(response.get("text", ""))
            
        except Exception as e:
            logger.error(f"Error in query classification: {str(e)}")
            return {
                "valid_cs_question": False,
                "reason": f"Classification error: {str(e)}"
            }
    
    def analyze_security(self, query: str, tool_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security data using the analysis model."""
        try:
            gemini_prompts = self.prompts["gemini"]["analyzer"]
            system_prompt = gemini_prompts["system"]
            user_prompt = gemini_prompts["user"].format(
                query=query,
                tool_results=json.dumps(tool_results, indent=2)
            )
            
            response = self._make_request(user_prompt, system_prompt)
            return {
                "formatted_output": response.get("text", "")
            }
            
        except Exception as e:
            logger.error(f"Error in security analysis: {str(e)}")
            return {
                "formatted_output": f"Error in security analysis: {str(e)}"
            }
    
    def format_output(self, query: str, analysis: Dict[str, Any]) -> str:
        """Format the final output using the analysis model."""
        try:
            gemini_prompts = self.prompts["gemini"]["formatter"]
            system_prompt = gemini_prompts["system"]
            user_prompt = gemini_prompts["user"].format(
                query=query,
                analysis=json.dumps(analysis, indent=2)
            )
            
            response = self._make_request(user_prompt, system_prompt)
            return response.get("text", "")
            
        except Exception as e:
            logger.error(f"Error in output formatting: {str(e)}")
            return f"Error in output formatting: {str(e)}"
    
    def _extract_json_from_response(self, response_text: str) -> Dict[str, Any]:
        """Extract JSON from response text."""
        try:
            # Try to find JSON in the response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx == -1 or end_idx == 0:
                logger.error(f"No JSON found in response: {response_text}")
                return {}
            
            json_str = response_text[start_idx:end_idx]
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from response: {response_text}")
            logger.error(f"JSON decode error: {str(e)}")
            return {} 