"""
Google Gemini client for different model interactions.
"""

import os
import json
import logging
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

class GeminiClient:
    """Client for interacting with different Gemini models through API gateway."""
    
    def __init__(self):
        """Initialize the Gemini client with API gateway configuration."""
        # API Gateway configuration
        self.api_gateway_url = "https://apigw-dev.internal.rickonsecurity.com/analytics/aiml/chat/v1/completion"
        
        # Required headers
        self.headers = {
            "x-rv-client-id": os.getenv("RV_CLIENT_ID"),
            "x-rv-api-key": os.getenv("RV_API_KEY"),
            "x-rv-usecase-id": "testing",
            "apigw_consumer_key": os.getenv("APIGW_CONSUMER_KEY"),
            "apigw_consumer_secret": os.getenv("APIGW_CONSUMER_SECRET"),
            "Content-Type": "application/json"
        }
        
        # Load prompts
        self.prompts = load_prompts()
        
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
        """Make a request to the API gateway."""
        try:
            payload = {
                "prompt": prompt,
                "model": "gemini-2.5-flash-preview-04-17"
            }
            
            if system_prompt:
                payload["system_prompt"] = system_prompt
            
            response = requests.post(
                self.api_gateway_url,
                headers=self.headers,
                json=payload
            )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API Gateway request failed: {str(e)}")
            raise
    
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