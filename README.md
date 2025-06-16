# Security Analysis Agent with LangGraph

A modern security analysis tool that implements a multi-agent system for comprehensive security analysis.

## Features

- Multi-agent architecture using LangGraph
- Support for internal and cloud resources
- Integration with Google Gemini for LLM operations
- Comprehensive security analysis tools
- Input/output validation and guardrails
- Configurable prompts and tool settings

## Configuration

The agent uses several configuration files in the `config` directory:

### 1. Prompts and Tools Configuration (`prompts.json`)

Contains all prompts and tool configurations in a single JSON file:
- Classifier prompts
- Gemini-specific prompts
- Tool configurations (WHOIS, DNS, Shodan, etc.)
- Output formatting rules

Example structure:
```json
{
  "classifier": { ... },
  "gemini": {
    "classifier": { ... },
    "analyzer": { ... },
    "formatter": { ... }
  },
  "tools": {
    "whois_analysis": { ... },
    "dns_analysis": { ... },
    ...
  }
}
```

### 2. Validation Rules (`validation_rules.yaml`)

Defines input/output validation rules and guardrails:
- Sensitive data detection
- Malicious command prevention
- Output sanitization

### 3. Internal Resources (`internal_resources.json`)

Defines patterns for internal and cloud resources:
- Internal domain patterns
- Cloud provider patterns
- Resource classification rules

## Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd security-agent-langgraph
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables in `.env`:
   ```
   GOOGLE_API_KEY=your_google_api_key
   RV_CLIENT_ID=your_service_api_id
   RV_API_KEY=your_service_api_key
   APIGW_CONSUMER_KEY=your_api_gateway_key
   APIGW_CONSUMER_SECRET=your_api_gateway_secret
   SHODAN_API_KEY=your_shodan_api_key
   WHOIS_API_KEY=your_whois_api_key
   IPGEO_API_KEY=your_ipgeo_api_key
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```

## Usage

Run the agent with a security query:
```bash
python security_agent_langgraph.py "Analyze the security of example.com"
```

### Example Queries

1. Internal Resource Analysis:
   ```bash
   python security_agent_langgraph.py "Analyze app1.azure.internal.rickonsecurity.com"
   ```

2. Cloud Resource Analysis:
   ```bash
   python security_agent_langgraph.py "Check security of s3-bucket.rickonsecurity.com"
   ```

3. Internet Resource Analysis:
   ```bash
   python security_agent_langgraph.py "Analyze 8.8.8.8"
   ```

## Architecture

### Agent Components

1. **Supervisor Agent**
   - Validates and classifies queries
   - Manages resource classification
   - Coordinates tool execution
   - Ensures output quality

2. **Tools Expert**
   - Selects appropriate tools
   - Executes security analysis tools
   - Handles tool-specific logic

3. **Output Formatter**
   - Formats analysis results
   - Generates comprehensive reports
   - Ensures consistent output style

### Resource Classification

Resources are classified in the following hierarchy:
1. Internal Resources
   - Matches internal domain patterns
   - Uses IRG for validation
2. Cloud Resources
   - Matches cloud provider patterns
   - Validates against cloud metadata
3. Internet Resources
   - All other resources
   - Standard security analysis

## Development

### Adding New Tools

1. Add tool configuration to `config/prompts.json`:
   ```json
   "tools": {
     "new_tool": {
       "name": "new_tool",
       "description": "Tool description",
       "input_types": ["internet:ip", "internet:domain"],
       "prompt": "Tool-specific prompt",
       "api_key_env": "NEW_TOOL_API_KEY",
       "base_url": "https://api.newtool.com/v1",
       "output_format": [...]
     }
   }
   ```

2. Implement tool function in `security_agent_langgraph.py`
3. Add tool to the tools expert node

### Modifying Prompts

Edit the appropriate section in `config/prompts.json`:
- `classifier`: Query classification prompts
- `gemini`: Gemini-specific prompts
- `tools`: Tool-specific prompts
- `output_formatter`: Output formatting rules

## Acknowledgments

- [Google Gemini](https://ai.google.dev/)
- [LangChain](https://github.com/langchain-ai/langchain)
- [Shodan](https://www.shodan.io/)

## Project Structure

```
.
├── config/
│   ├── input_guardrails.yaml    # Input validation rules
│   └── output_guardrails.yaml   # Output sanitization rules
├── security_agent_langgraph.py  # Main implementation
├── requirements.txt             # Dependencies
└── README.md                    # This file
```

## Workflow

The agent follows a three-step workflow:

1. **Input Analysis** (`analyze_input`):
   - Validates input using NeMo Guardrails
   - Extracts target (IP or domain)
   - Prevents malicious commands and sensitive data

2. **Security Analysis** (`perform_analysis`):
   - Performs WHOIS lookup
   - Analyzes DNS records
   - Checks SSL certificates
   - Queries Shodan for vulnerabilities
   - Sanitizes output using NeMo Guardrails

3. **Response Generation** (`generate_response`):
   - Generates comprehensive security report
   - Provides actionable recommendations
   - Ensures no sensitive data in output

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set up environment variables in `.env`:
   ```
   GOOGLE_API_KEY=your_google_api_key
   SHODAN_API_KEY=your_shodan_api_key
   ```

3. Run the agent:
   ```bash
   python security_agent_langgraph.py
   ```

## Usage

The agent accepts security queries about IP addresses or domains:

```
Enter your security query: Analyze the security of example.com
```

The agent will:
1. Validate the input
2. Extract the target
3. Perform security analysis
4. Generate a report with recommendations

## Guardrails Configuration

The agent uses two YAML configuration files for guardrails:

1. `config/input_guardrails.yaml`: Defines input validation rules
   - Prevents sharing of sensitive information
   - Blocks malicious commands
   - Validates input format

2. `config/output_guardrails.yaml`: Defines output sanitization rules
   - Removes sensitive information
   - Sanitizes output format
   - Ensures secure response

## Acknowledgments

- [Google Gemini](https://ai.google.dev/)
- [LangChain](https://github.com/langchain-ai/langchain)
- [Shodan](https://www.shodan.io/) 

## Example Queries

### Network Security Analysis
```
Analyze the security posture of IP 185.199.108.153
```
This will reveal GitHub Pages infrastructure and its security characteristics.

```
What are the security implications of IP 104.18.32.1?
```
This will show Cloudflare infrastructure details and associated security measures.

### Domain Analysis
```
Investigate the security status of microsoft.com and its associated infrastructure
```
This will provide comprehensive analysis of Microsoft's domain security, including:
- DNS configuration
- Email security (MX records)
- CDN usage
- Security headers

```
Analyze the security posture of paypal.com and identify potential vulnerabilities
```
This will examine PayPal's security infrastructure, focusing on:
- SSL/TLS configuration
- Domain reputation
- Associated IP ranges
- Security headers and configurations

### Advanced Threat Analysis
```
What is the threat intelligence for IP 45.95.147.0/24?
```
This will analyze a known malicious IP range, showing:
- Historical abuse data
- Associated malware
- Known attack patterns
- Current threat status

```
Investigate the security implications of domain ns1.cybercriminals.com
```
This will analyze a potentially malicious domain, including:
- DNS infrastructure
- Associated IP addresses
- Historical threat data
- Current threat status

### Infrastructure Analysis
```
Analyze the security of AWS infrastructure at IP 52.95.116.0/24
```
This will examine AWS infrastructure security, including:
- Service identification
- Security configurations
- Associated services
- Best practices compliance

```
What are the security characteristics of Google's infrastructure at 142.250.0.0/16?
```
This will provide detailed analysis of Google's network security, including:
- Service identification
- Security measures
- Associated domains
- Infrastructure patterns

## Development Setup

### Prerequisites
- Python 3.9+
- Git
- Virtual environment tool (venv, conda, etc.)
- Code editor (VS Code recommended)
- API keys for security services

### Development Environment Setup

1. Clone and setup:
```bash
git clone <repository-url>
cd <repository-directory>
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. VS Code Setup (Recommended):
   - Install Python extension
   - Install Pylance for better type checking
   - Configure settings.json:
   ```json
   {
       "python.analysis.typeCheckingMode": "basic",
       "python.linting.enabled": true,
       "python.linting.pylintEnabled": true
   }
   ```

3. Development Workflow:
   - Create feature branches from main
   - Follow PEP 8 style guide
   - Write docstrings for all functions
   - Update tests for new features
   - Update documentation

4. Code Structure:
   ```
   security_agent_langgraph/
   ├── config/
   │   ├── tools.csv           # Tool configurations
   │   └── guardrails_config.yaml  # Security rules
   ├── security_agent_langgraph.py  # Main agent code
   ├── requirements.txt        # Dependencies
   └── README.md              # Documentation
   ```

5. Testing:
   - Run the agent: `python security_agent_langgraph.py`
   - Test with example queries
   - Check logs for debugging
   - Verify tool outputs

### Adding New Tools

1. Update `config/tools.csv`:
   ```csv
   tool_name,description,input_types,prompt,api_key_env,base_url
   new_tool,Description of new tool,internet-ip;internet-domain,Prompt for the tool,NEW_TOOL_API_KEY,https://api.newtool.com
   ```

2. Implement tool function in `security_agent_langgraph.py`:
   ```python
   def perform_new_tool_analysis(entity: str) -> Dict[str, Any]:
       # Implementation
       pass
   ```

3. Update tool selection logic in `select_tools()`

4. Add API key to `.env`:
   ```
   NEW_TOOL_API_KEY=your_api_key
   ```

# Gemini Client Implementation

A Python client for interacting with Google's Gemini models through an API gateway, implementing OpenAI-compatible chat completion features.

## Features

- OpenAI-compatible chat completion interface
- Streaming response support
- Function calling capabilities
- Comprehensive parameter control
- OAuth token management
- Robust error handling and retries

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
# API Gateway Configuration
export APIGW_CONSUMER_KEY="your-consumer-key"
export APIGW_CONSUMER_SECRET="your-consumer-secret"
export RV_CLIENT_ID="your-client-id"
export RV_API_KEY="your-api-key"
```

## Usage

### Basic Usage

```python
from gemini_client import GeminiClient

# Initialize client
client = GeminiClient()

# Simple query classification
result = client.classify_query("What is the status of my security?")

# Security analysis with tool results
analysis = client.analyze_security(
    query="Analyze security logs",
    tool_results={
        "log_analyzer": {
            "results": "Log analysis results..."
        }
    }
)

# Format output
formatted_output = client.format_output(
    query="Format security report",
    analysis=analysis
)
```

### Streaming Responses

```python
# Stream classification results
for chunk in client.classify_query(
    "What is the status of my security?",
    stream=True
):
    print(chunk)

# Stream security analysis
for chunk in client.analyze_security(
    query="Analyze security logs",
    tool_results={},
    stream=True
):
    print(chunk)
```

### Function Calling

```python
# Define functions
functions = [
    {
        "name": "get_security_status",
        "description": "Get the current security status",
        "parameters": {
            "type": "object",
            "properties": {
                "system": {
                    "type": "string",
                    "description": "System to check"
                }
            }
        }
    }
]

# Use function calling
response = client.analyze_security(
    "Check security status",
    tool_results={},
    functions=functions,
    function_call="auto"
)
```

### Advanced Parameters

```python
response = client.format_output(
    query="Format security report",
    analysis={},
    temperature=0.8,          # Control randomness (0.0 to 1.0)
    max_tokens=1000,         # Maximum tokens to generate
    top_p=0.9,              # Nucleus sampling parameter
    frequency_penalty=0.5,   # Penalize frequent tokens
    presence_penalty=0.5,    # Penalize new tokens
    stop=["\n\n", "END"]     # Stop sequences
)
```

## Configuration

### Message Roles

The client supports the following message roles:
- `system`: System instructions
- `user`: User messages
- `assistant`: Model responses
- `function`: Function call results
- `tool`: Tool execution results

### Environment Variables

Required environment variables:
- `APIGW_CONSUMER_KEY`: API Gateway consumer key
- `APIGW_CONSUMER_SECRET`: API Gateway consumer secret
- `RV_CLIENT_ID`: Client ID for the API
- `RV_API_KEY`: API key for authentication

## Error Handling

The client includes comprehensive error handling:
- Automatic token refresh
- Request retries for failed calls
- Detailed error logging
- Streaming error recovery

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[Your License Here]
