# Security Analysis Agent with LangGraph

A modern security analysis tool that implements a multi-agent system for comprehensive security analysis using LangGraph. This tool provides detailed security analysis of IP addresses and domains through various security APIs and tools, with support for both internal and external resources.

## Features

- Multi-agent system using LangGraph for orchestration
- Comprehensive security analysis of IPs and domains
- Support for internal and cloud resources:
  - Internal IPs and domains
  - Azure cloud resources
  - GCP cloud resources
  - AWS cloud resources
- Integration with multiple security APIs:
  - Internal Resource Graph (IRG) for internal/cloud resources
  - IPAPI for geolocation and WHOIS data
  - AbuseIPDB for abuse reports
  - Shodan for port scanning and service detection
  - VirusTotal for threat intelligence
  - DNS analysis for domain information
- Input validation and security guardrails
- Detailed logging and error handling
- Configurable prompts and tool selection

## Architecture

The system uses a multi-agent architecture with LangGraph:

1. **Supervisor Agent**: 
   - Validates input and manages the workflow
   - Classifies resources as internal, cloud, or internet
   - Uses pattern matching for resource classification
2. **Tools Expert Agent**: 
   - Selects and executes appropriate security tools
   - Routes internal/cloud resources to IRG
   - Routes internet resources to external APIs
3. **Output Format Agent**: 
   - Formats and presents the results

### Resource Classification

The supervisor agent classifies resources using the following hierarchy:

1. **Internal Resources**:
   - Internal IPs (e.g., 192.168.100.0/24)
   - Internal domains (e.g., *.internal.rickonsecurity.com)
2. **Cloud Resources**:
   - Azure resources (e.g., *.azure.internal.rickonsecurity.com)
   - GCP resources (e.g., *.gcp.internal.rickonsecurity.com)
   - AWS resources (e.g., *.aws.internal.rickonsecurity.com)
3. **Internet Resources**:
   - Public IPs
   - Public domains

### LangGraph Implementation

The workflow is implemented using LangGraph's StateGraph:

```python
workflow = StateGraph(AgentState)
workflow.add_node("supervisor", supervisor_node)
workflow.add_node("tools_expert", tools_expert_node)
workflow.add_node("output_format", output_format_node)
```

The graph uses conditional routing based on the state:
- If there's an error or invalid query → Output Format
- If valid security query → Tools Expert → Output Format

## Configuration

### Environment Variables

Required API keys:
```bash
export IPAPI_API_KEY=your_ipapi_key
export ABUSEIPDB_API_KEY=your_abuseipdb_key
export SHODAN_API_KEY=your_shodan_key
export VT_API_KEY=your_virustotal_key
```

### Resource Configuration

Internal and cloud resources are configured in `config/internal_resources.json`:
```json
{
  "internal_networks": [
    "192.168.100.0/24",
    "10.0.0.0/8"
  ],
  "internal_domains": [
    "*.internal.rickonsecurity.com"
  ],
  "cloud_domains": {
    "azure": "*.azure.internal.rickonsecurity.com",
    "gcp": "*.gcp.internal.rickonsecurity.com",
    "aws": "*.aws.internal.rickonsecurity.com"
  }
}
```

### Prompt Configuration

Prompts are stored in `config/prompts.json` and include:
- Classifier prompts for query validation
- Supervisor prompts for workflow management
- Output formatter prompts for result presentation

### Tool Configuration

Tools are configured in `config/tools.csv` with:
- Tool name and description
- Input types
- API endpoints
- Required API keys

## Input/Output Guardrails

### Input Validation
- Query length limits (3-500 characters)
- Character validation (alphanumeric, basic punctuation)
- Security query classification
- Entity extraction and validation

### Output Validation
- Structured output format
- Security context preservation
- Error handling and reporting
- Data sanitization

## Example Queries

The agent can handle various security analysis queries:

```bash
# Internal resource analysis
python security_agent_langgraph.py "Analyze the security of 192.168.100.10"
python security_agent_langgraph.py "Check the security status of app.internal.rickonsecurity.com"

# Cloud resource analysis
python security_agent_langgraph.py "Analyze the security of app1.azure.internal.rickonsecurity.com"
python security_agent_langgraph.py "Check the security status of app1.gcp.internal.rickonsecurity.com"

# Internet resource analysis
python security_agent_langgraph.py "Analyze the security of 8.8.8.8"
python security_agent_langgraph.py "What can you tell me about example.com"
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ooRickoo/agent-test4.git
cd agent-test4
```

2. Create and activate virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys
```

## Usage

Run the agent with a security query:
```bash
python security_agent_langgraph.py "Analyze the security of 8.8.8.8"
```

Enable debug output:
```bash
python security_agent_langgraph.py --debug "Analyze the security of 8.8.8.8"
```

## Project Structure

```
.
├── config/
│   ├── prompts.json     # LLM prompts configuration
│   └── tools.csv        # Security tools configuration
├── security_agent_langgraph.py  # Main agent implementation
├── requirements.txt     # Python dependencies
├── .env.example        # Example environment variables
└── README.md           # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - see LICENSE file for details

## Support

For issues and feature requests, please create an issue in the repository.

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
