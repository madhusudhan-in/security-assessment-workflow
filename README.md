# Security Assessment Workflow with GenAI

An enterprise-level security assessment automation framework using GenAI, MCP (Model Context Protocol), and integrated security tools.

## 🎯 Overview

This project provides an intelligent security assessment workflow that:
- Performs automated network reconnaissance using Nmap
- Discovers vulnerabilities and CVEs
- Attempts exploit validation
- Analyzes web application security with OWASP ZAP
- Integrates with Metasploit for exploit testing
- Runs additional security tools (Gobuster, Hping, WafWoof, etc.)
- Uses AI to orchestrate and analyze results

## 🏗️ Architecture

```
security-assessment-workflow/
├── src/
│   ├── mcp_servers/          # MCP server implementations
│   │   ├── nmap_server.py
│   │   ├── zap_server.py
│   │   ├── metasploit_server.py
│   │   └── tools_server.py
│   ├── skills/               # AI Skills for each tool
│   │   ├── nmap_skill.py
│   │   ├── zap_skill.py
│   │   ├── metasploit_skill.py
│   │   └── auxiliary_tools_skill.py
│   ├── orchestrator/         # AI orchestration layer
│   │   ├── workflow_engine.py
│   │   └── decision_maker.py
│   ├── utils/                # Utility functions
│   │   ├── cve_lookup.py
│   │   ├── exploit_search.py
│   │   └── report_generator.py
│   └── tools/                # Tool wrappers
│       ├── nmap_wrapper.py
│       ├── zap_wrapper.py
│       └── metasploit_wrapper.py
├── config/                   # Configuration files
├── reports/                  # Generated reports
├── logs/                     # Application logs
├── tests/                    # Unit and integration tests
└── docs/                     # Documentation

```

## 🔧 Prerequisites

### Required Tools
- Python 3.10+
- Nmap (with NSE scripts)
- OWASP ZAP
- Metasploit Framework
- Gobuster
- Hping3
- WafWoof
- Docker (optional, for containerized deployment)

### Python Dependencies
- anthropic (for Claude API)
- mcp (Model Context Protocol)
- python-nmap
- zaproxy
- pymetasploit3
- requests
- aiohttp
- pydantic

## 📦 Installation

### 1. Clone the repository
```bash
git clone <repository-url>
cd security-assessment-workflow
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Install security tools (Ubuntu/Debian)
```bash
# Nmap
sudo apt-get install nmap

# OWASP ZAP
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
tar -xvf ZAP_2.14.0_Linux.tar.gz

# Metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Additional tools
sudo apt-get install gobuster hping3
pip install wafw00f
```

### 4. Configure the application
```bash
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your settings
```

## 🚀 Usage

### Basic Workflow
```bash
python src/orchestrator/workflow_engine.py --target <target-ip-or-domain> --mode full
```

### Individual Tool Execution
```bash
# Nmap scan
python src/tools/nmap_wrapper.py --target 192.168.1.1

# ZAP scan
python src/tools/zap_wrapper.py --target http://example.com

# Metasploit
python src/tools/metasploit_wrapper.py --exploit <exploit-name> --target <target>
```

### MCP Server Mode
```bash
# Start MCP servers
python src/mcp_servers/nmap_server.py
python src/mcp_servers/zap_server.py
python src/mcp_servers/metasploit_server.py
```

## 🔐 Security & Ethics

**⚠️ IMPORTANT: This tool is for authorized security testing only!**

- Always obtain written permission before testing
- Use only in controlled environments
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Never use for malicious purposes

## 📊 Workflow Stages

### Stage 1: Reconnaissance
1. Nmap port scanning
2. Service version detection
3. OS fingerprinting
4. NSE script execution

### Stage 2: Vulnerability Assessment
1. CVE lookup for discovered services
2. Exploit database search
3. ZAP web vulnerability scanning
4. Custom vulnerability checks

### Stage 3: Exploitation (Controlled)
1. Metasploit exploit selection
2. Exploit validation
3. Proof-of-concept execution
4. Impact assessment

### Stage 4: Additional Testing
1. Directory brute-forcing (Gobuster)
2. WAF detection (WafWoof)
3. Network stress testing (Hping)
4. Custom tool execution

### Stage 5: Reporting
1. Result aggregation
2. Risk scoring
3. Remediation recommendations
4. Executive summary generation

## 🤖 AI Integration

The system uses GenAI for:
- Intelligent tool selection
- Result interpretation
- Attack chain planning
- Anomaly detection
- Report generation

## 📝 Configuration

Edit `config/config.yaml`:
```yaml
api:
  anthropic_api_key: "your-api-key"
  
tools:
  nmap:
    path: "/usr/bin/nmap"
    default_options: "-sV -sC"
  zap:
    api_key: "your-zap-api-key"
    proxy: "http://localhost:8080"
  metasploit:
    host: "localhost"
    port: 55553
    
workflow:
  max_concurrent_scans: 3
  timeout: 3600
  auto_exploit: false  # Set to true for automatic exploitation
```

## 🧪 Testing

```bash
# Run unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Run full test suite
pytest tests/
```

## 📚 Documentation

- [Architecture Guide](docs/architecture.md)
- [API Reference](docs/api_reference.md)
- [Tool Integration Guide](docs/tool_integration.md)
- [Security Best Practices](docs/security_practices.md)

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) first.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by this tool. Users must ensure they have proper authorization before conducting any security assessments.

## 🙏 Acknowledgments

- OWASP for ZAP
- Rapid7 for Metasploit
- Nmap Project
- Anthropic for Claude AI
- MCP Protocol contributors

## 📧 Contact

For questions or support, please open an issue on GitHub.