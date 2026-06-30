# Installation Guide

Complete installation guide for the Security Assessment Workflow system.

## Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **Python**: 3.10 or higher
- **RAM**: Minimum 8GB (16GB recommended)
- **Disk Space**: 20GB free space
- **Network**: Internet connection for API access and tool downloads

### Required Accounts
- Anthropic API key (for Claude AI)
- NVD API key (optional, for CVE lookups)
- Shodan API key (optional)

## Step 1: System Dependencies

### Ubuntu/Debian
```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Python and development tools
sudo apt-get install -y python3.10 python3-pip python3-venv git

# Install Nmap
sudo apt-get install -y nmap

# Install additional security tools
sudo apt-get install -y gobuster hping3 nikto sqlmap

# Install WafWoof
pip3 install wafw00f
```

### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.10

# Install Nmap
brew install nmap

# Install additional tools
brew install gobuster
pip3 install wafw00f
```

## Step 2: Install OWASP ZAP

### Linux
```bash
cd /opt
sudo wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
sudo tar -xvf ZAP_2.14.0_Linux.tar.gz
sudo ln -s /opt/ZAP_2.14.0/zap.sh /usr/local/bin/zap

# Start ZAP in daemon mode
zap -daemon -port 8080 -config api.key=your-api-key-here
```

### macOS
```bash
brew install --cask owasp-zap

# Or download from: https://www.zaproxy.org/download/
```

## Step 3: Install Metasploit Framework

### Linux (Ubuntu/Debian)
```bash
# Download and run installer
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Initialize Metasploit database
msfdb init

# Start Metasploit RPC server
msfrpcd -P your-password -S -a 127.0.0.1
```

### macOS
```bash
# Install via Homebrew
brew install metasploit

# Initialize database
msfdb init

# Start RPC server
msfrpcd -P your-password -S -a 127.0.0.1
```

## Step 4: Clone and Setup Project

```bash
# Clone repository
git clone <repository-url>
cd security-assessment-workflow

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

## Step 5: Configuration

### Create Configuration File
```bash
# Copy example config
cp config/config.example.yaml config/config.yaml

# Edit configuration
nano config/config.yaml  # or use your preferred editor
```

### Required Configuration Changes

1. **API Keys**:
```yaml
api:
  anthropic_api_key: "sk-ant-your-key-here"

vulnerability_databases:
  nvd:
    api_key: "your-nvd-api-key"
  shodan:
    api_key: "your-shodan-api-key"
```

2. **Tool Paths** (adjust if needed):
```yaml
tools:
  nmap:
    path: "/usr/bin/nmap"
  zap:
    api_key: "your-zap-api-key"
    proxy_host: "localhost"
    proxy_port: 8080
  metasploit:
    password: "your-msf-password"
```

3. **Safety Settings**:
```yaml
safety:
  require_authorization: true
  authorization_file: "config/authorization.txt"
  auto_exploit: false  # IMPORTANT: Keep false unless in controlled environment
```

### Create Authorization File
```bash
# Create authorization file for targets you're allowed to test
echo "192.168.1.100" > config/authorization.txt
echo "testlab.example.com" >> config/authorization.txt
```

## Step 6: Verify Installation

### Test Individual Components

```bash
# Test Nmap wrapper
python src/tools/nmap_wrapper.py 127.0.0.1

# Test CVE lookup
python src/utils/cve_lookup.py

# Test exploit search
python src/utils/exploit_search.py
```

### Test Workflow Engine

```bash
# Run a quick scan (safe, no exploitation)
python src/orchestrator/workflow_engine.py --target 127.0.0.1 --mode quick
```

## Step 7: Start MCP Servers (Optional)

If you want to use MCP protocol for tool integration:

```bash
# Terminal 1: Start Nmap MCP server
python src/mcp_servers/nmap_server.py

# Terminal 2: Start ZAP MCP server
python src/mcp_servers/zap_server.py

# Terminal 3: Start Metasploit MCP server
python src/mcp_servers/metasploit_server.py
```

## Step 8: Database Setup (Optional)

For storing scan results:

```bash
# Create SQLite database
mkdir -p data
python -c "import sqlite3; sqlite3.connect('data/security_assessment.db').close()"
```

## Troubleshooting

### Common Issues

#### 1. Import Errors
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

#### 2. Nmap Permission Issues
```bash
# Run with sudo or add capabilities
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

#### 3. ZAP Connection Issues
```bash
# Check if ZAP is running
ps aux | grep zap

# Restart ZAP in daemon mode
zap -daemon -port 8080 -config api.key=your-api-key
```

#### 4. Metasploit RPC Issues
```bash
# Check if msfrpcd is running
ps aux | grep msfrpcd

# Restart RPC server
msfrpcd -P your-password -S -a 127.0.0.1 -p 55553
```

#### 5. API Rate Limiting
```bash
# For NVD API without key, add delays
# Edit config.yaml:
vulnerability_databases:
  nvd:
    rate_limit_delay: 6  # seconds between requests
```

## Security Considerations

### ⚠️ IMPORTANT WARNINGS

1. **Authorization**: ALWAYS obtain written permission before testing any system
2. **Legal Compliance**: Ensure compliance with local laws and regulations
3. **Controlled Environment**: Use in isolated lab environments when possible
4. **Data Protection**: Secure all scan results and credentials
5. **Responsible Disclosure**: Follow responsible disclosure practices for findings

### Recommended Lab Setup

```bash
# Use Docker for safe testing environment
docker run -d --name metasploitable nopesec/metasploitable2
docker run -d --name dvwa vulnerables/web-dvwa
```

## Post-Installation

### Create Test Targets File
```bash
cat > config/test_targets.txt << EOF
# Safe test targets (localhost only)
127.0.0.1
localhost
EOF
```

### Run First Scan
```bash
# Activate virtual environment
source venv/bin/activate

# Run quick scan on localhost
python src/orchestrator/workflow_engine.py \
  --target 127.0.0.1 \
  --mode quick \
  --config config/config.yaml

# Check results
ls -la reports/
```

## Updating

```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Update security tools
sudo apt-get update && sudo apt-get upgrade nmap
```

## Uninstallation

```bash
# Stop services
pkill -f msfrpcd
pkill -f zap

# Remove virtual environment
deactivate
rm -rf venv/

# Remove project (keep reports if needed)
cd ..
rm -rf security-assessment-workflow/
```

## Next Steps

1. Read the [User Guide](docs/user_guide.md)
2. Review [Security Best Practices](docs/security_practices.md)
3. Check [API Documentation](docs/api_reference.md)
4. Join the community discussions

## Support

- GitHub Issues: <repository-url>/issues
- Documentation: <repository-url>/docs
- Security Contact: security@example.com

## License

This project is licensed under the MIT License - see LICENSE file for details.