# Usage Guide

Comprehensive guide for using the Security Assessment Workflow system.

## Table of Contents
1. [Quick Start](#quick-start)
2. [Workflow Modes](#workflow-modes)
3. [Individual Tool Usage](#individual-tool-usage)
4. [Advanced Scenarios](#advanced-scenarios)
5. [AI-Powered Features](#ai-powered-features)
6. [Best Practices](#best-practices)

## Quick Start

### Basic Scan
```bash
# Activate virtual environment
source venv/bin/activate

# Run a quick reconnaissance scan
python src/orchestrator/workflow_engine.py \
  --target 192.168.1.100 \
  --mode quick

# View results
cat reports/workflow_*.json | jq '.'
```

### Full Assessment
```bash
# Complete security assessment (no exploitation)
python src/orchestrator/workflow_engine.py \
  --target example.com \
  --mode full \
  --config config/config.yaml
```

## Workflow Modes

### 1. Quick Mode
Fast reconnaissance and basic vulnerability detection.

```bash
python src/orchestrator/workflow_engine.py --target TARGET --mode quick
```

**What it does:**
- Fast port scan (top 1000 ports)
- Service version detection
- Basic NSE scripts
- CVE lookup for discovered services
- Quick risk assessment

**Duration:** 5-15 minutes

### 2. Full Mode (Recommended)
Comprehensive assessment without exploitation.

```bash
python src/orchestrator/workflow_engine.py --target TARGET --mode full
```

**What it does:**
- Complete port scan (all 65535 ports)
- Detailed service enumeration
- OS fingerprinting
- NSE vulnerability scripts
- CVE and exploit database search
- Web application scanning (if HTTP/HTTPS found)
- AI-powered analysis and recommendations

**Duration:** 30-60 minutes

### 3. Aggressive Mode
Most thorough assessment (requires authorization).

```bash
python src/orchestrator/workflow_engine.py --target TARGET --mode aggressive
```

**What it does:**
- Everything in Full mode
- Aggressive NSE scripts
- Brute force attempts (if configured)
- Exploit verification (check mode only)
- Deep web application testing

**Duration:** 1-3 hours

## Individual Tool Usage

### Nmap Wrapper

#### Quick Port Scan
```python
from tools.nmap_wrapper import NmapWrapper

nmap = NmapWrapper()
result = nmap.quick_scan("192.168.1.100")

print(f"Found {len(result.hosts[0].ports)} open ports")
for port in result.hosts[0].ports:
    print(f"  {port.port}/{port.protocol}: {port.service}")
```

#### Service Version Detection
```python
result = nmap.full_scan("192.168.1.100", ports="80,443,8080")

for host in result.hosts:
    for port in host.ports:
        print(f"Port {port.port}: {port.product} {port.version}")
```

#### Vulnerability Scanning
```python
result = nmap.vulnerability_scan("192.168.1.100")

for host in result.hosts:
    for script_name, script_output in host.scripts.items():
        print(f"\n{script_name}:")
        print(script_output)
```

#### Run Specific NSE Script
```python
# Check for MS17-010 (EternalBlue)
result = nmap.run_nse_script(
    target="192.168.1.100",
    script="smb-vuln-ms17-010",
    ports="445"
)
```

### CVE Lookup

#### Search by Product
```python
from utils.cve_lookup import CVELookup

cve_lookup = CVELookup(nvd_api_key="your-key")

# Find CVEs for Apache 2.4.49
cves = cve_lookup.search_by_product(
    vendor="apache",
    product="http_server",
    version="2.4.49"
)

for cve in cves:
    print(f"{cve.cve_id}: {cve.severity} (CVSS: {cve.cvss_score})")
    print(f"  {cve.description[:100]}...")
    if cve.exploits_available:
        print(f"  ⚠️  Exploits available!")
```

#### Search by CPE
```python
cves = cve_lookup.search_by_cpe(
    "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
)
```

#### Get CVE Details
```python
cve = cve_lookup.get_cve_details("CVE-2021-44228")
print(f"Log4Shell: {cve.description}")
print(f"CVSS Score: {cve.cvss_score}")
print(f"References: {', '.join(cve.references[:3])}")
```

### Exploit Search

#### Search by CVE
```python
from utils.exploit_search import ExploitSearch

exploit_search = ExploitSearch()

# Find exploits for Log4Shell
exploits = exploit_search.search_by_cve("CVE-2021-44228")

for exploit in exploits:
    print(f"\n{exploit.title}")
    print(f"  Source: {exploit.source_url}")
    print(f"  Verified: {exploit.verified}")
```

#### Search Metasploit Modules
```python
modules = exploit_search.search_metasploit_modules("eternal blue")

for module in modules:
    print(f"{module['name']}: {module['description']}")
```

#### Verify Exploit
```python
exploit_info = exploits[0]
verification = exploit_search.verify_exploit(exploit_info)

print(f"Verified: {verification['verified']}")
print(f"Has Metasploit module: {verification['has_metasploit_module']}")
print(f"Has PoC: {verification['has_poc']}")
```

### ZAP Wrapper

#### Basic Web Scan
```python
from tools.zap_wrapper import ZAPWrapper

zap = ZAPWrapper(api_key="your-zap-api-key")

# Start session
zap.start_session("test_scan")

# Spider and scan
result = zap.full_scan("http://example.com")

print(f"Found {result.summary['total_alerts']} alerts")
print(f"High risk: {result.summary['high_risk']}")
print(f"Medium risk: {result.summary['medium_risk']}")
```

#### Analyze Specific Alert
```python
for alert in result.alerts:
    if alert.risk == "High":
        print(f"\n⚠️  {alert.name}")
        print(f"URL: {alert.url}")
        print(f"Description: {alert.description}")
        
        # Get exploitation suggestions
        exploitation = zap.analyze_alert_for_exploitation(alert)
        if exploitation['exploitable']:
            print(f"Exploitation techniques:")
            for technique in exploitation['techniques']:
                print(f"  - {technique}")
```

#### Craft Custom Attack
```python
# Test for SQL injection
attack_result = zap.craft_attack(
    base_url="http://example.com/search",
    param="q",
    payload="' OR '1'='1",
    method="GET"
)

if attack_result['success']:
    print("Attack sent successfully")
    print(f"Response: {attack_result['response']['response_body'][:200]}")
```

### Metasploit Wrapper

#### Search and Run Exploit
```python
from tools.metasploit_wrapper import MetasploitWrapper

msf = MetasploitWrapper(password="your-msf-password")
msf.connect()

# Search for exploits
exploits = msf.search_exploits("ms17-010")

for exploit in exploits:
    print(f"{exploit.fullname}")
    print(f"  Rank: {exploit.rank}")
    print(f"  Description: {exploit.description[:100]}...")

# Check if target is vulnerable (safe)
check_result = msf.check_exploit(
    module_name="exploit/windows/smb/ms17_010_eternalblue",
    target="192.168.1.100",
    options={"RPORT": 445}
)

if check_result['vulnerable']:
    print("⚠️  Target is vulnerable!")
```

#### Run Auxiliary Scanner
```python
# Run SMB version scanner
result = msf.run_auxiliary(
    module_name="auxiliary/scanner/smb/smb_version",
    target="192.168.1.0/24",
    options={"THREADS": 10}
)
```

## Advanced Scenarios

### Scenario 1: Targeted Web Application Assessment

```python
import asyncio
from orchestrator.workflow_engine import WorkflowEngine

async def web_app_assessment():
    engine = WorkflowEngine()
    
    # Configure for web focus
    engine.config['workflow']['stages'] = [
        'reconnaissance',
        'web_vulnerability_assessment'
    ]
    
    result = await engine.run_workflow(
        target="https://webapp.example.com",
        mode="full"
    )
    
    # Analyze web-specific findings
    web_vulns = result.findings.get('web_vulnerabilities', [])
    
    for vuln in web_vulns:
        if vuln['risk'] in ['High', 'Critical']:
            print(f"⚠️  {vuln['name']}")
            print(f"   URL: {vuln['url']}")
            print(f"   Solution: {vuln['solution']}")

asyncio.run(web_app_assessment())
```

### Scenario 2: Network Range Assessment

```python
import ipaddress

async def network_assessment():
    engine = WorkflowEngine()
    
    network = ipaddress.IPv4Network('192.168.1.0/24')
    results = []
    
    for ip in network.hosts():
        try:
            result = await engine.run_workflow(
                target=str(ip),
                mode="quick"
            )
            results.append(result)
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
    
    # Aggregate results
    total_vulns = sum(
        len(r.findings.get('cves', [])) 
        for r in results
    )
    
    print(f"Scanned {len(results)} hosts")
    print(f"Total vulnerabilities: {total_vulns}")

asyncio.run(network_assessment())
```

### Scenario 3: CVE-Specific Testing

```python
async def test_specific_cve():
    """Test if targets are vulnerable to a specific CVE"""
    
    cve_id = "CVE-2021-44228"  # Log4Shell
    targets = ["192.168.1.100", "192.168.1.101"]
    
    cve_lookup = CVELookup()
    exploit_search = ExploitSearch()
    
    # Get CVE details
    cve = cve_lookup.get_cve_details(cve_id)
    print(f"Testing for: {cve.description[:100]}...")
    
    # Find exploits
    exploits = exploit_search.search_by_cve(cve_id)
    print(f"Found {len(exploits)} exploits")
    
    # Test each target
    for target in targets:
        print(f"\nTesting {target}...")
        
        # Check with Metasploit
        msf = MetasploitWrapper()
        msf.connect()
        
        msf_exploits = msf.get_exploit_for_cve(cve_id)
        
        for exploit_module in msf_exploits:
            result = msf.check_exploit(
                module_name=exploit_module,
                target=target,
                options={}
            )
            
            if result['vulnerable']:
                print(f"  ⚠️  VULNERABLE to {exploit_module}")
            else:
                print(f"  ✓ Not vulnerable to {exploit_module}")

asyncio.run(test_specific_cve())
```

## AI-Powered Features

### Intelligent Tool Selection
The AI automatically selects appropriate tools based on discovered services:

```python
# AI analyzes Nmap results and decides next steps
recon_results = nmap.full_scan(target)
ai_decision = await engine._ai_decide_next_steps(recon_results)

print("AI Recommendations:")
print(ai_decision['recommendations'])
```

### Vulnerability Prioritization
AI ranks vulnerabilities by exploitability and impact:

```python
vuln_results = {
    'cves': [...],  # List of discovered CVEs
    'exploits': [...]  # Available exploits
}

ai_analysis = await engine._ai_analyze_vulnerabilities(vuln_results)
print(f"Risk Level: {ai_analysis['risk_level']}")
print(f"Analysis: {ai_analysis['analysis']}")
```

### Attack Chain Planning
AI suggests potential attack chains:

```python
# AI selects best exploits to attempt
selected_exploits = await engine._ai_select_exploits(vuln_results)

for exploit in selected_exploits:
    print(f"Recommended: {exploit['title']}")
    print(f"  Reason: High success probability, low detection risk")
```

## Best Practices

### 1. Always Get Authorization
```bash
# Add authorized targets to authorization file
echo "192.168.1.100" >> config/authorization.txt
echo "testlab.example.com" >> config/authorization.txt
```

### 2. Start with Safe Scans
```bash
# Begin with reconnaissance only
python src/orchestrator/workflow_engine.py \
  --target TARGET \
  --mode quick
```

### 3. Review Results Before Exploitation
```bash
# Review findings
cat reports/workflow_*.json | jq '.findings.vulnerability_assessment'

# Only proceed if authorized and necessary
```

### 4. Use Rate Limiting
```yaml
# In config.yaml
safety:
  rate_limiting:
    enabled: true
    max_requests_per_minute: 60
```

### 5. Log Everything
```yaml
# In config.yaml
logging:
  level: "INFO"
  file: "logs/security_assessment.log"
  console_output: true
```

### 6. Secure Your Results
```bash
# Encrypt sensitive reports
gpg --encrypt --recipient your-email@example.com reports/workflow_*.json

# Set proper permissions
chmod 600 config/config.yaml
chmod 700 reports/
```

## Troubleshooting

### Issue: Scan Taking Too Long
```bash
# Use quick mode or limit port range
python src/orchestrator/workflow_engine.py \
  --target TARGET \
  --mode quick
```

### Issue: Too Many False Positives
```yaml
# Adjust confidence threshold in config.yaml
ai_orchestration:
  decision_making:
    confidence_threshold: 0.8  # Higher = fewer false positives
```

### Issue: API Rate Limiting
```python
# Add delays between requests
import time
for target in targets:
    scan(target)
    time.sleep(5)  # Wait 5 seconds between scans
```

## Next Steps

- Review [Security Best Practices](security_practices.md)
- Check [API Reference](api_reference.md)
- Explore [Example Scripts](../examples/)
- Join community discussions

## Support

For issues or questions:
- GitHub Issues: <repository-url>/issues
- Documentation: <repository-url>/docs
- Email: support@example.com