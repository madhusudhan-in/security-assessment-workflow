# Security Assessment Workflow — Documentation

> **Quick links:** [Installation](#installation) · [Quick Start](#quick-start) · [Usage Guide](#usage-guide) · [Project Summary](#project-summary)

---

## Table of Contents

1. [Project Summary](#project-summary)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Usage Guide](#usage-guide)

---

## Project Summary

An enterprise-level, AI-powered security assessment automation framework that integrates multiple security tools (Nmap, OWASP ZAP, Metasploit, etc.) with GenAI capabilities using the Model Context Protocol (MCP) and Skills architecture.

### Core Components

#### Tool Wrappers (`src/tools/`)

| Wrapper | Key Capabilities |
|---------|-----------------|
| `nmap_wrapper.py` | Port scanning (quick/full/aggressive), service version detection, OS fingerprinting, NSE scripts, vulnerability scanning |
| `zap_wrapper.py` | Spider scanning (traditional + AJAX), active/passive scanning, request/response analysis, attack crafting |
| `metasploit_wrapper.py` | Exploit search/execution, auxiliary modules, vulnerability checking, session management, post-exploitation |

#### Utility Modules (`src/utils/`)

| Module | Key Capabilities |
|--------|-----------------|
| `cve_lookup.py` | NVD API integration, CPE-based searching, CVSS scoring, batch lookups, exploit availability |
| `exploit_search.py` | Exploit-DB, GitHub, searchsploit, Metasploit module search, PoC retrieval |

#### MCP Servers (`src/mcp_servers/`)

- ✅ **Nmap MCP Server** — 7 tool endpoints, async operation, structured JSON responses
- 🔄 ZAP MCP Server (template ready)
- 🔄 Metasploit MCP Server (template ready)
- 🔄 Tools MCP Server (for auxiliary tools)

#### AI Orchestration Layer (`src/orchestrator/`)

- **Workflow Engine** (`workflow_engine.py`) — Multi-stage assessment, AI-powered decision making, intelligent tool selection, vulnerability prioritization, attack chain planning, risk scoring, automated report generation

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AI Orchestration Layer                   │
│  (Claude AI via Anthropic API + Workflow Engine)            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    MCP Protocol Layer                        │
│  - Nmap Server  - ZAP Server  - MSF Server  - Tools Server │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Tool Wrappers                           │
│  - Nmap  - ZAP  - Metasploit  - CVE Lookup  - Exploit DB   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Security Tools                            │
│  Nmap | OWASP ZAP | Metasploit | Gobuster | Hping | etc.   │
└─────────────────────────────────────────────────────────────┘
```

### Workflow Stages

**Stage 1 – Reconnaissance:** Nmap port scanning, service version detection, OS fingerprinting, NSE vulnerability scripts, AI analysis.

**Stage 2 – Vulnerability Assessment:** CVE lookup, exploit database search, web application scanning, vulnerability prioritization, AI risk assessment.

**Stage 3 – Exploitation** *(optional, requires authorization)*: AI-selected exploit attempts, Metasploit integration, controlled exploitation, session management, impact assessment.

**Stage 4 – Reporting:** Result aggregation, risk scoring, AI-generated recommendations, executive summary, technical details export.

### Key Features

**AI-Powered:** Intelligent tool selection, vulnerability prioritization, attack chain planning, automated analysis, risk scoring, recommendation generation.

**Security Controls:** Authorization checks, safety controls, rate limiting, blacklist/whitelist, audit logging, configurable exploit severity limits.

**Integration:** MCP protocol, async operations, structured JSON output, robust error handling, extensible architecture.

### Performance

| Scan Mode | Duration | CPU | Memory |
|-----------|----------|-----|--------|
| Quick | 5–15 min | Moderate | 2–4 GB |
| Full | 30–60 min | Moderate | 2–4 GB |
| Aggressive | 1–3 hrs | Higher | 2–4 GB |

### Project Status

**Completed ✅**
- Project structure and architecture
- Nmap, ZAP, and Metasploit integrations
- CVE lookup and exploit search
- AI orchestration engine, MCP server framework
- Configuration system and safety controls

**In Progress 🔄**
- Additional tool wrappers (Gobuster, Hping, WafWoof)
- Complete MCP server implementations, report generation module

**Pending ⏳**
- Integration testing, performance optimization, Docker containerization, CI/CD pipeline

### Security & Ethical Guidelines

1. **Authorization Required** — Must explicitly authorize targets before testing
2. **Auto-Exploit Disabled** — Exploitation is disabled by default
3. **Rate Limiting** — Prevents overwhelming targets
4. **Audit Logging** — All actions logged
5. Always obtain written authorization, test only in controlled environments, follow responsible disclosure, comply with laws and regulations.

### Extending the Framework

**Adding new tools:**
1. Create wrapper in `src/tools/`
2. Implement MCP server in `src/mcp_servers/`
3. Add configuration in `config.yaml`
4. Update workflow engine integration

**Custom workflows:**
```python
from src.orchestrator.workflow_engine import WorkflowEngine

engine = WorkflowEngine()
engine.config['workflow']['stages'] = ['custom_stage_1', 'custom_stage_2']
result = await engine.run_workflow(target, mode)
```

---

## Installation

### System Requirements

- **OS:** Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **Python:** 3.10+
- **RAM:** 8 GB minimum (16 GB recommended)
- **Disk:** 20 GB free space
- **Accounts:** Anthropic API key; NVD API key and Shodan API key (optional)

### Step 1 — System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y python3.10 python3-pip python3-venv git
sudo apt-get install -y nmap gobuster hping3 nikto sqlmap
pip3 install wafw00f
```

**macOS:**
```bash
brew install python@3.10 nmap gobuster
pip3 install wafw00f
```

### Step 2 — Install OWASP ZAP

**Linux:**
```bash
cd /opt
sudo wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
sudo tar -xvf ZAP_2.14.0_Linux.tar.gz
sudo ln -s /opt/ZAP_2.14.0/zap.sh /usr/local/bin/zap
zap -daemon -port 8080 -config api.key=your-api-key-here
```

**macOS:**
```bash
brew install --cask owasp-zap
# Or download from https://www.zaproxy.org/download/
```

### Step 3 — Install Metasploit

**Linux:**
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall && ./msfinstall
msfdb init
msfrpcd -P your-password -S -a 127.0.0.1
```

**macOS:**
```bash
brew install metasploit
msfdb init
msfrpcd -P your-password -S -a 127.0.0.1
```

### Step 4 — Clone and Setup Project

```bash
git clone <repository-url>
cd security-assessment-workflow
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 5 — Configuration

```bash
cp config/config.example.yaml config/config.yaml
nano config/config.yaml
```

**Required changes:**
```yaml
api:
  anthropic_api_key: "sk-ant-your-key-here"

vulnerability_databases:
  nvd:
    api_key: "your-nvd-api-key"
  shodan:
    api_key: "your-shodan-api-key"

tools:
  nmap:
    path: "/usr/bin/nmap"
  zap:
    api_key: "your-zap-api-key"
    proxy_host: "localhost"
    proxy_port: 8080
  metasploit:
    password: "your-msf-password"

safety:
  require_authorization: true
  authorization_file: "config/authorization.txt"
  auto_exploit: false   # IMPORTANT: keep false unless in controlled environment
```

**Create authorization file:**
```bash
echo "192.168.1.100" > config/authorization.txt
echo "testlab.example.com" >> config/authorization.txt
```

### Step 6 — Verify Installation

```bash
python src/tools/nmap_wrapper.py 127.0.0.1
python src/utils/cve_lookup.py
python src/utils/exploit_search.py
python src/orchestrator/workflow_engine.py --target 127.0.0.1 --mode quick
```

### Step 7 — Start MCP Servers (Optional)

```bash
python src/mcp_servers/nmap_server.py       # Terminal 1
python src/mcp_servers/zap_server.py        # Terminal 2
python src/mcp_servers/metasploit_server.py # Terminal 3
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Import errors | Activate venv, then `pip install -r requirements.txt --force-reinstall` |
| Nmap permission denied | `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap` |
| ZAP connection issues | Check with `ps aux \| grep zap`; restart: `zap -daemon -port 8080 -config api.key=your-key` |
| Metasploit RPC issues | Check with `ps aux \| grep msfrpcd`; restart: `msfrpcd -P your-password -S -a 127.0.0.1 -p 55553` |
| NVD rate limiting | Set `vulnerability_databases.nvd.rate_limit_delay: 6` in config.yaml |

### Updating

```bash
git pull origin main
pip install -r requirements.txt --upgrade
sudo apt-get update && sudo apt-get upgrade nmap
```

### Uninstalling

```bash
pkill -f msfrpcd; pkill -f zap
deactivate && rm -rf venv/
cd .. && rm -rf security-assessment-workflow/
```

---

## Quick Start

Get up and running in 10 minutes.

### Prerequisites

- Python 3.10+, Nmap installed, Anthropic API key

### Install (5 minutes)

```bash
git clone <repository-url>
cd security-assessment-workflow
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
nano config/config.yaml   # add your Anthropic API key
```

Minimal `config.yaml` change:
```yaml
api:
  anthropic_api_key: "sk-ant-your-key-here"
```

### Your First Scan (2 minutes)

```bash
# Scan localhost (safe, no exploitation)
python src/orchestrator/workflow_engine.py --target 127.0.0.1 --mode quick
```

Or test individual tools:
```bash
python src/tools/nmap_wrapper.py 127.0.0.1

python -c "
from src.utils.cve_lookup import CVELookup
lookup = CVELookup()
cves = lookup.search_by_product('apache', 'http_server', '2.4.49')
print(f'Found {len(cves)} CVEs')
"
```

### View Results

```bash
ls -la reports/
cat reports/workflow_*.json | jq '.'
```

### Scan Modes

```bash
python src/orchestrator/workflow_engine.py --target TARGET --mode quick       # 5–15 min
python src/orchestrator/workflow_engine.py --target TARGET --mode full        # 30–60 min
python src/orchestrator/workflow_engine.py --target TARGET --mode aggressive  # 1–3 hrs
```

### Safe Testing Lab (Docker)

```bash
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
python src/orchestrator/workflow_engine.py --target localhost:8080 --mode full
```

### Security Notes

| ✅ Always | ❌ Never |
|-----------|---------|
| Get written authorization | Test systems without permission |
| Test in isolated environments | Use in production without approval |
| Keep `auto_exploit: false` | Enable auto-exploitation without controls |
| Follow responsible disclosure | Share credentials or API keys |

### Common Use Cases (CLI)

```bash
# Network discovery
python src/orchestrator/workflow_engine.py --target 192.168.1.0/24 --mode quick

# Web application testing
python src/orchestrator/workflow_engine.py --target https://webapp.example.com --mode full
```

### Example: Full Python Workflow

```python
#!/usr/bin/env python3
import asyncio
from src.orchestrator.workflow_engine import WorkflowEngine

async def main():
    engine = WorkflowEngine(config_path="config/config.yaml")
    result = await engine.run_workflow(target="192.168.1.100", mode="full")

    print(f"\n{'='*80}")
    print(f"Target: {result.target}")
    print(f"Risk Score: {result.risk_score}/10")

    vulns = result.findings.get('vulnerability_assessment', {})
    for cve in sorted(vulns.get('cves', []), key=lambda x: x['cvss_score'], reverse=True)[:5]:
        print(f"  - {cve['cve_id']}: {cve['severity']} (CVSS: {cve['cvss_score']})")

    for i, rec in enumerate(result.recommendations[:5], 1):
        print(f"  {i}. {rec}")

    print(f"\nFull report: reports/workflow_{result.workflow_id}.json")

asyncio.run(main())
```

### Troubleshooting (Quick Reference)

```bash
# Import errors — activate venv first
source venv/bin/activate && pip install -r requirements.txt

# Nmap permission denied
sudo python src/orchestrator/workflow_engine.py --target TARGET --mode quick

# No results — check logs and connectivity
tail -f logs/security_assessment.log
ping TARGET && nmap -p 80,443 TARGET
```

---

## Usage Guide

### Workflow Modes

#### Quick Mode — 5–15 minutes
Fast port scan (top 1000 ports), service version detection, basic NSE scripts, CVE lookup, quick risk assessment.

#### Full Mode (Recommended) — 30–60 minutes
Complete port scan (all 65535 ports), detailed service enumeration, OS fingerprinting, NSE vulnerability scripts, CVE and exploit DB search, web application scanning (if HTTP/HTTPS found), AI-powered analysis.

#### Aggressive Mode — 1–3 hours
Everything in Full mode, plus aggressive NSE scripts, brute force attempts (if configured), exploit verification (check mode only), deep web application testing.

### Individual Tool Usage

#### Nmap Wrapper

```python
from tools.nmap_wrapper import NmapWrapper

nmap = NmapWrapper()

# Quick scan
result = nmap.quick_scan("192.168.1.100")
for port in result.hosts[0].ports:
    print(f"  {port.port}/{port.protocol}: {port.service}")

# Service version detection
result = nmap.full_scan("192.168.1.100", ports="80,443,8080")
for host in result.hosts:
    for port in host.ports:
        print(f"Port {port.port}: {port.product} {port.version}")

# Vulnerability scan
result = nmap.vulnerability_scan("192.168.1.100")

# Specific NSE script
result = nmap.run_nse_script(target="192.168.1.100", script="smb-vuln-ms17-010", ports="445")
```

#### CVE Lookup

```python
from utils.cve_lookup import CVELookup

cve_lookup = CVELookup(nvd_api_key="your-key")

# By product
cves = cve_lookup.search_by_product(vendor="apache", product="http_server", version="2.4.49")
for cve in cves:
    print(f"{cve.cve_id}: {cve.severity} (CVSS: {cve.cvss_score})")

# By CPE
cves = cve_lookup.search_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")

# By ID
cve = cve_lookup.get_cve_details("CVE-2021-44228")
```

#### Exploit Search

```python
from utils.exploit_search import ExploitSearch

exploit_search = ExploitSearch()
exploits = exploit_search.search_by_cve("CVE-2021-44228")
modules = exploit_search.search_metasploit_modules("eternal blue")
verification = exploit_search.verify_exploit(exploits[0])
```

#### ZAP Wrapper

```python
from tools.zap_wrapper import ZAPWrapper

zap = ZAPWrapper(api_key="your-zap-api-key")
zap.start_session("test_scan")
result = zap.full_scan("http://example.com")

# Analyze high-risk alerts
for alert in result.alerts:
    if alert.risk == "High":
        exploitation = zap.analyze_alert_for_exploitation(alert)

# Craft custom attack
attack_result = zap.craft_attack(
    base_url="http://example.com/search",
    param="q",
    payload="' OR '1'='1",
    method="GET"
)
```

#### Metasploit Wrapper

```python
from tools.metasploit_wrapper import MetasploitWrapper

msf = MetasploitWrapper(password="your-msf-password")
msf.connect()

exploits = msf.search_exploits("ms17-010")
check_result = msf.check_exploit(
    module_name="exploit/windows/smb/ms17_010_eternalblue",
    target="192.168.1.100",
    options={"RPORT": 445}
)

result = msf.run_auxiliary(
    module_name="auxiliary/scanner/smb/smb_version",
    target="192.168.1.0/24",
    options={"THREADS": 10}
)
```

### Advanced Scenarios

#### Web Application Assessment
```python
async def web_app_assessment():
    engine = WorkflowEngine()
    engine.config['workflow']['stages'] = ['reconnaissance', 'web_vulnerability_assessment']
    result = await engine.run_workflow(target="https://webapp.example.com", mode="full")
    for vuln in result.findings.get('web_vulnerabilities', []):
        if vuln['risk'] in ['High', 'Critical']:
            print(f"⚠️  {vuln['name']} — {vuln['url']}")
```

#### Network Range Assessment
```python
import ipaddress

async def network_assessment():
    engine = WorkflowEngine()
    results = []
    for ip in ipaddress.IPv4Network('192.168.1.0/24').hosts():
        result = await engine.run_workflow(target=str(ip), mode="quick")
        results.append(result)
    total_vulns = sum(len(r.findings.get('cves', [])) for r in results)
    print(f"Scanned {len(results)} hosts, {total_vulns} total vulnerabilities")
```

#### CVE-Specific Testing
```python
async def test_specific_cve():
    cve_id = "CVE-2021-44228"
    cve = CVELookup().get_cve_details(cve_id)
    exploits = ExploitSearch().search_by_cve(cve_id)

    msf = MetasploitWrapper(); msf.connect()
    for target in ["192.168.1.100", "192.168.1.101"]:
        for module in msf.get_exploit_for_cve(cve_id):
            result = msf.check_exploit(module_name=module, target=target, options={})
            status = "VULNERABLE" if result['vulnerable'] else "not vulnerable"
            print(f"{target} — {module}: {status}")
```

### AI-Powered Features

```python
# Intelligent tool selection
ai_decision = await engine._ai_decide_next_steps(recon_results)

# Vulnerability prioritization
ai_analysis = await engine._ai_analyze_vulnerabilities(vuln_results)
print(f"Risk Level: {ai_analysis['risk_level']}")

# Attack chain planning
selected_exploits = await engine._ai_select_exploits(vuln_results)
```

### Best Practices

```bash
# 1. Authorization
echo "192.168.1.100" >> config/authorization.txt

# 2. Start safe
python src/orchestrator/workflow_engine.py --target TARGET --mode quick

# 3. Review findings before proceeding
cat reports/workflow_*.json | jq '.findings.vulnerability_assessment'

# 4. Secure results
gpg --encrypt --recipient your-email@example.com reports/workflow_*.json
chmod 600 config/config.yaml && chmod 700 reports/
```

**config.yaml best-practice settings:**
```yaml
safety:
  rate_limiting:
    enabled: true
    max_requests_per_minute: 60
logging:
  level: "INFO"
  file: "logs/security_assessment.log"
  console_output: true
ai_orchestration:
  decision_making:
    confidence_threshold: 0.8
```

### Troubleshooting

| Symptom | Fix |
|---------|-----|
| Scan taking too long | Use `--mode quick` or reduce port range |
| Too many false positives | Raise `confidence_threshold` to `0.8` in config |
| API rate limiting | Add `time.sleep(5)` between scans |

---

*See [README.md](README.md) for project overview. See [IMPROVEMENTS.md](IMPROVEMENTS.md) for workflow engine improvement guides.*

---
<sub>⚠️ This tool is for authorized security testing only. Always obtain proper written authorization and comply with applicable laws.</sub>
