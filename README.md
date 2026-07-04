# AI-Orchestrated Security Assessment Workflow

An open-source framework where a large language model sequences Nmap, ZAP, and Metasploit through the Model Context Protocol — with authorization gates and audit logging built in from the start.

> **Authorized use only.** Every capability in this framework is intended exclusively for systems you have written permission to test. The exploitation pipeline is off by default and requires both a configuration flag and a runtime authorization file to activate.

---

## How it works

The framework models a security assessment as four sequential stages. An AI decision point sits between every stage — the engine packages accumulated findings as JSON, sends a structured prompt to Claude, and uses the response to drive the next action. Engineers spend their time on findings, not logistics.

```
┌─────────────────────────────────────────────────────────┐
│  Orchestration Layer                                    │
│  WorkflowEngine · Claude (Anthropic) · Risk scoring    │
└────────────────────────┬────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  MCP Protocol Layer  (typed tool contracts)             │
│  nmap_server · zap_server · metasploit_server           │
│  auxiliary_tools_server  (Gobuster/Hping3/WafWoof)      │
│  Per-tool rate limiting · Structured JSON endpoints     │
└────────────────────────┬────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  Wrapper & Utility Layer  (clean Python interfaces)     │
│  NmapWrapper · ZAPWrapper · MetasploitWrapper           │
│  CVELookup (NVD API) · ExploitSearch (searchsploit)     │
└────────────────────────┬────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  Tool Layer  (executables)                              │
│  Nmap · OWASP ZAP · Metasploit · Gobuster               │
│  Hping3 · WafWoof                                       │
└─────────────────────────────────────────────────────────┘
```

### The four stages

| # | Stage | What runs | AI role |
|---|---|---|---|
| 1 | **Reconnaissance** | Nmap full scan, OS fingerprint, NSE vuln scripts | Prioritizes services, flags unusual port combinations |
| 2 | **Vulnerability Assessment** | NVD CVE lookup (concurrent, semaphore-bounded), searchsploit, OWASP ZAP for HTTP/HTTPS ports | Produces ranked risk matrix with attack-chain hypotheses |
| 3 | **Controlled Exploitation** *(opt-in)* | Metasploit check mode → operator approval prompt → live run | Ranks exploits by success probability and reversibility; selects up to 3 |
| 4 | **Reporting** | AI synthesis across all findings | Writes `reports/<id>.json` and `reports/<id>.md` with risk score 0–10 and remediation checklist |

---

## Safety controls

**Authorization file** (`config/authorized_targets.txt`) — checked before any tool is invoked. Supports exact hostnames, IP addresses, CIDR blocks, and wildcard patterns. Unrecognized targets are rejected immediately.

**Exploitation gate** — `auto_exploit` defaults to `false`. The exploitation stage is only reached when both `--mode aggressive` is passed *and* `auto_exploit: true` is set in config. Even then, Metasploit runs `exploit.check()` first; a live run only proceeds after the operator types `yes` at the interactive prompt.

**MCP rate limiting** — every MCP server enforces a per-minute request ceiling (configurable via env vars) so the AI cannot flood the target with scan requests.

**Credential isolation** — `ANTHROPIC_API_KEY` and `NVD_API_KEY` are read exclusively from environment variables. No secrets appear in config files or source code.

**Rotating audit log** — every tool call, AI prompt, and config read is written to a `RotatingFileHandler` log at the MCP boundary.

---

## Repository layout

```
security-assessment-workflow/
├── config/
│   ├── config.example.yaml        # Copy to config.yaml and fill in
│   └── authorized_targets.txt     # One target per line — required before any scan
├── reports/                       # Auto-created; JSON + Markdown reports written here
├── src/
│   ├── mcp_servers/
│   │   ├── nmap_server.py         # 7 Nmap endpoints + rate limiter
│   │   ├── zap_server.py          # 4 ZAP endpoints + rate limiter
│   │   ├── metasploit_server.py   # search / check / module info / sessions
│   │   └── auxiliary_tools_server.py  # Gobuster · Hping3 · WafWoof
│   ├── orchestrator/
│   │   ├── workflow_engine_improved.py  # Primary engine (use this)
│   │   └── workflow_engine.py           # Original engine
│   ├── tools/
│   │   ├── nmap_wrapper.py
│   │   ├── zap_wrapper.py
│   │   └── metasploit_wrapper.py
│   └── utils/
│       ├── cve_lookup.py          # NVD API v2 client
│       └── exploit_search.py      # searchsploit + GitHub
└── requirements.txt
```

---

## Prerequisites

**System tools** (install once):
```bash
# Nmap
sudo apt-get install nmap

# Gobuster and Hping3
sudo apt-get install gobuster hping3

# WafWoof
pip install wafw00f

# OWASP ZAP — download from https://www.zaproxy.org/download/

# Metasploit Framework
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall && sudo ./msfinstall
```

**Python 3.10+** with packages from `requirements.txt`:

| Package | Purpose |
|---|---|
| `anthropic` | Claude API client |
| `mcp` | Model Context Protocol server/client |
| `python-nmap` | Nmap Python bindings |
| `python-owasp-zap-v2.4` | ZAP REST API client |
| `pymetasploit3` | Metasploit RPC client |
| `requests` | HTTP for NVD / Exploit-DB |
| `pyyaml` | Config file parsing |

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/madhusudhan-in/security-assessment-workflow.git
cd security-assessment-workflow

# 2. Virtual environment
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 3. Credentials — never put these in config files
export ANTHROPIC_API_KEY="sk-ant-..."
export NVD_API_KEY="your-nvd-key"

# 4. Config
cp config/config.example.yaml config/config.yaml
# Edit config.yaml — set tool paths, ZAP api_key, Metasploit credentials

# 5. Authorize your target
echo "127.0.0.1" >> config/authorized_targets.txt

# 6. Run a quick scan (recon + report only, ~5–15 min)
python src/orchestrator/workflow_engine_improved.py \
    --target 127.0.0.1 \
    --mode quick \
    --config config/config.yaml
```

On completion two files are written to `reports/`:
- `workflow_<id>.json` — full `WorkflowResult` dataclass (findings, CVEs, risk score, metadata)
- `workflow_<id>.md` — Markdown executive summary with numbered remediation checklist

---

## Scan modes

| Mode | Stages | Typical duration |
|---|---|---|
| `quick` | Reconnaissance → Reporting | 5–15 min |
| `full` | Reconnaissance → Vulnerability Assessment → Reporting | 30–60 min |
| `aggressive` | All four stages — exploitation only if `auto_exploit: true` | 1–3 hr |

```bash
# Full scan
python src/orchestrator/workflow_engine_improved.py \
    --target 192.168.1.10 --mode full --config config/config.yaml

# Aggressive (exploitation gate active — requires authorized_targets.txt entry
# AND auto_exploit: true in config.yaml)
python src/orchestrator/workflow_engine_improved.py \
    --target 192.168.1.10 --mode aggressive --config config/config.yaml
```

---

## Authorization file format

`config/authorized_targets.txt` — one entry per line, `#` for comments:

```
# Exact IP
192.168.1.10

# CIDR block
10.0.0.0/24

# Exact hostname
testlab.example.com

# Wildcard
*.pentest.lab
```

The workflow engine checks this file before any stage runs. If the target does not match any entry, the run exits immediately with an authorization error.

---

## Enabling ZAP web scanning

Set `enabled: true` and provide `api_key` in `config/config.yaml`:

```yaml
tools:
  zap:
    enabled: true
    api_key: "your-zap-api-key"
    proxy_host: "localhost"
    proxy_port: 8080
```

ZAP is automatically invoked for any port where Nmap detects an HTTP or HTTPS service.

---

## Enabling exploitation (aggressive mode)

Two explicit actions are required:

```yaml
# config/config.yaml
workflow:
  auto_exploit: true   # Step 1 — config flag
```

```
# config/authorized_targets.txt
192.168.1.10           # Step 2 — authorization file entry
```

When both are set and `--mode aggressive` is passed, the engine:
1. Calls `exploit.check()` (read-only probe — no damage)
2. Prints the result and waits for operator input
3. Only calls `exploit.execute()` if the operator types `yes`

---

## Adding a new tool

Three files, zero orchestrator changes:

```python
# 1. src/tools/nuclei_wrapper.py
class NucleiWrapper:
    def scan(self, target: str, templates: list[str]) -> NucleiResult: ...

# 2. src/mcp_servers/nuclei_server.py
@app.list_tools()
async def list_tools():
    return [Tool(name="nuclei_template_scan", ...)]

@app.call_tool()
async def call_tool(name, arguments):
    if name == "nuclei_template_scan":
        return wrapper.scan(arguments["target"], arguments["templates"]).to_dict()

# 3. config/config.yaml
# tools:
#   nuclei:
#     path: /usr/local/bin/nuclei
```

The AI discovers the new endpoint from the MCP registry on the next run and incorporates it into its assessment reasoning automatically.

---

## Rate limit configuration

Each MCP server respects an environment variable ceiling (requests per minute):

| Server | Env var | Default |
|---|---|---|
| `nmap_server.py` | `NMAP_MCP_RATE_LIMIT` | 15 |
| `zap_server.py` | `ZAP_MCP_RATE_LIMIT` | 10 |
| `metasploit_server.py` | `MSF_MCP_RATE_LIMIT` | 5 |
| `auxiliary_tools_server.py` | `AUX_MCP_RATE_LIMIT` | 20 |

---

## Disclaimer

This framework is provided for authorized security testing and educational purposes only. Users must obtain explicit written permission before testing any system. The authors are not responsible for misuse or any damage caused by this tool.
