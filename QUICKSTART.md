# Quick Start Guide

Get up and running with the Security Assessment Workflow in 10 minutes!

## 🚀 Prerequisites

- Python 3.10+
- Nmap installed
- Anthropic API key

## 📦 Installation (5 minutes)

```bash
# 1. Clone and navigate
git clone <repository-url>
cd security-assessment-workflow

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure
cp config/config.example.yaml config/config.yaml
nano config/config.yaml  # Add your Anthropic API key
```

## ⚙️ Minimal Configuration

Edit `config/config.yaml` and add your API key:

```yaml
api:
  anthropic_api_key: "sk-ant-your-key-here"
```

That's it! You're ready to run your first scan.

## 🎯 Your First Scan (2 minutes)

### Option 1: Quick Reconnaissance (Safest)

```bash
# Scan localhost (safe)
python src/orchestrator/workflow_engine.py --target 127.0.0.1 --mode quick
```

### Option 2: Individual Tool Test

```bash
# Test Nmap wrapper
python src/tools/nmap_wrapper.py 127.0.0.1

# Test CVE lookup
python -c "
from src.utils.cve_lookup import CVELookup
lookup = CVELookup()
cves = lookup.search_by_product('apache', 'http_server', '2.4.49')
print(f'Found {len(cves)} CVEs')
"
```

## 📊 View Results

```bash
# List generated reports
ls -la reports/

# View latest report (requires jq)
cat reports/workflow_*.json | jq '.'

# Or view in Python
python -c "
import json
import glob
latest = max(glob.glob('reports/workflow_*.json'))
with open(latest) as f:
    data = json.load(f)
    print(f\"Risk Score: {data['risk_score']}/10\")
    print(f\"Findings: {len(data['findings'])} categories\")
"
```

## 🎓 Next Steps

### 1. Set Up Test Environment (Recommended)

```bash
# Use Docker for safe testing
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa

# Scan the test environment
python src/orchestrator/workflow_engine.py --target localhost:8080 --mode full
```

### 2. Configure Additional Tools

For full functionality, install:

- **OWASP ZAP**: Web application scanning
- **Metasploit**: Exploit testing
- **Additional tools**: Gobuster, WafWoof, etc.

See [INSTALLATION.md](INSTALLATION.md) for detailed setup.

### 3. Explore Features

```bash
# Run different scan modes
python src/orchestrator/workflow_engine.py --target TARGET --mode quick    # 5-10 min
python src/orchestrator/workflow_engine.py --target TARGET --mode full     # 30-60 min
python src/orchestrator/workflow_engine.py --target TARGET --mode aggressive  # 1-3 hours
```

## 🔒 Important Security Notes

### ⚠️ ALWAYS:
- ✅ Get written authorization before testing
- ✅ Test in isolated lab environments
- ✅ Keep `auto_exploit: false` in config
- ✅ Review findings before taking action
- ✅ Follow responsible disclosure practices

### ❌ NEVER:
- ❌ Test systems without permission
- ❌ Use in production environments without approval
- ❌ Enable auto-exploitation without controls
- ❌ Share credentials or API keys
- ❌ Ignore legal and ethical guidelines

## 📚 Common Use Cases

### Use Case 1: Network Discovery
```bash
# Discover what's running on your network
python src/orchestrator/workflow_engine.py \
  --target 192.168.1.0/24 \
  --mode quick
```

### Use Case 2: Web Application Testing
```bash
# Test a web application
python src/orchestrator/workflow_engine.py \
  --target https://webapp.example.com \
  --mode full
```

### Use Case 3: Vulnerability Research
```python
# Search for specific CVE
from src.utils.cve_lookup import CVELookup
from src.utils.exploit_search import ExploitSearch

cve_lookup = CVELookup()
exploit_search = ExploitSearch()

# Get CVE details
cve = cve_lookup.get_cve_details("CVE-2021-44228")
print(f"{cve.cve_id}: {cve.description}")

# Find exploits
exploits = exploit_search.search_by_cve("CVE-2021-44228")
print(f"Found {len(exploits)} exploits")
```

## 🐛 Troubleshooting

### Issue: Import Errors
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Issue: Permission Denied (Nmap)
```bash
# Run with sudo or add capabilities
sudo python src/orchestrator/workflow_engine.py --target TARGET --mode quick
```

### Issue: API Rate Limiting
```yaml
# Edit config.yaml - add delays
vulnerability_databases:
  nvd:
    rate_limit_delay: 6  # seconds between requests
```

### Issue: No Results
```bash
# Check logs
tail -f logs/security_assessment.log

# Verify target is reachable
ping TARGET
nmap -p 80,443 TARGET
```

## 📖 Documentation

- **Full Installation**: [INSTALLATION.md](INSTALLATION.md)
- **Detailed Usage**: [docs/USAGE_GUIDE.md](docs/USAGE_GUIDE.md)
- **API Reference**: [docs/api_reference.md](docs/api_reference.md)
- **Architecture**: [README.md](README.md)

## 🤝 Getting Help

- **GitHub Issues**: Report bugs or request features
- **Documentation**: Check the docs/ directory
- **Examples**: See examples/ for sample scripts
- **Community**: Join discussions on GitHub

## 🎯 What's Next?

Now that you have the basics working:

1. **Read the full documentation** to understand all features
2. **Set up a test lab** for safe experimentation
3. **Configure additional tools** (ZAP, Metasploit) for complete functionality
4. **Customize workflows** for your specific needs
5. **Integrate with CI/CD** for automated security testing

## 📝 Example Workflow

Here's a complete example workflow:

```python
#!/usr/bin/env python3
"""
Example: Complete Security Assessment
"""
import asyncio
from src.orchestrator.workflow_engine import WorkflowEngine

async def main():
    # Initialize engine
    engine = WorkflowEngine(config_path="config/config.yaml")
    
    # Run assessment
    result = await engine.run_workflow(
        target="192.168.1.100",
        mode="full"
    )
    
    # Print summary
    print(f"\n{'='*80}")
    print(f"Security Assessment Complete")
    print(f"{'='*80}")
    print(f"Target: {result.target}")
    print(f"Risk Score: {result.risk_score}/10")
    print(f"Duration: {result.start_time} to {result.end_time}")
    print(f"\nTop Findings:")
    
    # Show top vulnerabilities
    vulns = result.findings.get('vulnerability_assessment', {})
    cves = vulns.get('cves', [])
    
    for cve in sorted(cves, key=lambda x: x['cvss_score'], reverse=True)[:5]:
        print(f"  - {cve['cve_id']}: {cve['severity']} (CVSS: {cve['cvss_score']})")
    
    print(f"\nRecommendations:")
    for i, rec in enumerate(result.recommendations[:5], 1):
        print(f"  {i}. {rec}")
    
    print(f"\nFull report: reports/workflow_{result.workflow_id}.json")

if __name__ == "__main__":
    asyncio.run(main())
```

Save as `example_scan.py` and run:
```bash
python example_scan.py
```

## 🎉 Success!

You're now ready to perform security assessments with AI-powered automation!

Remember:
- Start with safe, authorized targets
- Review results carefully
- Follow ethical guidelines
- Keep learning and improving

Happy (ethical) hacking! 🔐

---

**Need help?** Check the [full documentation](README.md) or open an issue on GitHub.