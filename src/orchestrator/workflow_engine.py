"""
AI-Powered Security Assessment Workflow Engine
Orchestrates security tools and makes intelligent decisions
"""

import asyncio
import logging
import yaml
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anthropic import Anthropic
from tools.nmap_wrapper import NmapWrapper
from tools.zap_wrapper import ZAPWrapper
from tools.metasploit_wrapper import MetasploitWrapper
from utils.cve_lookup import CVELookup
from utils.exploit_search import ExploitSearch

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class WorkflowConfig:
    """Workflow configuration"""
    target: str
    mode: str  # quick, full, aggressive
    stages: List[str]
    auto_exploit: bool
    max_concurrent: int
    timeout: int


@dataclass
class WorkflowResult:
    """Complete workflow execution result"""
    workflow_id: str
    target: str
    start_time: str
    end_time: str
    stages_completed: List[str]
    findings: Dict[str, Any]
    recommendations: List[str]
    risk_score: float
    summary: str


class WorkflowEngine:
    """AI-powered security assessment workflow orchestrator"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize AI client
        self.ai_client = Anthropic(api_key=self.config['api']['anthropic_api_key'])
        
        # Initialize tool wrappers
        self.nmap = NmapWrapper(self.config['tools']['nmap']['path'])
        self.cve_lookup = CVELookup(self.config['vulnerability_databases']['nvd'].get('api_key'))
        self.exploit_search = ExploitSearch()
        
        # ZAP and Metasploit require running services
        self.zap = None
        self.msf = None
        
        # Workflow state
        self.current_workflow = None
        self.findings = {}
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            # Return default config
            return {
                'api': {'anthropic_api_key': '', 'model': 'claude-3-5-sonnet-20241022'},
                'tools': {'nmap': {'path': '/usr/bin/nmap'}},
                'vulnerability_databases': {'nvd': {}},
                'workflow': {'auto_exploit': False, 'max_concurrent_scans': 3}
            }
    
    async def run_workflow(self, target: str, mode: str = "full") -> WorkflowResult:
        """
        Execute complete security assessment workflow
        
        Args:
            target: Target IP/hostname/URL
            mode: Workflow mode (quick, full, aggressive)
            
        Returns:
            WorkflowResult object
        """
        workflow_id = f"workflow_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        logger.info(f"Starting workflow {workflow_id} for target {target} in {mode} mode")
        
        self.current_workflow = WorkflowConfig(
            target=target,
            mode=mode,
            stages=['reconnaissance', 'vulnerability_assessment', 'exploitation', 'reporting'],
            auto_exploit=self.config['workflow'].get('auto_exploit', False),
            max_concurrent=self.config['workflow'].get('max_concurrent_scans', 3),
            timeout=self.config['workflow'].get('timeout', 7200)
        )
        
        stages_completed = []
        
        try:
            # Stage 1: Reconnaissance
            logger.info("Stage 1: Reconnaissance")
            recon_results = await self._stage_reconnaissance(target)
            stages_completed.append('reconnaissance')
            self.findings['reconnaissance'] = recon_results
            
            # Stage 2: Vulnerability Assessment
            logger.info("Stage 2: Vulnerability Assessment")
            vuln_results = await self._stage_vulnerability_assessment(target, recon_results)
            stages_completed.append('vulnerability_assessment')
            self.findings['vulnerability_assessment'] = vuln_results
            
            # Stage 3: Exploitation (if enabled)
            if self.current_workflow.auto_exploit:
                logger.info("Stage 3: Exploitation")
                exploit_results = await self._stage_exploitation(target, vuln_results)
                stages_completed.append('exploitation')
                self.findings['exploitation'] = exploit_results
            else:
                logger.info("Stage 3: Exploitation - SKIPPED (auto_exploit disabled)")
            
            # Stage 4: AI Analysis and Recommendations
            logger.info("Stage 4: AI Analysis")
            analysis = await self._ai_analysis()
            
            # Generate final report
            end_time = datetime.now()
            
            return WorkflowResult(
                workflow_id=workflow_id,
                target=target,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                stages_completed=stages_completed,
                findings=self.findings,
                recommendations=analysis['recommendations'],
                risk_score=analysis['risk_score'],
                summary=analysis['summary']
            )
            
        except Exception as e:
            logger.error(f"Workflow error: {e}")
            raise
    
    async def _stage_reconnaissance(self, target: str) -> Dict[str, Any]:
        """
        Stage 1: Network reconnaissance and service discovery
        """
        results = {
            'nmap_scan': None,
            'open_ports': [],
            'services': [],
            'os_detection': None
        }
        
        try:
            # Run Nmap scan
            logger.info("Running Nmap scan...")
            nmap_result = self.nmap.full_scan(target)
            results['nmap_scan'] = asdict(nmap_result)
            
            # Extract open ports and services
            for host in nmap_result.hosts:
                for port in host.ports:
                    if port.state == 'open':
                        results['open_ports'].append({
                            'port': port.port,
                            'protocol': port.protocol,
                            'service': port.service,
                            'version': port.version,
                            'product': port.product
                        })
                        
                        results['services'].append({
                            'port': port.port,
                            'service': port.service,
                            'version': port.version,
                            'product': port.product,
                            'cpe': port.cpe
                        })
                
                results['os_detection'] = host.os
            
            # Run NSE vulnerability scripts
            logger.info("Running NSE vulnerability scripts...")
            vuln_scan = self.nmap.vulnerability_scan(target)
            results['nse_scripts'] = asdict(vuln_scan)
            
            # AI decision: Determine next steps
            ai_decision = await self._ai_decide_next_steps(results)
            results['ai_recommendations'] = ai_decision
            
        except Exception as e:
            logger.error(f"Reconnaissance stage error: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _stage_vulnerability_assessment(self, target: str, recon_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stage 2: Vulnerability assessment and CVE lookup
        """
        results = {
            'cves': [],
            'exploits': [],
            'web_vulnerabilities': [],
            'severity_summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }
        
        try:
            # CVE lookup for discovered services
            logger.info("Looking up CVEs for discovered services...")
            services = recon_results.get('services', [])
            
            for service in services:
                if service.get('product') and service.get('version'):
                    cves = self.cve_lookup.search_by_product(
                        vendor=service.get('product', '').split()[0],
                        product=service.get('product', ''),
                        version=service.get('version', '')
                    )
                    
                    for cve in cves:
                        results['cves'].append({
                            'cve_id': cve.cve_id,
                            'service': service.get('service'),
                            'port': service.get('port'),
                            'severity': cve.severity,
                            'cvss_score': cve.cvss_score,
                            'description': cve.description,
                            'exploits_available': cve.exploits_available
                        })
                        
                        # Update severity summary
                        severity = cve.severity.lower()
                        if severity in results['severity_summary']:
                            results['severity_summary'][severity] += 1
                        elif cve.cvss_score >= 9.0:
                            results['severity_summary']['critical'] += 1
                        elif cve.cvss_score >= 7.0:
                            results['severity_summary']['high'] += 1
            
            # Search for available exploits
            logger.info("Searching for available exploits...")
            for cve_info in results['cves']:
                if cve_info['exploits_available']:
                    exploits = self.exploit_search.search_by_cve(cve_info['cve_id'])
                    
                    for exploit in exploits:
                        results['exploits'].append({
                            'cve_id': cve_info['cve_id'],
                            'exploit_id': exploit.exploit_id,
                            'title': exploit.title,
                            'source_url': exploit.source_url,
                            'verified': exploit.verified
                        })
            
            # Web application scanning (if HTTP/HTTPS detected)
            http_ports = [p for p in recon_results.get('open_ports', []) 
                         if p['service'] in ['http', 'https', 'http-proxy']]
            
            if http_ports and self.config['tools'].get('zap'):
                logger.info("Running web application scan...")
                # Note: ZAP integration would go here
                results['web_scan_note'] = "ZAP scan would be performed here"
            
            # AI analysis of vulnerabilities
            ai_analysis = await self._ai_analyze_vulnerabilities(results)
            results['ai_analysis'] = ai_analysis
            
        except Exception as e:
            logger.error(f"Vulnerability assessment stage error: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _stage_exploitation(self, target: str, vuln_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stage 3: Controlled exploitation (requires authorization)
        """
        results = {
            'exploits_attempted': [],
            'successful_exploits': [],
            'failed_exploits': []
        }
        
        logger.warning("⚠️  EXPLOITATION STAGE - Requires explicit authorization!")
        
        try:
            # Check authorization
            if not self._check_authorization(target):
                results['error'] = "No authorization found for exploitation"
                return results
            
            # Get exploits to try (AI-selected)
            exploits_to_try = await self._ai_select_exploits(vuln_results)
            
            for exploit_info in exploits_to_try:
                logger.info(f"Attempting exploit: {exploit_info['title']}")
                
                # Note: Actual exploitation would require Metasploit integration
                results['exploits_attempted'].append(exploit_info)
                
                # Placeholder for actual exploitation
                results['exploitation_note'] = "Metasploit integration would execute exploits here"
            
        except Exception as e:
            logger.error(f"Exploitation stage error: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _ai_decide_next_steps(self, recon_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to decide next steps based on reconnaissance"""
        
        prompt = f"""
        Analyze the following network reconnaissance results and recommend next steps:
        
        Open Ports: {len(recon_results.get('open_ports', []))}
        Services Discovered: {json.dumps(recon_results.get('services', [])[:5], indent=2)}
        
        Based on these findings:
        1. What are the most critical services to investigate?
        2. What specific vulnerability checks should be prioritized?
        3. Are there any immediate security concerns?
        
        Provide a structured response with priorities and reasoning.
        """
        
        try:
            response = self.ai_client.messages.create(
                model=self.config['api']['model'],
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return {
                'recommendations': response.content[0].text,
                'priority_services': [s['service'] for s in recon_results.get('services', [])[:3]]
            }
        except Exception as e:
            logger.error(f"AI decision error: {e}")
            return {'error': str(e)}
    
    async def _ai_analyze_vulnerabilities(self, vuln_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to analyze vulnerabilities and prioritize"""
        
        prompt = f"""
        Analyze the following vulnerability assessment results:
        
        Total CVEs Found: {len(vuln_results.get('cves', []))}
        Severity Summary: {json.dumps(vuln_results.get('severity_summary', {}), indent=2)}
        Available Exploits: {len(vuln_results.get('exploits', []))}
        
        Top 5 CVEs:
        {json.dumps(vuln_results.get('cves', [])[:5], indent=2)}
        
        Provide:
        1. Risk assessment and prioritization
        2. Attack chain possibilities
        3. Recommended mitigation strategies
        4. Exploitation difficulty assessment
        """
        
        try:
            response = self.ai_client.messages.create(
                model=self.config['api']['model'],
                max_tokens=3000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return {
                'analysis': response.content[0].text,
                'risk_level': self._calculate_risk_level(vuln_results)
            }
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return {'error': str(e)}
    
    async def _ai_select_exploits(self, vuln_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use AI to select which exploits to attempt"""
        
        prompt = f"""
        Given these vulnerabilities and available exploits:
        
        {json.dumps(vuln_results.get('exploits', [])[:10], indent=2)}
        
        Select the top 3 exploits to attempt, considering:
        1. Success probability
        2. Impact if successful
        3. Safety and reversibility
        4. Detection likelihood
        
        Return only the exploit IDs in order of priority.
        """
        
        try:
            response = self.ai_client.messages.create(
                model=self.config['api']['model'],
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Parse AI response to extract exploit selections
            # This is simplified - actual implementation would parse structured output
            return vuln_results.get('exploits', [])[:3]
        except Exception as e:
            logger.error(f"AI exploit selection error: {e}")
            return []
    
    async def _ai_analysis(self) -> Dict[str, Any]:
        """Final AI analysis of all findings"""
        
        prompt = f"""
        Provide a comprehensive security assessment based on these findings:
        
        {json.dumps(self.findings, indent=2)}
        
        Include:
        1. Executive summary
        2. Risk score (0-10)
        3. Top 5 recommendations
        4. Attack surface analysis
        5. Compliance considerations
        """
        
        try:
            response = self.ai_client.messages.create(
                model=self.config['api']['model'],
                max_tokens=4000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            analysis_text = response.content[0].text
            
            return {
                'summary': analysis_text,
                'risk_score': self._calculate_overall_risk(),
                'recommendations': self._extract_recommendations(analysis_text)
            }
        except Exception as e:
            logger.error(f"AI final analysis error: {e}")
            return {
                'summary': 'Analysis failed',
                'risk_score': 0.0,
                'recommendations': []
            }
    
    def _calculate_risk_level(self, vuln_results: Dict[str, Any]) -> str:
        """Calculate risk level based on vulnerabilities"""
        severity = vuln_results.get('severity_summary', {})
        
        if severity.get('critical', 0) > 0:
            return 'CRITICAL'
        elif severity.get('high', 0) > 2:
            return 'HIGH'
        elif severity.get('medium', 0) > 5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _calculate_overall_risk(self) -> float:
        """Calculate overall risk score (0-10)"""
        score = 0.0
        
        # Factor in CVE severity
        vuln_results = self.findings.get('vulnerability_assessment', {})
        severity = vuln_results.get('severity_summary', {})
        
        score += severity.get('critical', 0) * 2.5
        score += severity.get('high', 0) * 1.5
        score += severity.get('medium', 0) * 0.5
        score += severity.get('low', 0) * 0.1
        
        return min(score, 10.0)
    
    def _extract_recommendations(self, analysis_text: str) -> List[str]:
        """Extract recommendations from AI analysis"""
        # Simplified extraction - actual implementation would use better parsing
        recommendations = []
        lines = analysis_text.split('\n')
        
        in_recommendations = False
        for line in lines:
            if 'recommendation' in line.lower():
                in_recommendations = True
            elif in_recommendations and line.strip().startswith(('-', '•', '*', str)):
                recommendations.append(line.strip())
        
        return recommendations[:10]  # Top 10
    
    def _check_authorization(self, target: str) -> bool:
        """Check if we have authorization to test target"""
        auth_file = self.config.get('safety', {}).get('authorization_file')
        
        if not auth_file or not Path(auth_file).exists():
            return False
        
        try:
            with open(auth_file, 'r') as f:
                authorized_targets = [line.strip() for line in f.readlines()]
                return target in authorized_targets
        except Exception as e:
            logger.error(f"Error checking authorization: {e}")
            return False


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Assessment Workflow Engine')
    parser.add_argument('--target', required=True, help='Target IP/hostname/URL')
    parser.add_argument('--mode', default='full', choices=['quick', 'full', 'aggressive'],
                       help='Scan mode')
    parser.add_argument('--config', default='config/config.yaml', help='Config file path')
    
    args = parser.parse_args()
    
    engine = WorkflowEngine(config_path=args.config)
    result = await engine.run_workflow(args.target, args.mode)
    
    # Save results
    output_file = f"reports/workflow_{result.workflow_id}.json"
    os.makedirs('reports', exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(asdict(result), f, indent=2)
    
    print(f"\n{'='*80}")
    print(f"Workflow Complete: {result.workflow_id}")
    print(f"Target: {result.target}")
    print(f"Risk Score: {result.risk_score}/10")
    print(f"Stages Completed: {', '.join(result.stages_completed)}")
    print(f"Report saved to: {output_file}")
    print(f"{'='*80}\n")
    
    print("Summary:")
    print(result.summary[:500] + "..." if len(result.summary) > 500 else result.summary)


if __name__ == "__main__":
    asyncio.run(main())

