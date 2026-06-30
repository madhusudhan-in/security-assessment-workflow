"""
AI-Powered Security Assessment Workflow Engine

This module orchestrates security tools and makes intelligent decisions using AI.
It provides a comprehensive workflow for security assessments including reconnaissance,
vulnerability assessment, exploitation, and reporting.

Author: Security Assessment Team
Version: 2.0.0
"""

import asyncio
import logging
from logging.handlers import RotatingFileHandler
import yaml
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import sys
import os
from contextlib import asynccontextmanager
import hashlib

# Add parent directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anthropic import Anthropic, APIError, APITimeoutError
from tools.nmap_wrapper import NmapWrapper
from tools.zap_wrapper import ZAPWrapper
from tools.metasploit_wrapper import MetasploitWrapper
from utils.cve_lookup import CVELookup
from utils.exploit_search import ExploitSearch


# Configure structured logging with rotation
def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Configure structured logging with file rotation and console output.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path for persistent logging
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler with formatting
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation if log file specified
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5  # 10MB per file, 5 backups
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


logger = setup_logging(log_file="logs/workflow_engine.log")


class WorkflowMode(Enum):
    """Enumeration of workflow execution modes."""
    QUICK = "quick"
    FULL = "full"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"


class WorkflowStage(Enum):
    """Enumeration of workflow stages."""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class RiskLevel(Enum):
    """Enumeration of risk levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class WorkflowConfig:
    """
    Workflow configuration with validation.
    
    Attributes:
        target: Target IP/hostname/URL to assess
        mode: Workflow execution mode
        stages: List of stages to execute
        auto_exploit: Whether to automatically attempt exploitation
        max_concurrent: Maximum concurrent operations
        timeout: Overall workflow timeout in seconds
        retry_attempts: Number of retry attempts for failed operations
        rate_limit: Rate limiting for API calls (requests per minute)
    """
    target: str
    mode: WorkflowMode
    stages: List[WorkflowStage]
    auto_exploit: bool = False
    max_concurrent: int = 3
    timeout: int = 7200  # 2 hours default
    retry_attempts: int = 3
    rate_limit: int = 60  # requests per minute
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.target:
            raise ValueError("Target cannot be empty")
        
        if self.max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        
        if self.timeout < 60:
            raise ValueError("timeout must be at least 60 seconds")
        
        # Convert string mode to enum if needed
        if isinstance(self.mode, str):
            self.mode = WorkflowMode(self.mode)
        
        # Convert string stages to enums if needed
        self.stages = [
            WorkflowStage(stage) if isinstance(stage, str) else stage
            for stage in self.stages
        ]


@dataclass
class WorkflowResult:
    """
    Complete workflow execution result with metadata.
    
    Attributes:
        workflow_id: Unique workflow identifier
        target: Target that was assessed
        start_time: ISO format start timestamp
        end_time: ISO format end timestamp
        duration_seconds: Total execution time
        stages_completed: List of successfully completed stages
        findings: Detailed findings from all stages
        recommendations: AI-generated recommendations
        risk_score: Overall risk score (0-10)
        risk_level: Categorized risk level
        summary: Executive summary
        errors: List of errors encountered
        metadata: Additional metadata
    """
    workflow_id: str
    target: str
    start_time: str
    end_time: str
    duration_seconds: float
    stages_completed: List[str]
    findings: Dict[str, Any]
    recommendations: List[str]
    risk_score: float
    risk_level: str
    summary: str
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_json(self, filepath: str) -> None:
        """Save result to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(asdict(self), f, indent=2)
    
    def to_markdown(self, filepath: str) -> None:
        """Save result to Markdown report."""
        with open(filepath, 'w') as f:
            f.write(f"# Security Assessment Report\n\n")
            f.write(f"**Workflow ID:** {self.workflow_id}\n")
            f.write(f"**Target:** {self.target}\n")
            f.write(f"**Duration:** {self.duration_seconds:.2f} seconds\n")
            f.write(f"**Risk Score:** {self.risk_score}/10 ({self.risk_level})\n\n")
            f.write(f"## Executive Summary\n\n{self.summary}\n\n")
            f.write(f"## Recommendations\n\n")
            for i, rec in enumerate(self.recommendations, 1):
                f.write(f"{i}. {rec}\n")


class WorkflowEngineError(Exception):
    """Base exception for workflow engine errors."""
    pass


class ConfigurationError(WorkflowEngineError):
    """Configuration-related errors."""
    pass


class StageExecutionError(WorkflowEngineError):
    """Stage execution errors."""
    pass


class WorkflowEngine:
    """
    AI-powered security assessment workflow orchestrator.
    
    This class manages the complete security assessment workflow including:
    - Network reconnaissance and service discovery
    - Vulnerability assessment and CVE lookup
    - Controlled exploitation (with authorization)
    - AI-powered analysis and recommendations
    
    The engine uses async/await for concurrent operations and includes
    comprehensive error handling, retry logic, and rate limiting.
    """
    
    # Class-level constants
    DEFAULT_CONFIG_PATH = "config/config.yaml"
    DEFAULT_MODEL = "claude-3-5-sonnet-20241022"
    MAX_AI_RETRIES = 3
    AI_TIMEOUT = 30  # seconds
    
    def __init__(
        self,
        config_path: str = DEFAULT_CONFIG_PATH,
        log_level: str = "INFO"
    ):
        """
        Initialize the workflow engine.
        
        Args:
            config_path: Path to YAML configuration file
            log_level: Logging level
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        
        # Update logger level if specified
        logger.setLevel(getattr(logging, log_level.upper()))
        
        # Initialize AI client with error handling
        try:
            api_key = self.config['api']['anthropic_api_key']
            if not api_key:
                raise ConfigurationError("Anthropic API key not configured")
            self.ai_client = Anthropic(api_key=api_key)
        except KeyError as e:
            raise ConfigurationError(f"Missing API configuration: {e}")
        
        # Initialize tool wrappers with lazy loading
        self._nmap = None
        self._cve_lookup = None
        self._exploit_search = None
        self._zap = None
        self._msf = None
        
        # Workflow state management
        self.current_workflow: Optional[WorkflowConfig] = None
        self.findings: Dict[str, Any] = {}
        self.errors: List[str] = []
        
        # Rate limiting
        self._last_ai_call = datetime.now()
        self._ai_call_count = 0
        
        logger.info(f"WorkflowEngine initialized with config: {config_path}")
    
    @property
    def nmap(self) -> NmapWrapper:
        """Lazy-load Nmap wrapper."""
        if self._nmap is None:
            nmap_path = self.config.get('tools', {}).get('nmap', {}).get('path', '/usr/bin/nmap')
            self._nmap = NmapWrapper(nmap_path)
        return self._nmap
    
    @property
    def cve_lookup(self) -> CVELookup:
        """Lazy-load CVE lookup utility."""
        if self._cve_lookup is None:
            api_key = self.config.get('vulnerability_databases', {}).get('nvd', {}).get('api_key')
            self._cve_lookup = CVELookup(api_key)
        return self._cve_lookup
    
    @property
    def exploit_search(self) -> ExploitSearch:
        """Lazy-load exploit search utility."""
        if self._exploit_search is None:
            self._exploit_search = ExploitSearch()
        return self._exploit_search
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load and validate configuration from YAML file.
        
        Returns:
            Configuration dictionary
            
        Raises:
            ConfigurationError: If configuration is invalid or missing
        """
        if not self.config_path.exists():
            logger.warning(f"Config file not found: {self.config_path}, using defaults")
            return self._get_default_config()
        
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Validate required sections
            required_sections = ['api', 'tools', 'workflow']
            for section in required_sections:
                if section not in config:
                    logger.warning(f"Missing config section: {section}, using defaults")
                    config[section] = self._get_default_config()[section]
            
            logger.info("Configuration loaded successfully")
            return config
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML configuration: {e}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            'api': {
                'anthropic_api_key': os.getenv('ANTHROPIC_API_KEY', ''),
                'model': self.DEFAULT_MODEL
            },
            'tools': {
                'nmap': {'path': '/usr/bin/nmap'},
                'zap': {'enabled': False},
                'metasploit': {'enabled': False}
            },
            'vulnerability_databases': {
                'nvd': {'api_key': os.getenv('NVD_API_KEY')}
            },
            'workflow': {
                'auto_exploit': False,
                'max_concurrent_scans': 3,
                'timeout': 7200,
                'retry_attempts': 3
            },
            'safety': {
                'authorization_file': 'config/authorized_targets.txt'
            }
        }
    
    async def run_workflow(
        self,
        target: str,
        mode: str = "full",
        custom_stages: Optional[List[str]] = None
    ) -> WorkflowResult:
        """
        Execute complete security assessment workflow.
        
        Args:
            target: Target IP/hostname/URL
            mode: Workflow mode (quick, full, aggressive, custom)
            custom_stages: Custom stages for 'custom' mode
            
        Returns:
            WorkflowResult object with complete assessment results
            
        Raises:
            WorkflowEngineError: If workflow execution fails
        """
        workflow_id = self._generate_workflow_id(target)
        start_time = datetime.now()
        
        logger.info(f"Starting workflow {workflow_id} for target {target} in {mode} mode")
        
        try:
            # Initialize workflow configuration
            stages = self._get_stages_for_mode(mode, custom_stages)
            self.current_workflow = WorkflowConfig(
                target=target,
                mode=WorkflowMode(mode),
                stages=stages,
                auto_exploit=self.config['workflow'].get('auto_exploit', False),
                max_concurrent=self.config['workflow'].get('max_concurrent_scans', 3),
                timeout=self.config['workflow'].get('timeout', 7200),
                retry_attempts=self.config['workflow'].get('retry_attempts', 3)
            )
            
            # Reset state
            self.findings = {}
            self.errors = []
            stages_completed = []
            
            # Execute workflow stages with timeout
            async with asyncio.timeout(self.current_workflow.timeout):
                for stage in self.current_workflow.stages:
                    try:
                        await self._execute_stage(stage, target, stages_completed)
                    except Exception as e:
                        error_msg = f"Stage {stage.value} failed: {str(e)}"
                        logger.error(error_msg)
                        self.errors.append(error_msg)
                        # Continue with other stages unless critical
                        if stage == WorkflowStage.RECONNAISSANCE:
                            raise StageExecutionError(f"Critical stage failed: {error_msg}")
            
            # Generate final AI analysis
            logger.info("Generating final AI analysis")
            analysis = await self._ai_analysis()
            
            # Calculate results
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            result = WorkflowResult(
                workflow_id=workflow_id,
                target=target,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                duration_seconds=duration,
                stages_completed=[s.value for s in stages_completed],
                findings=self.findings,
                recommendations=analysis.get('recommendations', []),
                risk_score=analysis.get('risk_score', 0.0),
                risk_level=self._get_risk_level(analysis.get('risk_score', 0.0)).value,
                summary=analysis.get('summary', 'Analysis completed'),
                errors=self.errors,
                metadata={
                    'mode': mode,
                    'config_path': str(self.config_path),
                    'ai_model': self.config['api']['model']
                }
            )
            
            logger.info(f"Workflow {workflow_id} completed successfully")
            return result
            
        except asyncio.TimeoutError:
            error_msg = f"Workflow timeout after {self.current_workflow.timeout} seconds"
            logger.error(error_msg)
            raise WorkflowEngineError(error_msg)
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}", exc_info=True)
            raise WorkflowEngineError(f"Workflow failed: {str(e)}")
    
    def _generate_workflow_id(self, target: str) -> str:
        """Generate unique workflow ID."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_hash = hashlib.md5(target.encode()).hexdigest()[:8]
        return f"workflow_{timestamp}_{target_hash}"
    
    def _get_stages_for_mode(
        self,
        mode: str,
        custom_stages: Optional[List[str]] = None
    ) -> List[WorkflowStage]:
        """Get workflow stages based on mode."""
        if mode == "custom" and custom_stages:
            return [WorkflowStage(s) for s in custom_stages]
        
        stage_map = {
            "quick": [WorkflowStage.RECONNAISSANCE, WorkflowStage.REPORTING],
            "full": [
                WorkflowStage.RECONNAISSANCE,
                WorkflowStage.VULNERABILITY_ASSESSMENT,
                WorkflowStage.REPORTING
            ],
            "aggressive": [
                WorkflowStage.RECONNAISSANCE,
                WorkflowStage.VULNERABILITY_ASSESSMENT,
                WorkflowStage.EXPLOITATION,
                WorkflowStage.REPORTING
            ]
        }
        
        return stage_map.get(mode, stage_map["full"])
    
    async def _execute_stage(
        self,
        stage: WorkflowStage,
        target: str,
        stages_completed: List[WorkflowStage]
    ) -> None:
        """Execute a single workflow stage with retry logic."""
        logger.info(f"Executing stage: {stage.value}")
        
        stage_methods = {
            WorkflowStage.RECONNAISSANCE: self._stage_reconnaissance,
            WorkflowStage.VULNERABILITY_ASSESSMENT: self._stage_vulnerability_assessment,
            WorkflowStage.EXPLOITATION: self._stage_exploitation,
            WorkflowStage.REPORTING: self._stage_reporting
        }
        
        method = stage_methods.get(stage)
        if not method:
            raise StageExecutionError(f"Unknown stage: {stage}")
        
        # Execute with retry logic
        for attempt in range(self.current_workflow.retry_attempts):
            try:
                if stage == WorkflowStage.RECONNAISSANCE:
                    result = await method(target)
                elif stage == WorkflowStage.VULNERABILITY_ASSESSMENT:
                    recon_results = self.findings.get('reconnaissance', {})
                    result = await method(target, recon_results)
                elif stage == WorkflowStage.EXPLOITATION:
                    vuln_results = self.findings.get('vulnerability_assessment', {})
                    result = await method(target, vuln_results)
                else:
                    result = await method()
                
                self.findings[stage.value] = result
                stages_completed.append(stage)
                logger.info(f"Stage {stage.value} completed successfully")
                return
                
            except Exception as e:
                logger.warning(f"Stage {stage.value} attempt {attempt + 1} failed: {e}")
                if attempt == self.current_workflow.retry_attempts - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
    
    async def _stage_reconnaissance(self, target: str) -> Dict[str, Any]:
        """
        Stage 1: Network reconnaissance and service discovery.
        
        Performs comprehensive network scanning including:
        - Port scanning
        - Service detection
        - OS fingerprinting
        - NSE vulnerability scripts
        
        Args:
            target: Target to scan
            
        Returns:
            Dictionary containing reconnaissance results
        """
        results = {
            'nmap_scan': None,
            'open_ports': [],
            'services': [],
            'os_detection': None,
            'nse_scripts': None,
            'scan_metadata': {
                'start_time': datetime.now().isoformat(),
                'target': target
            }
        }
        
        try:
            # Run Nmap scan with timeout
            logger.info(f"Running Nmap scan on {target}")
            nmap_result = await asyncio.wait_for(
                asyncio.to_thread(self.nmap.full_scan, target),
                timeout=600  # 10 minutes
            )
            results['nmap_scan'] = asdict(nmap_result)
            
            # Extract and structure port/service information
            for host in nmap_result.hosts:
                for port in host.ports:
                    if port.state == 'open':
                        port_info = {
                            'port': port.port,
                            'protocol': port.protocol,
                            'service': port.service,
                            'version': port.version,
                            'product': port.product,
                            'state': port.state
                        }
                        results['open_ports'].append(port_info)
                        
                        service_info = {
                            **port_info,
                            'cpe': port.cpe,
                            'extrainfo': getattr(port, 'extrainfo', None)
                        }
                        results['services'].append(service_info)
                
                results['os_detection'] = host.os
            
            # Run NSE vulnerability scripts if ports found
            if results['open_ports']:
                logger.info("Running NSE vulnerability scripts")
                vuln_scan = await asyncio.wait_for(
                    asyncio.to_thread(self.nmap.vulnerability_scan, target),
                    timeout=900  # 15 minutes
                )
                results['nse_scripts'] = asdict(vuln_scan)
            
            # AI-powered next steps recommendation
            logger.info("Getting AI recommendations for next steps")
            ai_decision = await self._ai_decide_next_steps(results)
            results['ai_recommendations'] = ai_decision
            
            results['scan_metadata']['end_time'] = datetime.now().isoformat()
            results['scan_metadata']['ports_found'] = len(results['open_ports'])
            
        except asyncio.TimeoutError:
            error_msg = "Reconnaissance stage timeout"
            logger.error(error_msg)
            results['error'] = error_msg
            raise StageExecutionError(error_msg)
        except Exception as e:
            error_msg = f"Reconnaissance stage error: {str(e)}"
            logger.error(error_msg, exc_info=True)
            results['error'] = error_msg
            raise
        
        return results
    
    async def _stage_vulnerability_assessment(
        self,
        target: str,
        recon_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Stage 2: Vulnerability assessment and CVE lookup.
        
        Performs comprehensive vulnerability assessment including:
        - CVE lookup for discovered services
        - Exploit availability checking
        - Web application scanning (if applicable)
        - Severity analysis and prioritization
        
        Args:
            target: Target being assessed
            recon_results: Results from reconnaissance stage
            
        Returns:
            Dictionary containing vulnerability assessment results
        """
        results = {
            'cves': [],
            'exploits': [],
            'web_vulnerabilities': [],
            'severity_summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'assessment_metadata': {
                'start_time': datetime.now().isoformat(),
                'target': target
            }
        }
        
        try:
            services = recon_results.get('services', [])
            logger.info(f"Assessing {len(services)} services for vulnerabilities")
            
            # CVE lookup with concurrent processing
            cve_tasks = []
            for service in services:
                if service.get('product') and service.get('version'):
                    task = self._lookup_service_cves(service)
                    cve_tasks.append(task)
            
            # Process CVE lookups concurrently with limit
            if cve_tasks:
                semaphore = asyncio.Semaphore(self.current_workflow.max_concurrent)
                async def bounded_task(task):
                    async with semaphore:
                        return await task
                
                cve_results = await asyncio.gather(
                    *[bounded_task(task) for task in cve_tasks],
                    return_exceptions=True
                )
                
                # Aggregate CVE results
                for result in cve_results:
                    if isinstance(result, Exception):
                        logger.warning(f"CVE lookup failed: {result}")
                        continue
                    if result:
                        results['cves'].extend(result)
            
            # Update severity summary
            for cve in results['cves']:
                severity = self._normalize_severity(cve.get('severity'), cve.get('cvss_score', 0))
                results['severity_summary'][severity] += 1
            
            # Search for exploits
            logger.info("Searching for available exploits")
            exploit_tasks = [
                self._search_exploits(cve['cve_id'])
                for cve in results['cves']
                if cve.get('exploits_available')
            ]
            
            if exploit_tasks:
                exploit_results = await asyncio.gather(*exploit_tasks, return_exceptions=True)
                for exploits in exploit_results:
                    if isinstance(exploits, Exception):
                        continue
                    if exploits:
                        results['exploits'].extend(exploits)
            
            # Web application scanning for HTTP/HTTPS services
            http_ports = [
                p for p in recon_results.get('open_ports', [])
                if p['service'] in ['http', 'https', 'http-proxy', 'ssl/http']
            ]
            
            if http_ports and self.config['tools'].get('zap', {}).get('enabled'):
                logger.info("Performing web application scan")
                web_scan_results = await self._web_application_scan(target, http_ports)
                results['web_vulnerabilities'] = web_scan_results
            
            # AI-powered vulnerability analysis
            logger.info("Performing AI vulnerability analysis")
            ai_analysis = await self._ai_analyze_vulnerabilities(results)
            results['ai_analysis'] = ai_analysis
            
            results['assessment_metadata']['end_time'] = datetime.now().isoformat()
            results['assessment_metadata']['total_cves'] = len(results['cves'])
            results['assessment_metadata']['total_exploits'] = len(results['exploits'])
            
        except Exception as e:
            error_msg = f"Vulnerability assessment error: {str(e)}"
            logger.error(error_msg, exc_info=True)
            results['error'] = error_msg
            raise
        
        return results
    
    async def _lookup_service_cves(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Lookup CVEs for a specific service."""
        try:
            product = service.get('product', '')
            version = service.get('version', '')
            
            if not product or not version:
                return []
            
            # Extract vendor from product (simplified)
            vendor = product.split()[0] if product else ''
            
            cves = await asyncio.to_thread(
                self.cve_lookup.search_by_product,
                vendor=vendor,
                product=product,
                version=version
            )
            
            return [
                {
                    'cve_id': cve.cve_id,
                    'service': service.get('service'),
                    'port': service.get('port'),
                    'severity': cve.severity,
                    'cvss_score': cve.cvss_score,
                    'description': cve.description,
                    'exploits_available': cve.exploits_available,
                    'published_date': getattr(cve, 'published_date', None),
                    'references': getattr(cve, 'references', [])
                }
                for cve in cves
            ]
        except Exception as e:
            logger.warning(f"CVE lookup failed for {service.get('product')}: {e}")
            return []
    
    async def _search_exploits(self, cve_id: str) -> List[Dict[str, Any]]:
        """Search for exploits for a specific CVE."""
        try:
            exploits = await asyncio.to_thread(
                self.exploit_search.search_by_cve,
                cve_id
            )
            
            return [
                {
                    'cve_id': cve_id,
                    'exploit_id': exploit.exploit_id,
                    'title': exploit.title,
                    'source_url': exploit.source_url,
                    'verified': exploit.verified,
                    'platform': getattr(exploit, 'platform', None),
                    'type': getattr(exploit, 'type', None)
                }
                for exploit in exploits
            ]
        except Exception as e:
            logger.warning(f"Exploit search failed for {cve_id}: {e}")
            return []
    
    async def _web_application_scan(
        self,
        target: str,
        http_ports: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Perform web application vulnerability scanning."""
        # Placeholder for ZAP integration
        logger.info(f"Web scan would be performed on {len(http_ports)} HTTP services")
        return []
    
    def _normalize_severity(self, severity: Optional[str], cvss_score: float) -> str:
        """Normalize severity to standard levels."""
        if severity:
            severity_lower = severity.lower()
            if severity_lower in ['critical', 'high', 'medium', 'low', 'info']:
                return severity_lower
        
        # Fallback to CVSS score
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score > 0:
            return 'low'
        else:
            return 'info'
    
    async def _stage_exploitation(
        self,
        target: str,
        vuln_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Stage 3: Controlled exploitation (requires authorization).
        
        WARNING: This stage performs actual exploitation attempts and should
        only be used with explicit written authorization.
        
        Args:
            target: Target to exploit
            vuln_results: Vulnerability assessment results
            
        Returns:
            Dictionary containing exploitation results
        """
        results = {
            'exploits_attempted': [],
            'successful_exploits': [],
            'failed_exploits': [],
            'authorization_checked': False,
            'exploitation_metadata': {
                'start_time': datetime.now().isoformat(),
                'target': target
            }
        }
        
        logger.warning("⚠️  EXPLOITATION STAGE - Requires explicit authorization!")
        
        try:
            # Check authorization
            if not self._check_authorization(target):
                error_msg = f"No authorization found for exploitation of {target}"
                logger.error(error_msg)
                results['error'] = error_msg
                results['authorization_checked'] = True
                return results
            
            results['authorization_checked'] = True
            logger.info(f"Authorization confirmed for {target}")
            
            # AI-powered exploit selection
            exploits_to_try = await self._ai_select_exploits(vuln_results)
            
            if not exploits_to_try:
                logger.info("No exploits selected for execution")
                return results
            
            # Execute selected exploits with safety checks
            for exploit_info in exploits_to_try:
                logger.info(f"Attempting exploit: {exploit_info.get('title')}")
                
                exploit_result = await self._execute_exploit(target, exploit_info)
                
                results['exploits_attempted'].append(exploit_info)
                
                if exploit_result.get('success'):
                    results['successful_exploits'].append({
                        **exploit_info,
                        'result': exploit_result
                    })
                else:
                    results['failed_exploits'].append({
                        **exploit_info,
                        'error': exploit_result.get('error')
                    })
            
            results['exploitation_metadata']['end_time'] = datetime.now().isoformat()
            results['exploitation_metadata']['success_rate'] = (
                len(results['successful_exploits']) / len(results['exploits_attempted'])
                if results['exploits_attempted'] else 0
            )
            
        except Exception as e:
            error_msg = f"Exploitation stage error: {str(e)}"
            logger.error(error_msg, exc_info=True)
            results['error'] = error_msg
        
        return results
    
    async def _execute_exploit(
        self,
        target: str,
        exploit_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a single exploit (placeholder for Metasploit integration)."""
        # Placeholder - actual implementation would use Metasploit
        logger.info(f"Exploit execution placeholder for: {exploit_info.get('exploit_id')}")
        return {
            'success': False,
            'note': 'Metasploit integration required for actual exploitation'
        }
    
    async def _stage_reporting(self) -> Dict[str, Any]:
        """Stage 4: Generate comprehensive report."""
        return {
            'report_generated': True,
            'timestamp': datetime.now().isoformat()
        }
    
    async def _ai_decide_next_steps(self, recon_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to decide next steps based on reconnaissance."""
        prompt = f"""
Analyze the following network reconnaissance results and recommend next steps:

Open Ports: {len(recon_results.get('open_ports', []))}
Services Discovered: {json.dumps(recon_results.get('services', [])[:5], indent=2)}

Based on these findings:
1. What are the most critical services to investigate?
2. What specific vulnerability checks should be prioritized?
3. Are there any immediate security concerns?
4. What is the attack surface assessment?

Provide a structured response with priorities and reasoning.
"""
        
        try:
            response = await self._call_ai_with_retry(prompt, max_tokens=2000)
            
            return {
                'recommendations': response,
                'priority_services': [
                    s['service'] for s in recon_results.get('services', [])[:3]
                ],
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"AI decision error: {e}")
            return {'error': str(e)}
    
    async def _ai_analyze_vulnerabilities(self, vuln_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to analyze vulnerabilities and prioritize."""
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
3. Recommended mitigation strategies (specific and actionable)
4. Exploitation difficulty assessment
5. Business impact analysis
"""
        
        try:
            response = await self._call_ai_with_retry(prompt, max_tokens=3000)
            
            return {
                'analysis': response,
                'risk_level': self._calculate_risk_level(vuln_results),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return {'error': str(e)}
    
    async def _ai_select_exploits(self, vuln_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use AI to select which exploits to attempt."""
        exploits = vuln_results.get('exploits', [])[:10]
        
        if not exploits:
            return []
        
        prompt = f"""
Given these vulnerabilities and available exploits:

{json.dumps(exploits, indent=2)}

Select the top 3 exploits to attempt, considering:
1. Success probability
2. Impact if successful
3. Safety and reversibility
4. Detection likelihood
5. Ethical considerations

Return a JSON array with exploit IDs in order of priority.
Format: ["exploit_id_1", "exploit_id_2", "exploit_id_3"]
"""
        
        try:
            response = await self._call_ai_with_retry(prompt, max_tokens=1000)
            
            # Parse AI response (simplified - would need better parsing)
            # For now, return top 3 exploits
            return exploits[:3]
        except Exception as e:
            logger.error(f"AI exploit selection error: {e}")
            return []
    
    async def _ai_analysis(self) -> Dict[str, Any]:
        """Final AI analysis of all findings."""
        prompt = f"""
Provide a comprehensive security assessment based on these findings:

{json.dumps(self.findings, indent=2)[:10000]}  # Limit to avoid token limits

Include:
1. Executive summary (2-3 paragraphs)
2. Overall risk score (0-10) with justification
3. Top 10 prioritized recommendations (specific and actionable)
4. Attack surface analysis
5. Compliance considerations (OWASP, CIS, etc.)
6. Remediation timeline suggestions

Format the response as structured text with clear sections.
"""
        
        try:
            response = await self._call_ai_with_retry(prompt, max_tokens=4000)
            
            return {
                'summary': response,
                'risk_score': self._calculate_overall_risk(),
                'recommendations': self._extract_recommendations(response),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"AI final analysis error: {e}")
            return {
                'summary': f'Analysis failed: {str(e)}',
                'risk_score': 0.0,
                'recommendations': [],
                'error': str(e)
            }
    
    async def _call_ai_with_retry(
        self,
        prompt: str,
        max_tokens: int = 2000
    ) -> str:
        """
        Call AI API with retry logic and rate limiting.
        
        Args:
            prompt: Prompt to send to AI
            max_tokens: Maximum tokens in response
            
        Returns:
            AI response text
            
        Raises:
            Exception: If all retries fail
        """
        # Rate limiting
        await self._apply_rate_limit()
        
        for attempt in range(self.MAX_AI_RETRIES):
            try:
                response = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.ai_client.messages.create,
                        model=self.config['api']['model'],
                        max_tokens=max_tokens,
                        messages=[{"role": "user", "content": prompt}]
                    ),
                    timeout=self.AI_TIMEOUT
                )
                
                self._ai_call_count += 1
                return response.content[0].text
                
            except (APIError, APITimeoutError) as e:
                logger.warning(f"AI API call attempt {attempt + 1} failed: {e}")
                if attempt == self.MAX_AI_RETRIES - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            except asyncio.TimeoutError:
                logger.warning(f"AI API call timeout on attempt {attempt + 1}")
                if attempt == self.MAX_AI_RETRIES - 1:
                    raise Exception("AI API timeout after all retries")
                await asyncio.sleep(2 ** attempt)
    
    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting for AI API calls."""
        now = datetime.now()
        time_since_last = (now - self._last_ai_call).total_seconds()
        
        # Reset counter if more than a minute has passed
        if time_since_last > 60:
            self._ai_call_count = 0
        
        # Wait if we've hit the rate limit
        if self._ai_call_count >= self.current_workflow.rate_limit:
            wait_time = 60 - time_since_last
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.2f} seconds")
                await asyncio.sleep(wait_time)
                self._ai_call_count = 0
        
        self._last_ai_call = now
    
    def _calculate_risk_level(self, vuln_results: Dict[str, Any]) -> str:
        """Calculate risk level based on vulnerabilities."""
        severity = vuln_results.get('severity_summary', {})
        
        if severity.get('critical', 0) > 0:
            return RiskLevel.CRITICAL.value
        elif severity.get('high', 0) > 2:
            return RiskLevel.HIGH.value
        elif severity.get('medium', 0) > 5:
            return RiskLevel.MEDIUM.value
        elif severity.get('low', 0) > 0:
            return RiskLevel.LOW.value
        else:
            return RiskLevel.INFO.value
    
    def _calculate_overall_risk(self) -> float:
        """
        Calculate overall risk score (0-10) based on all findings.
        
        Returns:
            Risk score between 0 and 10
        """
        score = 0.0
        
        # Factor in CVE severity with weighted scoring
        vuln_results = self.findings.get('vulnerability_assessment', {})
        severity = vuln_results.get('severity_summary', {})
        
        score += severity.get('critical', 0) * 2.5
        score += severity.get('high', 0) * 1.5
        score += severity.get('medium', 0) * 0.5
        score += severity.get('low', 0) * 0.1
        
        # Factor in exploit availability
        exploits = len(vuln_results.get('exploits', []))
        score += min(exploits * 0.3, 2.0)  # Cap at 2.0
        
        # Factor in successful exploitations
        exploit_results = self.findings.get('exploitation', {})
        successful = len(exploit_results.get('successful_exploits', []))
        score += successful * 1.0
        
        return min(score, 10.0)
    
    def _get_risk_level(self, risk_score: float) -> RiskLevel:
        """Convert risk score to risk level."""
        if risk_score >= 9.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 7.0:
            return RiskLevel.HIGH
        elif risk_score >= 4.0:
            return RiskLevel.MEDIUM
        elif risk_score > 0:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _extract_recommendations(self, analysis_text: str) -> List[str]:
        """
        Extract recommendations from AI analysis text.
        
        Args:
            analysis_text: AI-generated analysis text
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        lines = analysis_text.split('\n')
        
        in_recommendations = False
        for line in lines:
            line_lower = line.lower()
            
            # Detect recommendations section
            if any(keyword in line_lower for keyword in ['recommendation', 'remediation', 'mitigation']):
                in_recommendations = True
                continue
            
            # Extract numbered or bulleted items
            if in_recommendations:
                stripped = line.strip()
                if stripped and any(stripped.startswith(prefix) for prefix in ['-', '•', '*', '1', '2', '3', '4', '5', '6', '7', '8', '9']):
                    # Clean up the recommendation text
                    rec = stripped.lstrip('-•*0123456789. ')
                    if rec and len(rec) > 10:  # Filter out very short items
                        recommendations.append(rec)
                elif stripped and not stripped[0].isalnum():
                    # Stop if we hit a new section
                    break
        
        return recommendations[:10]  # Return top 10
    
    def _check_authorization(self, target: str) -> bool:
        """
        Check if we have authorization to test target.
        
        Args:
            target: Target to check authorization for
            
        Returns:
            True if authorized, False otherwise
        """
        auth_file = self.config.get('safety', {}).get('authorization_file')
        
        if not auth_file:
            logger.warning("No authorization file configured")
            return False
        
        auth_path = Path(auth_file)
        if not auth_path.exists():
            logger.warning(f"Authorization file not found: {auth_file}")
            return False
        
        try:
            with open(auth_path, 'r') as f:
                authorized_targets = {line.strip() for line in f if line.strip() and not line.startswith('#')}
                
                # Check exact match or wildcard patterns
                if target in authorized_targets:
                    return True
                
                # Check for wildcard matches (simplified)
                for auth_target in authorized_targets:
                    if '*' in auth_target:
                        pattern = auth_target.replace('.', '[.]').replace('*', '.*')