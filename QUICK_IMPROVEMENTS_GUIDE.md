# Quick Improvements Guide for workflow_engine.py

This guide provides ready-to-use code snippets to improve the original `workflow_engine.py` file.

---

## 1. Add Enhanced Imports (Lines 1-20)

Replace the import section with:

```python
"""
AI-Powered Security Assessment Workflow Engine

This module orchestrates security tools and makes intelligent decisions using AI.
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
import hashlib
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anthropic import Anthropic, APIError, APITimeoutError
from tools.nmap_wrapper import NmapWrapper
from tools.zap_wrapper import ZAPWrapper
from tools.metasploit_wrapper import MetasploitWrapper
from utils.cve_lookup import CVELookup
from utils.exploit_search import ExploitSearch
```

---

## 2. Add Enumerations (After imports)

```python
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
```

---

## 3. Add Custom Exceptions (After enums)

```python
class WorkflowEngineError(Exception):
    """Base exception for workflow engine errors."""
    pass


class ConfigurationError(WorkflowEngineError):
    """Configuration-related errors."""
    pass


class StageExecutionError(WorkflowEngineError):
    """Stage execution errors."""
    pass
```

---

## 4. Improve Logging Setup (Replace lines 27-28)

```python
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
    
    if logger.handlers:
        return logger
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setFormatter(console_formatter)
        logger.addHandler(file_handler)
    
    return logger


logger = setup_logging(log_file="logs/workflow_engine.log")
```

---

## 5. Enhance WorkflowConfig Dataclass (Replace lines 31-40)

```python
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
    timeout: int = 7200
    retry_attempts: int = 3
    rate_limit: int = 60
    
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
```

---

## 6. Enhance WorkflowResult Dataclass (Replace lines 42-54)

```python
@dataclass
class WorkflowResult:
    """
    Complete workflow execution result with metadata.
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
```

---

## 7. Add Lazy Loading Properties to WorkflowEngine

Add these properties to the WorkflowEngine class:

```python
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
```

And update __init__ to use lazy loading:

```python
def __init__(self, config_path: str = "config/config.yaml", log_level: str = "INFO"):
    self.config_path = Path(config_path)
    self.config = self._load_config()
    
    # Update logger level
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Initialize AI client
    try:
        api_key = self.config['api']['anthropic_api_key']
        if not api_key:
            raise ConfigurationError("Anthropic API key not configured")
        self.ai_client = Anthropic(api_key=api_key)
    except KeyError as e:
        raise ConfigurationError(f"Missing API configuration: {e}")
    
    # Lazy-loaded tool wrappers
    self._nmap = None
    self._cve_lookup = None
    self._exploit_search = None
    self._zap = None
    self._msf = None
    
    # Workflow state
    self.current_workflow: Optional[WorkflowConfig] = None
    self.findings: Dict[str, Any] = {}
    self.errors: List[str] = []
    
    # Rate limiting
    self._last_ai_call = datetime.now()
    self._ai_call_count = 0
    
    logger.info(f"WorkflowEngine initialized with config: {config_path}")
```

---

## 8. Add Retry Logic Method

Add this method to WorkflowEngine class:

```python
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
            
            self.findings[stage.value] = result
            stages_completed.append(stage)
            logger.info(f"Stage {stage.value} completed successfully")
            return
            
        except Exception as e:
            logger.warning(f"Stage {stage.value} attempt {attempt + 1} failed: {e}")
            if attempt == self.current_workflow.retry_attempts - 1:
                raise
            await asyncio.sleep(2 ** attempt)  # Exponential backoff
```

---

## 9. Add AI Rate Limiting

Add these methods to WorkflowEngine class:

```python
async def _apply_rate_limit(self) -> None:
    """Apply rate limiting for AI API calls."""
    now = datetime.now()
    time_since_last = (now - self._last_ai_call).total_seconds()
    
    if time_since_last > 60:
        self._ai_call_count = 0
    
    if self._ai_call_count >= self.current_workflow.rate_limit:
        wait_time = 60 - time_since_last
        if wait_time > 0:
            logger.info(f"Rate limit reached, waiting {wait_time:.2f} seconds")
            await asyncio.sleep(wait_time)
            self._ai_call_count = 0
    
    self._last_ai_call = now

async def _call_ai_with_retry(self, prompt: str, max_tokens: int = 2000) -> str:
    """Call AI API with retry logic and rate limiting."""
    await self._apply_rate_limit()
    
    MAX_AI_RETRIES = 3
    AI_TIMEOUT = 30
    
    for attempt in range(MAX_AI_RETRIES):
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self.ai_client.messages.create,
                    model=self.config['api']['model'],
                    max_tokens=max_tokens,
                    messages=[{"role": "user", "content": prompt}]
                ),
                timeout=AI_TIMEOUT
            )
            self._ai_call_count += 1
            return response.content[0].text
            
        except (APIError, APITimeoutError) as e:
            logger.warning(f"AI API call attempt {attempt + 1} failed: {e}")
            if attempt == MAX_AI_RETRIES - 1:
                raise
            await asyncio.sleep(2 ** attempt)
        except asyncio.TimeoutError:
            logger.warning(f"AI API call timeout on attempt {attempt + 1}")
            if attempt == MAX_AI_RETRIES - 1:
                raise Exception("AI API timeout after all retries")
            await asyncio.sleep(2 ** attempt)
```

---

## 10. Add Unique Workflow ID Generation

Replace the workflow ID generation in `run_workflow`:

```python
def _generate_workflow_id(self, target: str) -> str:
    """Generate unique workflow ID."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    target_hash = hashlib.md5(target.encode()).hexdigest()[:8]
    return f"workflow_{timestamp}_{target_hash}"

# In run_workflow method, replace:
# workflow_id = f"workflow_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
# with:
workflow_id = self._generate_workflow_id(target)
```

---

## 11. Add Concurrent CVE Lookup

Replace the CVE lookup section in `_stage_vulnerability_assessment`:

```python
# Create tasks for concurrent CVE lookup
cve_tasks = []
for service in services:
    if service.get('product') and service.get('version'):
        task = self._lookup_service_cves(service)
        cve_tasks.append(task)

# Process with concurrency limit
if cve_tasks:
    semaphore = asyncio.Semaphore(self.current_workflow.max_concurrent)
    
    async def bounded_task(task):
        async with semaphore:
            return await task
    
    cve_results = await asyncio.gather(
        *[bounded_task(task) for task in cve_tasks],
        return_exceptions=True
    )
    
    # Aggregate results
    for result in cve_results:
        if isinstance(result, Exception):
            logger.warning(f"CVE lookup failed: {result}")
            continue
        if result:
            results['cves'].extend(result)

# Add this helper method:
async def _lookup_service_cves(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Lookup CVEs for a specific service."""
    try:
        product = service.get('product', '')
        version = service.get('version', '')
        
        if not product or not version:
            return []
        
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
            }
            for cve in cves
        ]
    except Exception as e:
        logger.warning(f"CVE lookup failed for {service.get('product')}: {e}")
        return []
```

---

## 12. Improve Authorization Checking

Replace the `_check_authorization` method:

```python
def _check_authorization(self, target: str) -> bool:
    """Check if we have authorization to test target with wildcard support."""
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
            authorized_targets = {
                line.strip() for line in f 
                if line.strip() and not line.startswith('#')
            }
            
            # Exact match
            if target in authorized_targets:
                return True
            
            # Wildcard matching
            for auth_target in authorized_targets:
                if '*' in auth_target:
                    pattern = auth_target.replace('.', r'\.').replace('*', '.*')
                    if re.match(f'^{pattern}$', target):
                        return True
            
            return False
    except Exception as e:
        logger.error(f"Error checking authorization: {e}")
        return False
```

---

## 13. Add Timeout to run_workflow

Wrap the stage execution in `run_workflow` with timeout:

```python
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
```

---

## 14. Enhanced Main Function

Replace the main() function with:

```python
async def main():
    """Main entry point for the workflow engine."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='AI-Powered Security Assessment Workflow Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--target', required=True, help='Target IP/hostname/URL')
    parser.add_argument('--mode', default='full', 
                       choices=['quick', 'full', 'aggressive'],
                       help='Scan mode (default: full)')
    parser.add_argument('--config', default='config/config.yaml',
                       help='Config file path')
    parser.add_argument('--output-dir', default='reports',
                       help='Output directory for reports')
    parser.add_argument('--log-level', default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Logging level')
    parser.add_argument('--format', default='json',
                       choices=['json', 'markdown', 'both'],
                       help='Output format')
    
    args = parser.parse_args()
    
    try:
        engine = WorkflowEngine(config_path=args.config, log_level=args.log_level)
        result = await engine.run_workflow(args.target, args.mode)
        
        # Create output directory
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save results
        base_filename = f"workflow_{result.workflow_id}"
        
        if args.format in ['json', 'both']:
            json_file = output_dir / f"{base_filename}.json"
            result.to_json(str(json_file))
            print(f"JSON report saved to: {json_file}")
        
        if args.format in ['markdown', 'both']:
            md_file = output_dir / f"{base_filename}.md"
            result.to_markdown(str(md_file))
            print(f"Markdown report saved to: {md_file}")
        
        # Print summary
        print(f"\n{'='*80}")
        print(f"Workflow Complete: {result.workflow_id}")
        print(f"Target: {result.target}")
        print(f"Risk Score: {result.risk_score:.1f}/10 ({result.risk_level})")
        print(f"Duration: {result.duration_seconds:.2f} seconds")
        print(f"{'='*80}\n")
        
        # Exit with appropriate code
        sys.exit(1 if result.risk_level in ['CRITICAL', 'HIGH'] else 0)
        
    except KeyboardInterrupt:
        logger.warning("Assessment interrupted by user")
        sys.exit(130)
    except WorkflowEngineError as e:
        logger.error(f"Workflow error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)
```

---

## Application Order

Apply improvements in this order for best results:

1. **Imports and Enums** (Sections 1-2)
2. **Exceptions** (Section 3)
3. **Logging** (Section 4)
4. **Dataclasses** (Sections 5-6)
5. **Lazy Loading** (Section 7)
6. **Retry Logic** (Section 8)
7. **AI Rate Limiting** (Section 9)
8. **Workflow ID** (Section 10)
9. **Concurrent Processing** (Section 11)
10. **Authorization** (Section 12)
11. **Timeouts** (Section 13)
12. **Main Function** (Section 14)

Test after each major section to ensure compatibility.