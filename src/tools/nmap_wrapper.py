"""
Nmap Wrapper for Security Assessment
Provides comprehensive port scanning, service detection, and NSE script execution
"""

import nmap
import json
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class Port:
    """Represents a discovered port"""
    port: int
    protocol: str
    state: str
    service: str
    version: str
    product: str
    extra_info: str
    cpe: List[str]


@dataclass
class Host:
    """Represents a scanned host"""
    ip: str
    hostname: str
    state: str
    os: Optional[str]
    ports: List[Port]
    scripts: Dict[str, Any]


@dataclass
class NmapScanResult:
    """Complete Nmap scan result"""
    scan_id: str
    timestamp: str
    target: str
    scan_type: str
    hosts: List[Host]
    summary: Dict[str, Any]


class NmapWrapper:
    """Wrapper for Nmap scanning operations"""
    
    def __init__(self, nmap_path: str = "/usr/bin/nmap"):
        self.nmap_path = nmap_path
        self.scanner = nmap.PortScanner()
        
    def quick_scan(self, target: str) -> NmapScanResult:
        """
        Perform a quick scan to discover open ports
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            NmapScanResult object
        """
        logger.info(f"Starting quick scan on {target}")
        
        try:
            self.scanner.scan(target, arguments='-T4 -F')
            return self._parse_results(target, "quick_scan")
        except Exception as e:
            logger.error(f"Quick scan failed: {e}")
            raise
    
    def full_scan(self, target: str, ports: str = "1-65535") -> NmapScanResult:
        """
        Perform a comprehensive scan with service detection
        
        Args:
            target: IP address or hostname to scan
            ports: Port range to scan (default: all ports)
            
        Returns:
            NmapScanResult object
        """
        logger.info(f"Starting full scan on {target} (ports: {ports})")
        
        try:
            self.scanner.scan(
                target,
                ports,
                arguments='-sV -sC -O -T4 --version-intensity 5'
            )
            return self._parse_results(target, "full_scan")
        except Exception as e:
            logger.error(f"Full scan failed: {e}")
            raise
    
    def vulnerability_scan(self, target: str, ports: Optional[str] = None) -> NmapScanResult:
        """
        Run NSE vulnerability scripts against target
        
        Args:
            target: IP address or hostname to scan
            ports: Specific ports to scan (optional)
            
        Returns:
            NmapScanResult object with vulnerability information
        """
        logger.info(f"Starting vulnerability scan on {target}")
        
        nse_scripts = [
            'vuln',
            'exploit',
            'auth',
            'default',
            'discovery'
        ]
        
        script_args = ','.join(nse_scripts)
        
        try:
            if ports:
                self.scanner.scan(
                    target,
                    ports,
                    arguments=f'-sV --script={script_args} -T4'
                )
            else:
                self.scanner.scan(
                    target,
                    arguments=f'-sV --script={script_args} -T4'
                )
            
            return self._parse_results(target, "vulnerability_scan")
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            raise
    
    def run_nse_script(self, target: str, script: str, ports: Optional[str] = None) -> Dict[str, Any]:
        """
        Run a specific NSE script
        
        Args:
            target: IP address or hostname
            script: NSE script name
            ports: Specific ports (optional)
            
        Returns:
            Script execution results
        """
        logger.info(f"Running NSE script '{script}' on {target}")
        
        try:
            if ports:
                self.scanner.scan(
                    target,
                    ports,
                    arguments=f'--script={script} -T4'
                )
            else:
                self.scanner.scan(
                    target,
                    arguments=f'--script={script} -T4'
                )
            
            results = {}
            for host in self.scanner.all_hosts():
                if 'tcp' in self.scanner[host]:
                    for port in self.scanner[host]['tcp']:
                        if 'script' in self.scanner[host]['tcp'][port]:
                            results[f"{host}:{port}"] = self.scanner[host]['tcp'][port]['script']
            
            return results
        except Exception as e:
            logger.error(f"NSE script execution failed: {e}")
            raise
    
    def os_detection(self, target: str) -> Dict[str, Any]:
        """
        Perform OS detection
        
        Args:
            target: IP address or hostname
            
        Returns:
            OS detection results
        """
        logger.info(f"Performing OS detection on {target}")
        
        try:
            self.scanner.scan(target, arguments='-O -T4')
            
            results = {}
            for host in self.scanner.all_hosts():
                if 'osmatch' in self.scanner[host]:
                    results[host] = {
                        'os_matches': self.scanner[host]['osmatch'],
                        'accuracy': self.scanner[host].get('accuracy', 'unknown')
                    }
            
            return results
        except Exception as e:
            logger.error(f"OS detection failed: {e}")
            raise
    
    def aggressive_scan(self, target: str) -> NmapScanResult:
        """
        Perform aggressive scan with all detection methods
        
        Args:
            target: IP address or hostname
            
        Returns:
            NmapScanResult object
        """
        logger.info(f"Starting aggressive scan on {target}")
        
        try:
            self.scanner.scan(target, arguments='-A -T4')
            return self._parse_results(target, "aggressive_scan")
        except Exception as e:
            logger.error(f"Aggressive scan failed: {e}")
            raise
    
    def _parse_results(self, target: str, scan_type: str) -> NmapScanResult:
        """Parse Nmap scan results into structured format"""
        
        hosts = []
        
        for host in self.scanner.all_hosts():
            ports = []
            scripts = {}
            
            # Parse TCP ports
            if 'tcp' in self.scanner[host]:
                for port_num in self.scanner[host]['tcp']:
                    port_info = self.scanner[host]['tcp'][port_num]
                    
                    port = Port(
                        port=port_num,
                        protocol='tcp',
                        state=port_info.get('state', 'unknown'),
                        service=port_info.get('name', 'unknown'),
                        version=port_info.get('version', ''),
                        product=port_info.get('product', ''),
                        extra_info=port_info.get('extrainfo', ''),
                        cpe=port_info.get('cpe', [])
                    )
                    ports.append(port)
                    
                    # Extract NSE script results
                    if 'script' in port_info:
                        scripts[f"port_{port_num}"] = port_info['script']
            
            # Parse UDP ports
            if 'udp' in self.scanner[host]:
                for port_num in self.scanner[host]['udp']:
                    port_info = self.scanner[host]['udp'][port_num]
                    
                    port = Port(
                        port=port_num,
                        protocol='udp',
                        state=port_info.get('state', 'unknown'),
                        service=port_info.get('name', 'unknown'),
                        version=port_info.get('version', ''),
                        product=port_info.get('product', ''),
                        extra_info=port_info.get('extrainfo', ''),
                        cpe=port_info.get('cpe', [])
                    )
                    ports.append(port)
            
            # Get OS information
            os_info = None
            if 'osmatch' in self.scanner[host] and self.scanner[host]['osmatch']:
                os_info = self.scanner[host]['osmatch'][0].get('name', None)
            
            host_obj = Host(
                ip=host,
                hostname=self.scanner[host].hostname(),
                state=self.scanner[host].state(),
                os=os_info,
                ports=ports,
                scripts=scripts
            )
            hosts.append(host_obj)
        
        # Create summary
        summary = {
            'total_hosts': len(hosts),
            'total_open_ports': sum(len(h.ports) for h in hosts),
            'scan_info': self.scanner.scaninfo()
        }
        
        return NmapScanResult(
            scan_id=f"nmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            target=target,
            scan_type=scan_type,
            hosts=hosts,
            summary=summary
        )
    
    def export_results(self, result: NmapScanResult, format: str = "json") -> str:
        """
        Export scan results to various formats
        
        Args:
            result: NmapScanResult object
            format: Output format (json, xml, txt)
            
        Returns:
            Formatted string
        """
        if format == "json":
            return json.dumps(asdict(result), indent=2)
        elif format == "xml":
            return self.scanner.get_nmap_last_output()
        else:
            return str(result)


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python nmap_wrapper.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    wrapper = NmapWrapper()
    
    print(f"Scanning {target}...")
    result = wrapper.quick_scan(target)
    
    print(json.dumps(asdict(result), indent=2))

# Made with Bob
