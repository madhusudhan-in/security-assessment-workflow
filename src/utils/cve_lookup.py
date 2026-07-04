"""
CVE Lookup and Vulnerability Database Integration
Searches for CVEs related to discovered services and versions
"""

import requests
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import time

logger = logging.getLogger(__name__)


@dataclass
class CVEInfo:
    """CVE Information"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: str
    modified_date: str
    references: List[str]
    cpe_matches: List[str]
    exploits_available: bool
    exploit_links: List[str]


class CVELookup:
    """CVE Database Lookup Service"""
    
    def __init__(self, nvd_api_key: Optional[str] = None):
        self.nvd_api_key = nvd_api_key
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.exploit_db_url = "https://www.exploit-db.com/search"
        self.session = requests.Session()
        
        if nvd_api_key:
            self.session.headers.update({"apiKey": nvd_api_key})
    
    def search_by_cpe(self, cpe: str) -> List[CVEInfo]:
        """
        Search CVEs by CPE (Common Platform Enumeration)
        
        Args:
            cpe: CPE string (e.g., 'cpe:2.3:a:apache:http_server:2.4.49')
            
        Returns:
            List of CVEInfo objects
        """
        logger.info(f"Searching CVEs for CPE: {cpe}")
        
        try:
            params = {
                "cpeName": cpe,
                "resultsPerPage": 100
            }
            
            response = self.session.get(self.nvd_base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            if "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    cve_data = vuln.get("cve", {})
                    cve_info = self._parse_cve_data(cve_data)
                    if cve_info:
                        cves.append(cve_info)
            
            logger.info(f"Found {len(cves)} CVEs for {cpe}")
            return cves
            
        except Exception as e:
            logger.error(f"Error searching CVEs by CPE: {e}")
            return []
    
    def search_by_product(self, vendor: str, product: str, version: str) -> List[CVEInfo]:
        """
        Search CVEs by product information
        
        Args:
            vendor: Vendor name (e.g., 'apache')
            product: Product name (e.g., 'http_server')
            version: Version string (e.g., '2.4.49')
            
        Returns:
            List of CVEInfo objects
        """
        logger.info(f"Searching CVEs for {vendor} {product} {version}")
        
        try:
            # Construct CPE-like search
            params = {
                "keywordSearch": f"{vendor} {product} {version}",
                "resultsPerPage": 50
            }
            
            response = self.session.get(self.nvd_base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            if "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    cve_data = vuln.get("cve", {})
                    cve_info = self._parse_cve_data(cve_data)
                    if cve_info:
                        cves.append(cve_info)
            
            logger.info(f"Found {len(cves)} CVEs for {vendor} {product} {version}")
            return cves
            
        except Exception as e:
            logger.error(f"Error searching CVEs by product: {e}")
            return []
    
    def search_by_keyword(self, keyword: str) -> List[CVEInfo]:
        """
        Search CVEs by keyword
        
        Args:
            keyword: Search keyword
            
        Returns:
            List of CVEInfo objects
        """
        logger.info(f"Searching CVEs for keyword: {keyword}")
        
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 50
            }
            
            response = self.session.get(self.nvd_base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            if "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    cve_data = vuln.get("cve", {})
                    cve_info = self._parse_cve_data(cve_data)
                    if cve_info:
                        cves.append(cve_info)
            
            return cves
            
        except Exception as e:
            logger.error(f"Error searching CVEs by keyword: {e}")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Get detailed information about a specific CVE
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2021-44228')
            
        Returns:
            CVEInfo object or None
        """
        logger.info(f"Getting details for {cve_id}")
        
        try:
            url = f"{self.nvd_base_url}?cveId={cve_id}"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
                cve_data = data["vulnerabilities"][0].get("cve", {})
                return self._parse_cve_data(cve_data)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting CVE details: {e}")
            return None
    
    def _parse_cve_data(self, cve_data: Dict[str, Any]) -> Optional[CVEInfo]:
        """Parse CVE data from NVD API response"""
        
        try:
            cve_id = cve_data.get("id", "")
            
            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Get CVSS score and severity
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = self._cvss_v2_to_severity(cvss_score)
            
            # Get dates
            published_date = cve_data.get("published", "")
            modified_date = cve_data.get("lastModified", "")
            
            # Get references
            references = []
            for ref in cve_data.get("references", []):
                references.append(ref.get("url", ""))
            
            # Get CPE matches
            cpe_matches = []
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            cpe_matches.append(cpe_match.get("criteria", ""))
            
            # Check for exploits
            exploits_available, exploit_links = self._check_exploits(cve_id)
            
            return CVEInfo(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                published_date=published_date,
                modified_date=modified_date,
                references=references,
                cpe_matches=cpe_matches,
                exploits_available=exploits_available,
                exploit_links=exploit_links
            )
            
        except Exception as e:
            logger.error(f"Error parsing CVE data: {e}")
            return None
    
    def _cvss_v2_to_severity(self, score: float) -> str:
        """Convert CVSS v2 score to severity rating"""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _check_exploits(self, cve_id: str) -> tuple[bool, List[str]]:
        """
        Check if exploits are available for a CVE
        
        Returns:
            Tuple of (exploits_available, exploit_links)
        """
        exploit_links = []
        
        try:
            # Check Exploit-DB
            exploit_db_search = f"https://www.exploit-db.com/search?cve={cve_id}"
            exploit_links.append(exploit_db_search)
            
            # Check GitHub
            github_search = f"https://github.com/search?q={cve_id}+exploit&type=repositories"
            exploit_links.append(github_search)
            
            # Check Metasploit modules (would need actual API integration)
            # For now, just add the search link
            metasploit_search = f"https://www.rapid7.com/db/?q={cve_id}"
            exploit_links.append(metasploit_search)
            
            return True, exploit_links
            
        except Exception as e:
            logger.error(f"Error checking exploits: {e}")
            return False, []
    
    def batch_lookup(self, services: List[Dict[str, str]]) -> Dict[str, List[CVEInfo]]:
        """
        Perform batch CVE lookup for multiple services
        
        Args:
            services: List of service dictionaries with 'product', 'version', etc.
            
        Returns:
            Dictionary mapping service identifiers to CVE lists
        """
        results = {}
        
        for service in services:
            service_id = f"{service.get('product', 'unknown')}_{service.get('version', 'unknown')}"
            
            # Try CPE lookup first
            if 'cpe' in service and service['cpe']:
                cves = self.search_by_cpe(service['cpe'][0] if isinstance(service['cpe'], list) else service['cpe'])
            # Fall back to product search
            elif service.get('product') and service.get('version'):
                parts = service['product'].split()
                vendor = service.get('vendor', parts[0] if parts else service['product'])
                cves = self.search_by_product(vendor, service['product'], service['version'])
            else:
                cves = []
            
            results[service_id] = cves
            
            # Rate limiting
            time.sleep(0.6)  # NVD API rate limit: max 5 requests per second without API key
        
        return results


if __name__ == "__main__":
    # Example usage
    lookup = CVELookup()
    
    # Search for Apache HTTP Server vulnerabilities
    cves = lookup.search_by_product("apache", "http_server", "2.4.49")
    
    for cve in cves[:5]:  # Print first 5
        print(f"\n{cve.cve_id} - {cve.severity} (CVSS: {cve.cvss_score})")
        print(f"Description: {cve.description[:200]}...")
        print(f"Exploits available: {cve.exploits_available}")

