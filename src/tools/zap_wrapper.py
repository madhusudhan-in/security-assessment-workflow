"""
OWASP ZAP Wrapper for Web Application Security Testing
Provides comprehensive web vulnerability scanning and attack crafting
"""

import time
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from zapv2 import ZAPv2

logger = logging.getLogger(__name__)


@dataclass
class ZAPAlert:
    """ZAP Security Alert"""
    alert_id: str
    name: str
    risk: str  # High, Medium, Low, Informational
    confidence: str
    description: str
    solution: str
    reference: str
    url: str
    method: str
    param: str
    attack: str
    evidence: str
    cwe_id: str
    wasc_id: str


@dataclass
class ZAPScanResult:
    """Complete ZAP scan result"""
    scan_id: str
    timestamp: str
    target: str
    scan_type: str
    alerts: List[ZAPAlert]
    summary: Dict[str, Any]
    requests: List[Dict[str, Any]]
    responses: List[Dict[str, Any]]


class ZAPWrapper:
    """Wrapper for OWASP ZAP operations"""
    
    def __init__(self, api_key: str, proxy_host: str = "localhost", proxy_port: int = 8080):
        self.api_key = api_key
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={
                'http': f'http://{proxy_host}:{proxy_port}',
                'https': f'http://{proxy_host}:{proxy_port}'
            }
        )
        
    def start_session(self, session_name: str) -> bool:
        """
        Start a new ZAP session
        
        Args:
            session_name: Name for the session
            
        Returns:
            Success status
        """
        logger.info(f"Starting ZAP session: {session_name}")
        
        try:
            self.zap.core.new_session(name=session_name, overwrite=True)
            return True
        except Exception as e:
            logger.error(f"Error starting session: {e}")
            return False
    
    def spider_scan(self, target: str, max_depth: int = 5) -> Dict[str, Any]:
        """
        Perform spider scan to discover URLs
        
        Args:
            target: Target URL
            max_depth: Maximum crawl depth
            
        Returns:
            Spider scan results
        """
        logger.info(f"Starting spider scan on {target}")
        
        try:
            # Start spider
            scan_id = self.zap.spider.scan(target, maxchildren=max_depth)
            
            # Wait for spider to complete
            while int(self.zap.spider.status(scan_id)) < 100:
                logger.info(f"Spider progress: {self.zap.spider.status(scan_id)}%")
                time.sleep(2)
            
            # Get results
            urls = self.zap.spider.results(scan_id)
            
            logger.info(f"Spider found {len(urls)} URLs")
            
            return {
                'scan_id': scan_id,
                'urls_found': len(urls),
                'urls': urls
            }
            
        except Exception as e:
            logger.error(f"Spider scan failed: {e}")
            raise
    
    def ajax_spider_scan(self, target: str, max_duration: int = 10) -> Dict[str, Any]:
        """
        Perform AJAX spider scan for JavaScript-heavy applications
        
        Args:
            target: Target URL
            max_duration: Maximum scan duration in minutes
            
        Returns:
            AJAX spider results
        """
        logger.info(f"Starting AJAX spider scan on {target}")
        
        try:
            # Start AJAX spider
            self.zap.ajaxSpider.scan(target)
            
            timeout = max_duration * 60
            elapsed = 0
            
            # Wait for AJAX spider to complete
            while self.zap.ajaxSpider.status == 'running':
                if elapsed >= timeout:
                    self.zap.ajaxSpider.stop()
                    break
                
                logger.info(f"AJAX spider running... ({elapsed}s)")
                time.sleep(5)
                elapsed += 5
            
            # Get results
            results = self.zap.ajaxSpider.results()
            
            logger.info(f"AJAX spider found {len(results)} URLs")
            
            return {
                'urls_found': len(results),
                'urls': results
            }
            
        except Exception as e:
            logger.error(f"AJAX spider scan failed: {e}")
            raise
    
    def active_scan(self, target: str, scan_policy: Optional[str] = None) -> ZAPScanResult:
        """
        Perform active vulnerability scan
        
        Args:
            target: Target URL
            scan_policy: Custom scan policy name (optional)
            
        Returns:
            ZAPScanResult object
        """
        logger.info(f"Starting active scan on {target}")
        
        try:
            # Start active scan
            if scan_policy:
                scan_id = self.zap.ascan.scan(target, scanpolicyname=scan_policy)
            else:
                scan_id = self.zap.ascan.scan(target)
            
            # Wait for scan to complete
            while int(self.zap.ascan.status(scan_id)) < 100:
                progress = self.zap.ascan.status(scan_id)
                logger.info(f"Active scan progress: {progress}%")
                time.sleep(5)
            
            # Get alerts
            alerts = self._get_alerts(target)
            
            # Get requests and responses
            messages = self._get_messages(target)
            
            return self._create_scan_result(
                target=target,
                scan_type="active_scan",
                alerts=alerts,
                messages=messages
            )
            
        except Exception as e:
            logger.error(f"Active scan failed: {e}")
            raise
    
    def passive_scan(self, target: str) -> ZAPScanResult:
        """
        Perform passive vulnerability scan
        
        Args:
            target: Target URL
            
        Returns:
            ZAPScanResult object
        """
        logger.info(f"Starting passive scan on {target}")
        
        try:
            # Access the target to generate traffic
            self.zap.urlopen(target)
            
            # Wait for passive scan to complete
            while int(self.zap.pscan.records_to_scan) > 0:
                logger.info(f"Passive scan records remaining: {self.zap.pscan.records_to_scan}")
                time.sleep(2)
            
            # Get alerts
            alerts = self._get_alerts(target)
            
            # Get requests and responses
            messages = self._get_messages(target)
            
            return self._create_scan_result(
                target=target,
                scan_type="passive_scan",
                alerts=alerts,
                messages=messages
            )
            
        except Exception as e:
            logger.error(f"Passive scan failed: {e}")
            raise
    
    def full_scan(self, target: str, use_ajax: bool = True) -> ZAPScanResult:
        """
        Perform comprehensive scan (spider + active + passive)
        
        Args:
            target: Target URL
            use_ajax: Use AJAX spider for JavaScript applications
            
        Returns:
            ZAPScanResult object
        """
        logger.info(f"Starting full scan on {target}")
        
        try:
            # Spider scan
            self.spider_scan(target)
            
            # AJAX spider if requested
            if use_ajax:
                self.ajax_spider_scan(target)
            
            # Active scan
            result = self.active_scan(target)
            
            return result
            
        except Exception as e:
            logger.error(f"Full scan failed: {e}")
            raise
    
    def get_request_response(self, message_id: int) -> Dict[str, Any]:
        """
        Get detailed request and response for a specific message
        
        Args:
            message_id: Message ID from ZAP
            
        Returns:
            Request and response details
        """
        try:
            message = self.zap.core.message(message_id)
            
            return {
                'message_id': message_id,
                'request_header': message.get('requestHeader', ''),
                'request_body': message.get('requestBody', ''),
                'response_header': message.get('responseHeader', ''),
                'response_body': message.get('responseBody', ''),
                'timestamp': message.get('timestamp', '')
            }
            
        except Exception as e:
            logger.error(f"Error getting message: {e}")
            return {}
    
    def craft_attack(self, base_url: str, param: str, payload: str, method: str = "GET") -> Dict[str, Any]:
        """
        Craft and send a custom attack
        
        Args:
            base_url: Target URL
            param: Parameter to attack
            payload: Attack payload
            method: HTTP method
            
        Returns:
            Attack result
        """
        logger.info(f"Crafting attack on {base_url} with payload: {payload}")
        
        try:
            # Construct attack URL
            if method.upper() == "GET":
                attack_url = f"{base_url}?{param}={payload}"
                response = self.zap.urlopen(attack_url)
            else:
                # For POST requests, would need to use httpSender
                response = None
            
            # Get the last message
            messages = self.zap.core.messages()
            if messages:
                last_message = self.get_request_response(messages[-1]['id'])
                
                return {
                    'success': True,
                    'url': attack_url,
                    'payload': payload,
                    'response': last_message
                }
            
            return {'success': False, 'error': 'No response captured'}
            
        except Exception as e:
            logger.error(f"Error crafting attack: {e}")
            return {'success': False, 'error': str(e)}
    
    def analyze_alert_for_exploitation(self, alert: ZAPAlert) -> Dict[str, Any]:
        """
        Analyze an alert and suggest exploitation techniques
        
        Args:
            alert: ZAPAlert object
            
        Returns:
            Exploitation suggestions
        """
        exploitation = {
            'alert_name': alert.name,
            'risk': alert.risk,
            'exploitable': False,
            'techniques': [],
            'payloads': [],
            'references': []
        }
        
        # SQL Injection
        if 'SQL' in alert.name.upper():
            exploitation['exploitable'] = True
            exploitation['techniques'] = [
                'Union-based injection',
                'Boolean-based blind injection',
                'Time-based blind injection',
                'Error-based injection'
            ]
            exploitation['payloads'] = [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "' AND SLEEP(5)--"
            ]
        
        # XSS
        elif 'XSS' in alert.name.upper() or 'CROSS SITE SCRIPTING' in alert.name.upper():
            exploitation['exploitable'] = True
            exploitation['techniques'] = [
                'Reflected XSS',
                'Stored XSS',
                'DOM-based XSS'
            ]
            exploitation['payloads'] = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')"
            ]
        
        # Command Injection
        elif 'COMMAND' in alert.name.upper():
            exploitation['exploitable'] = True
            exploitation['techniques'] = [
                'OS command injection',
                'Code injection'
            ]
            exploitation['payloads'] = [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd"
            ]
        
        # Path Traversal
        elif 'PATH TRAVERSAL' in alert.name.upper() or 'DIRECTORY' in alert.name.upper():
            exploitation['exploitable'] = True
            exploitation['techniques'] = [
                'Directory traversal',
                'Local file inclusion'
            ]
            exploitation['payloads'] = [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd"
            ]
        
        return exploitation
    
    def _get_alerts(self, target: str) -> List[ZAPAlert]:
        """Get all alerts for a target"""
        alerts = []
        
        try:
            zap_alerts = self.zap.core.alerts(baseurl=target)
            
            for alert_data in zap_alerts:
                alert = ZAPAlert(
                    alert_id=alert_data.get('id', ''),
                    name=alert_data.get('alert', ''),
                    risk=alert_data.get('risk', ''),
                    confidence=alert_data.get('confidence', ''),
                    description=alert_data.get('description', ''),
                    solution=alert_data.get('solution', ''),
                    reference=alert_data.get('reference', ''),
                    url=alert_data.get('url', ''),
                    method=alert_data.get('method', ''),
                    param=alert_data.get('param', ''),
                    attack=alert_data.get('attack', ''),
                    evidence=alert_data.get('evidence', ''),
                    cwe_id=alert_data.get('cweid', ''),
                    wasc_id=alert_data.get('wascid', '')
                )
                alerts.append(alert)
        
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
        
        return alerts
    
    def _get_messages(self, target: str) -> Dict[str, List[Dict[str, Any]]]:
        """Get HTTP messages for a target"""
        messages = {'requests': [], 'responses': []}
        
        try:
            zap_messages = self.zap.core.messages(baseurl=target)
            
            for msg in zap_messages[:100]:  # Limit to first 100 messages
                message_detail = self.get_request_response(msg['id'])
                messages['requests'].append({
                    'id': msg['id'],
                    'url': msg.get('url', ''),
                    'method': msg.get('method', ''),
                    'header': message_detail.get('request_header', ''),
                    'body': message_detail.get('request_body', '')
                })
                messages['responses'].append({
                    'id': msg['id'],
                    'header': message_detail.get('response_header', ''),
                    'body': message_detail.get('response_body', '')
                })
        
        except Exception as e:
            logger.error(f"Error getting messages: {e}")
        
        return messages
    
    def _create_scan_result(self, target: str, scan_type: str, alerts: List[ZAPAlert], 
                           messages: Dict[str, List[Dict[str, Any]]]) -> ZAPScanResult:
        """Create a ZAPScanResult object"""
        
        # Create summary
        summary = {
            'total_alerts': len(alerts),
            'high_risk': len([a for a in alerts if a.risk == 'High']),
            'medium_risk': len([a for a in alerts if a.risk == 'Medium']),
            'low_risk': len([a for a in alerts if a.risk == 'Low']),
            'informational': len([a for a in alerts if a.risk == 'Informational']),
            'total_requests': len(messages['requests'])
        }
        
        return ZAPScanResult(
            scan_id=f"zap_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            target=target,
            scan_type=scan_type,
            alerts=alerts,
            summary=summary,
            requests=messages['requests'],
            responses=messages['responses']
        )
    
    def export_results(self, result: ZAPScanResult, format: str = "json") -> str:
        """
        Export scan results to various formats
        
        Args:
            result: ZAPScanResult object
            format: Output format (json, html, xml)
            
        Returns:
            Formatted string
        """
        if format == "json":
            return json.dumps(asdict(result), indent=2)
        elif format == "html":
            return self.zap.core.htmlreport()
        elif format == "xml":
            return self.zap.core.xmlreport()
        else:
            return str(result)


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python zap_wrapper.py <api_key> <target_url>")
        sys.exit(1)
    
    api_key = sys.argv[1]
    target = sys.argv[2]
    
    wrapper = ZAPWrapper(api_key)
    
    print(f"Scanning {target}...")
    result = wrapper.full_scan(target)
    
    print(json.dumps(asdict(result), indent=2))

# Made with Bob
