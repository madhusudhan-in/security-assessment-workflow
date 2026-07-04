"""
Metasploit Framework Wrapper
Provides exploit execution and post-exploitation capabilities
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from pymetasploit3.msfrpc import MsfRpcClient
import subprocess
import json

logger = logging.getLogger(__name__)


@dataclass
class ExploitResult:
    """Metasploit exploit execution result"""
    exploit_id: str
    module_name: str
    target: str
    timestamp: str
    success: bool
    session_id: Optional[int]
    output: str
    error: Optional[str]


@dataclass
class ModuleInfo:
    """Metasploit module information"""
    name: str
    fullname: str
    type: str  # exploit, auxiliary, post, payload
    rank: str
    description: str
    author: List[str]
    references: List[str]
    targets: List[str]
    options: Dict[str, Any]


class MetasploitWrapper:
    """Wrapper for Metasploit Framework operations"""
    
    def __init__(self, host: str = "localhost", port: int = 55553, 
                 username: str = "msf", password: str = "password", ssl: bool = True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        self.client = None
        self.console_id = None
        
    def connect(self) -> bool:
        """
        Connect to Metasploit RPC server
        
        Returns:
            Connection success status
        """
        logger.info(f"Connecting to Metasploit at {self.host}:{self.port}")
        
        try:
            self.client = MsfRpcClient(
                password=self.password,
                username=self.username,
                server=self.host,
                port=self.port,
                ssl=self.ssl
            )
            
            # Create console
            self.console_id = self.client.consoles.console().cid
            
            logger.info("Successfully connected to Metasploit")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Metasploit: {e}")
            return False
    
    def search_exploits(self, query: str) -> List[ModuleInfo]:
        """
        Search for exploits matching query
        
        Args:
            query: Search term (CVE, product name, etc.)
            
        Returns:
            List of ModuleInfo objects
        """
        logger.info(f"Searching exploits for: {query}")
        
        if not self.client:
            self.connect()
        
        try:
            modules = []
            search_results = self.client.modules.search(query)
            
            for result in search_results:
                if result.startswith('exploit/'):
                    module_info = self.get_module_info(result)
                    if module_info:
                        modules.append(module_info)
            
            logger.info(f"Found {len(modules)} exploits")
            return modules
            
        except Exception as e:
            logger.error(f"Error searching exploits: {e}")
            return []
    
    def get_module_info(self, module_name: str) -> Optional[ModuleInfo]:
        """
        Get detailed information about a module
        
        Args:
            module_name: Full module name (e.g., 'exploit/windows/smb/ms17_010_eternalblue')
            
        Returns:
            ModuleInfo object or None
        """
        logger.info(f"Getting info for module: {module_name}")
        
        if not self.client:
            self.connect()
        
        try:
            module = self.client.modules.use(module_name.split('/')[0], module_name)
            info = module.info
            
            return ModuleInfo(
                name=module_name.split('/')[-1],
                fullname=module_name,
                type=module_name.split('/')[0],
                rank=info.get('rank', 'unknown'),
                description=info.get('description', ''),
                author=info.get('author', []),
                references=info.get('references', []),
                targets=info.get('targets', []),
                options=module.options
            )
            
        except Exception as e:
            logger.error(f"Error getting module info: {e}")
            return None
    
    def run_exploit(self, module_name: str, target: str, options: Dict[str, Any],
                   payload: Optional[str] = None) -> ExploitResult:
        """
        Execute an exploit module
        
        Args:
            module_name: Full module name
            target: Target IP/hostname
            options: Module options
            payload: Payload to use (optional)
            
        Returns:
            ExploitResult object
        """
        logger.info(f"Running exploit {module_name} against {target}")
        
        if not self.client:
            self.connect()
        
        try:
            # Load exploit module
            exploit = self.client.modules.use('exploit', module_name)
            
            # Set RHOSTS (target)
            exploit['RHOSTS'] = target
            
            # Set additional options
            for key, value in options.items():
                exploit[key] = value
            
            # Set payload if specified
            if payload:
                exploit['PAYLOAD'] = payload
            
            # Execute exploit
            result = exploit.execute()
            
            # Check if session was created
            session_id = None
            if result.get('job_id'):
                # Wait a bit for session to establish
                import time
                time.sleep(5)
                
                sessions = self.client.sessions.list
                if sessions:
                    session_id = list(sessions.keys())[-1]
            
            return ExploitResult(
                exploit_id=f"msf_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                module_name=module_name,
                target=target,
                timestamp=datetime.now().isoformat(),
                success=session_id is not None,
                session_id=session_id,
                output=str(result),
                error=None
            )
            
        except Exception as e:
            logger.error(f"Error running exploit: {e}")
            return ExploitResult(
                exploit_id=f"msf_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                module_name=module_name,
                target=target,
                timestamp=datetime.now().isoformat(),
                success=False,
                session_id=None,
                output="",
                error=str(e)
            )
    
    def run_auxiliary(self, module_name: str, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run an auxiliary module (scanner, fuzzer, etc.)
        
        Args:
            module_name: Full module name
            target: Target IP/hostname
            options: Module options
            
        Returns:
            Execution results
        """
        logger.info(f"Running auxiliary module {module_name} against {target}")
        
        if not self.client:
            self.connect()
        
        try:
            # Load auxiliary module
            aux = self.client.modules.use('auxiliary', module_name)
            
            # Set RHOSTS
            aux['RHOSTS'] = target
            
            # Set additional options
            for key, value in options.items():
                aux[key] = value
            
            # Execute
            result = aux.execute()
            
            return {
                'success': True,
                'module': module_name,
                'target': target,
                'result': result
            }
            
        except Exception as e:
            logger.error(f"Error running auxiliary module: {e}")
            return {
                'success': False,
                'module': module_name,
                'target': target,
                'error': str(e)
            }
    
    def get_sessions(self) -> List[Dict[str, Any]]:
        """
        Get list of active sessions
        
        Returns:
            List of session information
        """
        if not self.client:
            self.connect()
        
        try:
            sessions = []
            for sid, session in self.client.sessions.list.items():
                sessions.append({
                    'id': sid,
                    'type': session.get('type', 'unknown'),
                    'tunnel': session.get('tunnel_peer', ''),
                    'via': session.get('via_exploit', ''),
                    'info': session.get('info', '')
                })
            
            return sessions
            
        except Exception as e:
            logger.error(f"Error getting sessions: {e}")
            return []
    
    def interact_with_session(self, session_id: int, command: str) -> str:
        """
        Execute command in a session
        
        Args:
            session_id: Session ID
            command: Command to execute
            
        Returns:
            Command output
        """
        logger.info(f"Executing command in session {session_id}: {command}")
        
        if not self.client:
            self.connect()
        
        try:
            session = self.client.sessions.session(session_id)
            session.write(command)
            
            # Read output
            import time
            time.sleep(2)
            output = session.read()
            
            return output
            
        except Exception as e:
            logger.error(f"Error interacting with session: {e}")
            return f"Error: {str(e)}"
    
    def run_post_module(self, session_id: int, module_name: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run a post-exploitation module
        
        Args:
            session_id: Target session ID
            module_name: Post module name
            options: Module options
            
        Returns:
            Execution results
        """
        logger.info(f"Running post module {module_name} on session {session_id}")
        
        if not self.client:
            self.connect()
        
        try:
            # Load post module
            post = self.client.modules.use('post', module_name)
            
            # Set session
            post['SESSION'] = session_id
            
            # Set additional options
            if options:
                for key, value in options.items():
                    post[key] = value
            
            # Execute
            result = post.execute()
            
            return {
                'success': True,
                'module': module_name,
                'session_id': session_id,
                'result': result
            }
            
        except Exception as e:
            logger.error(f"Error running post module: {e}")
            return {
                'success': False,
                'module': module_name,
                'session_id': session_id,
                'error': str(e)
            }
    
    def check_exploit(self, module_name: str, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if target is vulnerable without exploiting
        
        Args:
            module_name: Exploit module name
            target: Target IP/hostname
            options: Module options
            
        Returns:
            Check results
        """
        logger.info(f"Checking if {target} is vulnerable to {module_name}")
        
        if not self.client:
            self.connect()
        
        try:
            # Load exploit
            exploit = self.client.modules.use('exploit', module_name)
            
            # Set target
            exploit['RHOSTS'] = target
            
            # Set options
            for key, value in options.items():
                exploit[key] = value
            
            # Run check
            result = exploit.check()
            
            return {
                'vulnerable': 'vulnerable' in str(result).lower(),
                'result': result,
                'module': module_name,
                'target': target
            }
            
        except Exception as e:
            logger.error(f"Error checking exploit: {e}")
            return {
                'vulnerable': False,
                'error': str(e),
                'module': module_name,
                'target': target
            }
    
    def execute_console_command(self, command: str) -> str:
        """
        Execute command in Metasploit console
        
        Args:
            command: MSF console command
            
        Returns:
            Command output
        """
        logger.info(f"Executing console command: {command}")
        
        if not self.client or not self.console_id:
            self.connect()
        
        try:
            console = self.client.consoles.console(self.console_id)
            console.write(command)
            
            # Wait for output
            import time
            time.sleep(2)
            
            output = console.read()
            return output.get('data', '')
            
        except Exception as e:
            logger.error(f"Error executing console command: {e}")
            return f"Error: {str(e)}"
    
    def get_exploit_for_cve(self, cve_id: str) -> List[str]:
        """
        Find Metasploit modules for a specific CVE
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            List of module names
        """
        logger.info(f"Finding exploits for {cve_id}")
        
        if not self.client:
            self.connect()
        
        try:
            results = self.client.modules.search(cve_id)
            exploits = [r for r in results if r.startswith('exploit/')]
            
            logger.info(f"Found {len(exploits)} exploits for {cve_id}")
            return exploits
            
        except Exception as e:
            logger.error(f"Error finding exploits: {e}")
            return []
    
    def disconnect(self):
        """Disconnect from Metasploit"""
        logger.info("Disconnecting from Metasploit")
        
        if self.console_id and self.client:
            try:
                self.client.consoles.destroy(self.console_id)
            except Exception as e:
                logger.error(f"Error destroying console: {e}")
        
        self.client = None
        self.console_id = None


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python metasploit_wrapper.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    msf = MetasploitWrapper()
    
    if msf.connect():
        print(f"Searching exploits for {target}...")
        
        # Search for SMB exploits
        exploits = msf.search_exploits("smb")
        
        for exploit in exploits[:5]:
            print(f"\n{exploit.fullname}")
            print(f"Rank: {exploit.rank}")
            print(f"Description: {exploit.description[:100]}...")
        
        msf.disconnect()

