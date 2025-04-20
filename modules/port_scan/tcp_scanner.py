"""
TCP port scanner module for ReconXtreme

This module implements asynchronous TCP port scanning to identify open ports
and services on target hosts.
"""
import asyncio
import socket
import time
from typing import List, Dict, Any, Set, Optional, Tuple
import ipaddress
import struct
import random

from core.logger import get_module_logger
from modules import ModuleBase

logger = get_module_logger("port_scan.tcp_scanner")

class TcpScannerModule(ModuleBase):
    """TCP port scanning module for identifying open ports and services"""
    
    name = "tcp_scanner"
    description = "TCP port scanner for identifying open ports"
    author = "ReconXtreme Team"
    version = "0.1.0"
    
    # Common ports to scan by default
    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443
    ]
    
    # TCP connection timeout
    DEFAULT_TIMEOUT = 2.0
    
    # Service identification
    COMMON_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    
    def __init__(self, config=None):
        super().__init__(config)
        
        # Set configuration with defaults
        self.timeout = self.config.get('timeout', self.DEFAULT_TIMEOUT)
        
        # Process port ranges
        port_config = self.config.get('ports', "1-1000")
        self.ports = self._parse_ports(port_config)
        
        # Set concurrency limit
        self.max_concurrent = self.config.get('max_concurrent', 500)
        
        # Set scan type
        self.scan_type = self.config.get('scan_type', 'connect')
        
        # Results will store discovered open ports
        self.results = {
            'hosts': {},  # host -> {ports: [port_info]}
            'total_hosts': 0,
            'total_open_ports': 0
        }
    
    async def run(self, target, *args, **kwargs):
        """
        Run port scan on the target
        
        Args:
            target (str): The target IP or domain
            
        Returns:
            Dict containing discovered open ports
        """
        logger.info(f"Starting TCP port scan for {target}")
        
        # Resolve target to IP if it's a domain
        if not self._is_valid_ip(target):
            try:
                ips = await self._resolve_domain(target)
                if not ips:
                    logger.error(f"Could not resolve domain: {target}")
                    return self.results
                logger.info(f"Resolved {target} to {', '.join(ips)}")
            except Exception as e:
                logger.error(f"Error resolving domain {target}: {e}")
                return self.results
        else:
            ips = [target]
        
        # Scan each resolved IP
        for ip in ips:
            await self._scan_host(ip)
        
        # Update statistics
        self.results['total_hosts'] = len(self.results['hosts'])
        self.results['total_open_ports'] = sum(
            len(host_data['ports']) for host_data in self.results['hosts'].values()
        )
        
        logger.info(f"TCP port scan completed. Scanned {self.results['total_hosts']} hosts, "
                   f"found {self.results['total_open_ports']} open ports.")
        return self.results
    
    async def _scan_host(self, host: str):
        """
        Scan a single host for open ports
        
        Args:
            host: IP address to scan
        """
        logger.info(f"Scanning host {host} for {len(self.ports)} ports")
        
        # Initialize results for this host
        self.results['hosts'][host] = {
            'ports': {},
            'hostname': await self._get_hostname(host)
        }
        
        # Create a semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Choose scan method based on configuration
        if self.scan_type == 'connect':
            scan_func = self._connect_scan
        else:
            # Default to connect scan for now
            scan_func = self._connect_scan
        
        # Create scanning tasks
        tasks = []
        for port in self.ports:
            tasks.append(self._scan_port(host, port, semaphore, scan_func))
        
        # Run all scan tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"Completed scan of {host}. Found "
                   f"{len(self.results['hosts'][host]['ports'])} open ports.")
    
    async def _scan_port(self, host: str, port: int, semaphore: asyncio.Semaphore, 
                         scan_func) -> Optional[Dict[str, Any]]:
        """
        Scan a single port on a host
        
        Args:
            host: Host IP to scan
            port: Port number to scan
            semaphore: Semaphore for limiting concurrent scans
            scan_func: Function to use for scanning
            
        Returns:
            Optional dict with port information if open
        """
        async with semaphore:
            try:
                start_time = time.time()
                is_open = await scan_func(host, port)
                scan_time = time.time() - start_time
                
                if is_open:
                    # Port is open, add to results
                    service = self.COMMON_SERVICES.get(port, "unknown")
                    port_info = {
                        'service': service,
                        'state': 'open',
                        'scan_time': scan_time
                    }
                    
                    # Add banner grabbing in the future
                    # if self.config.get('banner_grabbing', False):
                    #    port_info['banner'] = await self._grab_banner(host, port)
                    
                    # Store result
                    self.results['hosts'][host]['ports'][port] = port_info
                    logger.debug(f"Port {port} is open on {host} ({service})")
                    return port_info
                
            except Exception as e:
                logger.debug(f"Error scanning {host}:{port} - {e}")
            
            return None
    
    async def _connect_scan(self, host: str, port: int) -> bool:
        """
        Perform a TCP connect scan on a port
        
        Args:
            host: Host IP to scan
            port: Port number to scan
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Run the connect operation in a thread to make it non-blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._tcp_connect(sock, host, port)
            )
            
            return result
            
        except Exception:
            return False
    
    def _tcp_connect(self, sock, host, port):
        """Perform TCP connect (executed in thread pool)"""
        try:
            sock.connect((host, port))
            sock.close()
            return True
        except Exception:
            sock.close()
            return False
    
    async def _get_hostname(self, ip: str) -> str:
        """
        Attempt to get hostname from IP via reverse DNS
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Hostname if found, otherwise empty string
        """
        try:
            loop = asyncio.get_event_loop()
            hostname, _, _ = await loop.run_in_executor(
                None,
                lambda: socket.gethostbyaddr(ip)
            )
            return hostname
        except Exception:
            return ""
    
    async def _resolve_domain(self, domain: str) -> List[str]:
        """
        Resolve domain to IP addresses
        
        Args:
            domain: Domain to resolve
            
        Returns:
            List of IP addresses
        """
        try:
            loop = asyncio.get_event_loop()
            info = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(domain, None)
            )
            # Extract unique IPs
            ips = set()
            for result in info:
                ip = result[4][0]
                if self._is_valid_ip(ip):
                    ips.add(ip)
            return list(ips)
        except Exception as e:
            logger.error(f"Error resolving {domain}: {e}")
            return []
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if a string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _parse_ports(self, port_config) -> List[int]:
        """
        Parse port configuration, which can be:
        - a comma-separated list of ports: "80,443,8080"
        - a range of ports: "1-1000"
        - a list of common ports: "common"
        - a combination: "80,443,1000-2000"
        
        Args:
            port_config: Port configuration string
            
        Returns:
            List of port numbers to scan
        """
        if (port_config == "common"):
            return self.DEFAULT_PORTS
        
        ports = set()
        
        for part in port_config.split(','):
            part = part.strip()
            
            if '-' in part:
                # Port range
                try:
                    start, end = map(int, part.split('-'))
                    ports.update(range(start, end + 1))
                except ValueError:
                    logger.warning(f"Invalid port range: {part}")
            else:
                # Single port
                try:
                    ports.add(int(part))
                except ValueError:
                    logger.warning(f"Invalid port: {part}")
        
        return sorted(list(ports))