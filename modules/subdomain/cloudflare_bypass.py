"""
Cloudflare bypass module for ReconXtreme

This module implements various techniques to discover the origin IP address
behind Cloudflare protection.

Raises:
    CloudflareProtectedError: When target is protected by Cloudflare
"""
import asyncio
import platform
if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
import socket
import ssl
import dns.resolver
from typing import List, Dict, Set, Optional
import aiohttp
import logging

from core.logger import get_module_logger
from modules import ModuleBase

logger = get_module_logger("subdomain.cloudflare_bypass")

class CloudflareProtectedError(Exception):
    """Raised when target is protected by Cloudflare"""
    pass

class CloudflareBypassModule(ModuleBase):
    """Module for bypassing Cloudflare to find origin IP addresses"""
    
    name = "cloudflare_bypass"
    description = "Bypass Cloudflare to discover origin IP addresses"
    author = "ReconXtreme Team"
    version = "0.1.0"
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = self.config.get('timeout', 10)
        self.max_concurrent = self.config.get('max_concurrent', 10)
        
        # Results will store discovered IPs and methods
        self.results = {
            'origin_ips': set(),
            'methods': {},
            'cloudflare_ips': set(),
            'subdomains': set()
        }
    
    async def run(self, target: str, *args, **kwargs) -> Dict:
        """
        Run Cloudflare bypass techniques on target
        
        Args:
            target: Target domain
            
        Returns:
            Dict containing discovered origin IPs and methods
        """
        logger.info(f"Starting Cloudflare bypass for {target}")
        
        # Confirm target is behind Cloudflare
        is_cloudflare = await self._is_cloudflare(target)
        if is_cloudflare:
            logger.info(f"{target} is behind Cloudflare protection - skipping scan")
            raise CloudflareProtectedError(f"{target} is protected by Cloudflare")
        else:
            logger.info(f"{target} does not appear to be behind Cloudflare")
            return self.results
            
        # Run all bypass methods
        bypass_methods = [
            self._check_dns_history,
            self._check_ssl_certs,
            self._check_subdomains,
            self._check_email_records,
            self._check_origin_headers
        ]
        
        for method in bypass_methods:
            try:
                results = await method(target)
                if results:
                    self.results['methods'][method.__name__] = results
                    self.results['origin_ips'].update(results)
            except Exception as e:
                logger.error(f"Error in {method.__name__}: {e}")
        
        # Process results
        self.results['origin_ips'] = list(self.results['origin_ips'])
        self.results['cloudflare_ips'] = list(self.results['cloudflare_ips'])
        self.results['subdomains'] = list(self.results['subdomains'])
        
        logger.info(f"Completed Cloudflare bypass for {target}. " +
                   f"Found {len(self.results['origin_ips'])} potential origin IPs")
        
        return self.results
    
    async def _is_cloudflare(self, domain: str) -> bool:
        """Check if domain is behind Cloudflare"""
        try:
            # Check DNS
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                ip = str(rdata)
                if self._is_cloudflare_ip(ip):
                    self.results['cloudflare_ips'].add(ip)
                    return True
            
            # Check headers
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{domain}", timeout=self.timeout) as resp:
                    if 'cf-ray' in resp.headers:
                        return True
            
            return False
        except Exception:
            return False
    
    def _is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP belongs to Cloudflare"""
        cloudflare_ranges = [
            '173.245.48.0/20',
            '103.21.244.0/22',
            '103.22.200.0/22', 
            '103.31.4.0/22',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '108.162.192.0/18',
            '131.0.72.0/22',
            '141.101.64.0/18',
            '162.158.0.0/15',
            '172.64.0.0/13',
            '190.93.240.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17'
        ]
        
        for range in cloudflare_ranges:
            net = range.split('/')[0]
            bits = int(range.split('/')[1])
            if self._ip_in_network(ip, net, bits):
                return True
        return False
    
    def _ip_in_network(self, ip: str, net: str, bits: int) -> bool:
        """Check if IP is in network range"""
        ip_int = self._ip_to_int(ip)
        net_int = self._ip_to_int(net)
        mask = ((1 << 32) - 1) ^ ((1 << (32 - bits)) - 1)
        return (ip_int & mask) == (net_int & mask)
    
    def _ip_to_int(self, ip: str) -> int:
        """Convert IP to integer"""
        octets = ip.split('.')
        return sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(octets))
    
    async def _check_dns_history(self, domain: str) -> Set[str]:
        """Check historical DNS records using SecurityTrails API"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
                headers = {
                    'apikey': self.config.get('securitytrails_api_key', ''),
                    'Accept': 'application/json',
                }
                
                async with session.get(url, headers=headers, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        ips = set()
                        for record in data.get('records', []):
                            for ip in record.get('values', []):
                                ip_addr = ip.get('ip')
                                if ip_addr and not self._is_cloudflare_ip(ip_addr):
                                    ips.add(ip_addr)
                        return ips
                    
                    # If API key not working, try archive.org
                    archive_url = f"http://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain&collapse=digest&output=json&fl=timestamp,original"
                    async with session.get(archive_url, timeout=self.timeout) as response:
                        if response.status == 200:
                            data = await response.json()
                            ips = set()
                            for entry in data[1:]:  # Skip header row
                                try:
                                    url = entry[1]
                                    parsed = urllib.parse.urlparse(url)
                                    ip = socket.gethostbyname(parsed.netloc)
                                    if not self._is_cloudflare_ip(ip):
                                        ips.add(ip)
                                except Exception:
                                    continue
                            return ips
        except Exception as e:
            logger.debug(f"Error checking DNS history: {e}")
        
        return set()
    
    async def _check_ssl_certs(self, domain: str) -> Set[str]:
        """Check SSL certificates for origin hints"""
        results = set()
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                
                # Extract all SANs
                for type, value in cert['subjectAltName']:
                    if type == 'DNS':
                        try:
                            ip = socket.gethostbyname(value)
                            if not self._is_cloudflare_ip(ip):
                                results.add(ip)
                        except socket.gaierror:
                            pass
        except Exception as e:
            logger.debug(f"SSL cert check failed: {e}")
        
        return results
    
    async def _check_subdomains(self, domain: str) -> Set[str]:
        """Check subdomains that might bypass Cloudflare"""
        results = set()
        common_prefixes = ['direct-', 'origin-', 'backend-', 'api-', 'staging-', 'dev-']
        
        for prefix in common_prefixes:
            subdomain = f"{prefix}{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                if not self._is_cloudflare_ip(ip):
                    results.add(ip)
                    self.results['subdomains'].add(subdomain)
            except socket.gaierror:
                continue
                
        return results
    
    async def _check_email_records(self, domain: str) -> Set[str]:
        """Check email records for origin hints"""
        results = set()
        try:
            # Check MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            for rdata in mx_records:
                try:
                    ip = socket.gethostbyname(str(rdata.exchange))
                    if not self._is_cloudflare_ip(ip):
                        results.add(ip)
                except socket.gaierror:
                    continue
                    
            # Check SPF records
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for rdata in txt_records:
                txt = str(rdata)
                if 'v=spf1' in txt:
                    for part in txt.split():
                        if part.startswith(('ip4:', 'ip6:')):
                            ip = part.split(':', 1)[1]
                            if not self._is_cloudflare_ip(ip):
                                results.add(ip)
        except Exception as e:
            logger.debug(f"Email records check failed: {e}")
            
        return results
    
    async def _check_origin_headers(self, domain: str) -> Set[str]:
        """Check various headers that might reveal origin"""
        results = set()
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Forwarded-Proto': 'https'
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"https://{domain}",
                    headers=headers,
                    timeout=self.timeout
                ) as resp:
                    # Check response headers for origin hints
                    for header in ['X-Origin', 'X-Real-IP', 'Server']:
                        if header in resp.headers:
                            value = resp.headers[header]
                            try:
                                socket.inet_aton(value)  # Validate IP format
                                if not self._is_cloudflare_ip(value):
                                    results.add(value)
                            except socket.error:
                                continue
            except Exception as e:
                logger.debug(f"Origin headers check failed: {e}")
                
        return results