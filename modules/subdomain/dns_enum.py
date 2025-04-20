"""
DNS enumeration module for ReconXtreme

This module implements subdomain discovery using various techniques including:
- DNS brute forcing
- Certificate transparency logs
- Public DNS datasets
"""
import asyncio
import socket
import random
import aiohttp
import dns.resolver
from typing import List, Dict, Any, Set, Optional
import ipaddress

from core.logger import get_module_logger
from modules import ModuleBase

logger = get_module_logger("subdomain.dns_enum")

class DnsEnumModule(ModuleBase):
    """DNS enumeration module for discovering subdomains"""
    
    name = "dns_enum"
    description = "DNS enumeration for subdomain discovery"
    author = "ReconXtreme Team"
    version = "0.1.0"
    
    # Default wordlist for subdomain bruteforce
    DEFAULT_WORDLIST = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
        "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
        "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
        "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
        "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search",
        "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites", "proxy",
        "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info", "apps", "download"
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        self.wordlist = self.config.get('wordlist', self.DEFAULT_WORDLIST)
        self.max_concurrent = self.config.get('max_concurrent', 50)
        self.timeout = self.config.get('timeout', 10)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        
        # Set custom DNS servers if provided
        if 'nameservers' in self.config:
            self.resolver.nameservers = self.config['nameservers']
        
        # Results will store discovered subdomains and their IP addresses
        self.results = {
            'subdomains': {},  # subdomain -> [ip_addresses]
            'total_found': 0
        }
    
    async def run(self, target, *args, **kwargs):
        """
        Run subdomain enumeration on the target domain
        
        Args:
            target (str): The target domain
            
        Returns:
            Dict containing discovered subdomains and their IP addresses
        """
        logger.info(f"Starting DNS enumeration for {target}")
        
        # Validate the target domain
        if not self._is_valid_domain(target):
            logger.error(f"Invalid domain: {target}")
            return self.results
        
        # Create a set to store unique subdomains
        discovered = set()
        
        # Run various discovery methods
        tasks = []
        
        # Bruteforce method
        if self.config.get('bruteforce', True):
            tasks.append(self.bruteforce_subdomains(target))
        
        # Certificate transparency logs
        if self.config.get('cert_transparency', True):
            tasks.append(self.check_certificate_transparency(target))
            
        # Add other discovery methods as tasks
        # ...
        
        # Run all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Error in subdomain enumeration: {result}")
            elif isinstance(result, set):
                discovered.update(result)
        
        # Resolve IPs for discovered subdomains
        await self.resolve_ips(discovered)
        
        # Update statistics
        self.results['total_found'] = len(self.results['subdomains'])
        
        logger.info(f"DNS enumeration completed for {target}. Found {self.results['total_found']} subdomains.")
        return self.results
    
    async def bruteforce_subdomains(self, domain: str) -> Set[str]:
        """
        Perform bruteforce subdomain discovery
        
        Args:
            domain: Base domain to enumerate
            
        Returns:
            Set of discovered subdomains
        """
        logger.info(f"Starting subdomain bruteforce for {domain} with {len(self.wordlist)} words")
        discovered = set()
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_subdomain(subdomain):
            """Try to resolve a subdomain"""
            full_domain = f"{subdomain}.{domain}"
            async with semaphore:
                try:
                    answers = await self._resolve(full_domain, 'A')
                    if answers:
                        logger.debug(f"Found subdomain: {full_domain}")
                        discovered.add(full_domain)
                        return full_domain
                except Exception as e:
                    # Most subdomains won't exist, so we don't log these errors
                    pass
                return None
        
        # Create tasks for all subdomains
        tasks = [check_subdomain(subdomain) for subdomain in self.wordlist]
        await asyncio.gather(*tasks)
        
        logger.info(f"Bruteforce completed. Found {len(discovered)} subdomains.")
        return discovered
    
    async def check_certificate_transparency(self, domain: str) -> Set[str]:
        """
        Check certificate transparency logs for subdomains
        
        Args:
            domain: Base domain to check
            
        Returns:
            Set of discovered subdomains
        """
        logger.info(f"Checking certificate transparency logs for {domain}")
        discovered = set()
        
        try:
            # Use crt.sh API to find certificates for the domain
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://crt.sh/?q=%.{domain}&output=json", 
                    timeout=self.timeout
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data:
                            name_value = item.get("name_value", "")
                            if name_value and name_value.endswith(domain):
                                # Clean up wildcard entries
                                name_value = name_value.replace("*.", "")
                                discovered.add(name_value)
        except Exception as e:
            logger.error(f"Error checking certificate transparency: {e}")
        
        logger.info(f"Certificate transparency check completed. Found {len(discovered)} subdomains.")
        return discovered
    
    async def resolve_ips(self, subdomains: Set[str]):
        """
        Resolve IP addresses for discovered subdomains
        
        Args:
            subdomains: Set of subdomains to resolve
        """
        logger.info(f"Resolving IP addresses for {len(subdomains)} subdomains")
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def resolve_subdomain(subdomain):
            """Resolve IP addresses for a single subdomain"""
            async with semaphore:
                try:
                    a_records = await self._resolve(subdomain, 'A')
                    if a_records:
                        ips = [str(rdata) for rdata in a_records]
                        self.results['subdomains'][subdomain] = ips
                        logger.debug(f"Resolved {subdomain} to {', '.join(ips)}")
                except Exception as e:
                    logger.debug(f"Failed to resolve {subdomain}: {e}")
        
        # Create tasks for all subdomains
        tasks = [resolve_subdomain(subdomain) for subdomain in subdomains]
        await asyncio.gather(*tasks)
        
        logger.info(f"IP resolution completed. Resolved {len(self.results['subdomains'])} subdomains.")
    
    async def _resolve(self, domain: str, record_type: str) -> List[Any]:
        """
        Resolve DNS records for a domain
        
        Args:
            domain: Domain to resolve
            record_type: DNS record type (e.g., 'A', 'AAAA', 'CNAME')
            
        Returns:
            List of DNS record data
        """
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, record_type)
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.debug(f"Error resolving {domain} ({record_type}): {e}")
            return []
    
    def _is_valid_domain(self, domain: str) -> bool:
        """
        Check if a domain is valid
        
        Args:
            domain: Domain to check
            
        Returns:
            True if the domain is valid, False otherwise
        """
        if not domain or len(domain) > 255:
            return False
        
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Check that all labels are valid
        for label in domain.split('.'):
            if not label or len(label) > 63:
                return False
            if not all(c.isalnum() or c == '-' for c in label):
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        
        return True