"""
WHOIS lookup module for ReconXtreme

This module performs WHOIS lookups to gather domain registration information
and identify related domains that may be part of the target's infrastructure.
"""
import asyncio
import re
import time
import random
import socket
import ipaddress
import aiohttp
import aiodns
import datetime
from typing import Dict, Any, List, Set, Optional, Tuple
import json

from core.logger import get_module_logger
from modules import ModuleBase

logger = get_module_logger("osint.whois_lookup")

class WhoisLookupModule(ModuleBase):
    """
    WHOIS lookup module for domain and IP information gathering
    
    Performs WHOIS lookups to gather registration information about domains and IPs:
    - Registrar information
    - Creation, expiration dates
    - Name servers
    - Administrative contacts
    - Related domains (same registrant)
    - IP WHOIS (ASN, netblocks)
    """
    
    name = "whois_lookup"
    description = "WHOIS lookups for domain and IP information"
    author = "ReconXtreme Team"
    version = "0.1.0"
    
    # WHOIS servers for various TLDs
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'us': 'whois.nic.us',
        'uk': 'whois.nic.uk',
        'de': 'whois.denic.de',
        'jp': 'whois.jprs.jp',
        'fr': 'whois.nic.fr',
        'ai': 'whois.nic.ai',
        'app': 'whois.nic.google',
        'dev': 'whois.nic.google',
        'ru': 'whois.tcinet.ru',
        'au': 'whois.auda.org.au',
        'arin': 'whois.arin.net',
        'ripe': 'whois.ripe.net',
        'apnic': 'whois.apnic.net',
        'lacnic': 'whois.lacnic.net',
        'afrinic': 'whois.afrinic.net'
    }
    
    # Default WHOIS server
    DEFAULT_WHOIS_SERVER = 'whois.iana.org'
    
    # User agents for HTTP requests
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = self.config.get('timeout', 10)
        self.max_concurrent = self.config.get('max_concurrent', 5)
        self.use_api = self.config.get('use_api', False)
        self.api_keys = self.config.get('api_keys', {})
        self.whois_timeout = self.config.get('whois_timeout', 15)
        self.whois_retries = self.config.get('whois_retries', 3)
        self.query_delay = self.config.get('query_delay', 1)
        self.fetch_related = self.config.get('fetch_related', True)
        self.max_related = self.config.get('max_related', 20)
        
        # Results will store WHOIS information
        self.results = {
            'domain_info': {},
            'ip_info': {},
            'related_domains': [],
            'nameservers': [],
            'registrar': None,
            'emails': [],
            'asn_info': {},
            'creation_date': None,
            'expiration_date': None,
            'last_updated': None,
            'raw_data': {}
        }
    
    async def run(self, target, *args, **kwargs):
        """
        Run WHOIS lookup on the target
        
        Args:
            target (str): The target domain or IP
            
        Returns:
            Dict containing WHOIS information
        """
        logger.info(f"Starting WHOIS lookup for {target}")
        
        # Create a semaphore to limit concurrent tasks
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Determine if the target is an IP or domain
        is_ip = self._is_ip_address(target)
        
        if is_ip:
            logger.info(f"Target {target} is an IP address")
            await self._process_ip(target, semaphore)
        else:
            logger.info(f"Target {target} is a domain")
            await self._process_domain(target, semaphore)
        
        # Process the information
        self._process_results()
        
        logger.info(f"WHOIS lookup completed for {target}")
        
        return self.results
    
    async def _process_domain(self, domain: str, semaphore: asyncio.Semaphore):
        """
        Process a domain target
        
        Args:
            domain: Target domain
            semaphore: Semaphore for limiting concurrent tasks
        """
        # First, get the basic WHOIS information
        whois_data = await self._get_domain_whois(domain, semaphore)
        
        if not whois_data:
            logger.warning(f"Failed to get WHOIS data for {domain}")
            return
        
        self.results['raw_data']['domain'] = whois_data
        
        # Parse the WHOIS data
        parsed_data = self._parse_domain_whois(whois_data, domain)
        self.results['domain_info'] = parsed_data
        
        # Get IP address for the domain
        ip_address = await self._resolve_domain(domain, semaphore)
        
        if ip_address:
            logger.debug(f"Resolved {domain} to IP {ip_address}")
            
            # Store the IP in domain info
            self.results['domain_info']['ip_address'] = ip_address
            
            # Get WHOIS for the IP
            await self._process_ip(ip_address, semaphore)
        
        # Get related domains if enabled
        if self.fetch_related and 'registrant_org' in parsed_data:
            registrant = parsed_data.get('registrant_org') or parsed_data.get('registrant_name')
            
            if registrant:
                related_domains = await self._find_related_domains(registrant, domain, semaphore)
                
                if related_domains:
                    self.results['related_domains'] = related_domains
    
    async def _process_ip(self, ip: str, semaphore: asyncio.Semaphore):
        """
        Process an IP target
        
        Args:
            ip: Target IP
            semaphore: Semaphore for limiting concurrent tasks
        """
        # Get the IP WHOIS information
        whois_data = await self._get_ip_whois(ip, semaphore)
        
        if not whois_data:
            logger.warning(f"Failed to get WHOIS data for IP {ip}")
            return
        
        self.results['raw_data']['ip'] = whois_data
        
        # Parse the IP WHOIS data
        parsed_data = self._parse_ip_whois(whois_data, ip)
        self.results['ip_info'] = parsed_data
        
        # Get ASN information if available
        if 'asn' in parsed_data:
            asn = parsed_data['asn']
            asn_data = await self._get_asn_info(asn, semaphore)
            
            if asn_data:
                self.results['asn_info'] = asn_data
    
    async def _get_domain_whois(self, domain: str, semaphore: asyncio.Semaphore) -> Optional[str]:
        """
        Get WHOIS data for a domain
        
        Args:
            domain: Target domain
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            WHOIS data string or None if error
        """
        async with semaphore:
            logger.debug(f"Getting WHOIS data for domain {domain}")
            
            # Check if we should use an API service
            if self.use_api and 'whois' in self.api_keys:
                return await self._get_whois_from_api(domain)
            
            # Otherwise use direct WHOIS query
            return await self._get_whois_from_server(domain)
    
    async def _get_whois_from_api(self, domain: str) -> Optional[str]:
        """
        Get WHOIS data from an API service
        
        Args:
            domain: Target domain
            
        Returns:
            WHOIS data string or None if error
        """
        try:
            # Get the API key
            api_key = self.api_keys.get('whois')
            
            if not api_key:
                logger.warning("WHOIS API key is missing")
                return None
            
            # For this example, we'll use a generic API structure
            # In a real implementation, you would use a specific WHOIS API service
            
            # Create a session for the request
            async with aiohttp.ClientSession() as session:
                # For example, using the WhoisXML API or a similar service
                url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
                params = {
                    'apiKey': api_key,
                    'domainName': domain,
                    'outputFormat': 'json'
                }
                
                # Make the request
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Extract the raw WHOIS data from the API response
                        if 'rawText' in data:
                            return data['rawText']
                        else:
                            logger.warning(f"API response for {domain} does not contain raw WHOIS data")
                    else:
                        logger.warning(f"WHOIS API request failed for {domain}: HTTP {response.status}")
        
        except Exception as e:
            logger.debug(f"Error getting WHOIS from API for {domain}: {e}")
        
        return None
    
    async def _get_whois_from_server(self, domain: str) -> Optional[str]:
        """
        Get WHOIS data directly from WHOIS servers
        
        Args:
            domain: Target domain
            
        Returns:
            WHOIS data string or None if error
        """
        whois_server = self._get_whois_server(domain)
        
        for attempt in range(self.whois_retries):
            try:
                # Create a socket connection to the WHOIS server
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.whois_timeout)
                
                # Connect to the WHOIS server
                s.connect((whois_server, 43))
                
                # Send the domain query
                query = f"{domain}\r\n"
                s.send(query.encode())
                
                # Receive the response
                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                
                # Close the socket
                s.close()
                
                # Decode the response
                whois_data = response.decode('utf-8', errors='ignore')
                
                # Check if the response contains a referral to another WHOIS server
                referral_server = self._extract_referral_server(whois_data)
                
                if referral_server and referral_server != whois_server:
                    logger.debug(f"Following WHOIS referral to {referral_server}")
                    
                    # Try again with the new server
                    whois_server = referral_server
                    continue
                
                return whois_data
            
            except socket.timeout:
                logger.debug(f"WHOIS server {whois_server} timed out (attempt {attempt+1})")
            
            except Exception as e:
                logger.debug(f"Error getting WHOIS from server {whois_server} for {domain}: {e}")
            
            # Wait before retrying
            await asyncio.sleep(self.query_delay)
        
        return None
    
    def _get_whois_server(self, domain: str) -> str:
        """
        Determine the appropriate WHOIS server for a domain
        
        Args:
            domain: Target domain
            
        Returns:
            WHOIS server hostname
        """
        # Extract the TLD
        tld = domain.split('.')[-1].lower()
        
        # Check if we have a specific server for this TLD
        if tld in self.WHOIS_SERVERS:
            return self.WHOIS_SERVERS[tld]
        
        # Otherwise use the default server
        return self.DEFAULT_WHOIS_SERVER
    
    def _extract_referral_server(self, whois_data: str) -> Optional[str]:
        """
        Extract a referral WHOIS server from WHOIS data
        
        Args:
            whois_data: WHOIS data string
            
        Returns:
            Referral server or None if not found
        """
        # Look for common referral patterns
        patterns = [
            r'(?i)whois server:\s*([^\s]+)',
            r'(?i)refer:\s*([^\s]+)',
            r'(?i)referral url:\s*(?:https?://)?([^/\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, whois_data)
            if match:
                server = match.group(1).strip().lower()
                
                # Remove any trailing dots
                if server.endswith('.'):
                    server = server[:-1]
                
                return server
        
        return None
    
    async def _get_ip_whois(self, ip: str, semaphore: asyncio.Semaphore) -> Optional[str]:
        """
        Get WHOIS data for an IP address
        
        Args:
            ip: Target IP
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            WHOIS data string or None if error
        """
        async with semaphore:
            logger.debug(f"Getting WHOIS data for IP {ip}")
            
            # Determine the appropriate RIR (Regional Internet Registry) for this IP
            whois_server = self._get_rir_for_ip(ip)
            
            for attempt in range(self.whois_retries):
                try:
                    # Create a socket connection to the WHOIS server
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.whois_timeout)
                    
                    # Connect to the WHOIS server
                    s.connect((whois_server, 43))
                    
                    # Send the IP query
                    query = f"{ip}\r\n"
                    s.send(query.encode())
                    
                    # Receive the response
                    response = b""
                    while True:
                        data = s.recv(4096)
                        if not data:
                            break
                        response += data
                    
                    # Close the socket
                    s.close()
                    
                    # Decode the response
                    whois_data = response.decode('utf-8', errors='ignore')
                    
                    return whois_data
                
                except socket.timeout:
                    logger.debug(f"WHOIS server {whois_server} timed out (attempt {attempt+1})")
                
                except Exception as e:
                    logger.debug(f"Error getting WHOIS from server {whois_server} for IP {ip}: {e}")
                
                # Wait before retrying
                await asyncio.sleep(self.query_delay)
            
            return None
    
    def _get_rir_for_ip(self, ip: str) -> str:
        """
        Determine the appropriate RIR for an IP address
        
        This is a simplified approach. In a real implementation, you would use
        more accurate methods to determine the correct RIR.
        
        Args:
            ip: Target IP
            
        Returns:
            WHOIS server for the RIR
        """
        try:
            # Convert string to IP address object
            ip_obj = ipaddress.ip_address(ip)
            
            # Determine if it's a private IP
            if ip_obj.is_private:
                return self.WHOIS_SERVERS['arin']  # Default to ARIN for private IPs
            
            # Simple range checking for RIRs
            # This is not fully accurate but provides a reasonable approximation
            ip_int = int(ip_obj)
            
            # ARIN (North America)
            if (ip_int >> 24) in [3, 4, 6, 8, 9, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 28, 29, 30]:
                return self.WHOIS_SERVERS['arin']
            
            # RIPE (Europe, Middle East, Central Asia)
            if (ip_int >> 24) in [31, 37, 46, 51, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91]:
                return self.WHOIS_SERVERS['ripe']
            
            # APNIC (Asia Pacific)
            if (ip_int >> 24) in [1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126]:
                return self.WHOIS_SERVERS['apnic']
            
            # LACNIC (Latin America and Caribbean)
            if (ip_int >> 24) in [186, 187, 189, 190, 191, 200, 201]:
                return self.WHOIS_SERVERS['lacnic']
            
            # AFRINIC (Africa)
            if (ip_int >> 24) in [41, 102, 105, 154, 196, 197]:
                return self.WHOIS_SERVERS['afrinic']
            
        except ValueError:
            pass
        
        # Default to ARIN if we can't determine
        return self.WHOIS_SERVERS['arin']
    
    async def _get_asn_info(self, asn: str, semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
        """
        Get information about an Autonomous System Number (ASN)
        
        Args:
            asn: ASN string or number
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            Dictionary with ASN information or None if error
        """
        async with semaphore:
            logger.debug(f"Getting information for ASN {asn}")
            
            try:
                # Remove 'AS' prefix if present
                if isinstance(asn, str) and asn.upper().startswith('AS'):
                    asn = asn[2:]
                
                # Create a session for the request
                async with aiohttp.ClientSession() as session:
                    # Use a public ASN lookup API
                    url = f"https://api.bgpview.io/asn/{asn}"
                    
                    # Random user agent
                    headers = {
                        "User-Agent": random.choice(self.USER_AGENTS),
                        "Accept": "application/json"
                    }
                    
                    # Make the request
                    async with session.get(url, headers=headers, timeout=self.timeout) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Process the response
                            if data.get('status') == 'ok':
                                asn_data = data.get('data', {})
                                
                                # Extract relevant information
                                return {
                                    'asn': asn_data.get('asn'),
                                    'name': asn_data.get('name'),
                                    'description': asn_data.get('description_full'),
                                    'country_code': asn_data.get('country_code'),
                                    'prefix_count': asn_data.get('prefix_count'),
                                    'rir_allocation': asn_data.get('rir_allocation', {}).get('rir_name'),
                                    'looking_glass': asn_data.get('looking_glass'),
                                    'prefixes': self._extract_asn_prefixes(asn_data)
                                }
                        else:
                            logger.warning(f"ASN lookup failed for {asn}: HTTP {response.status}")
            
            except Exception as e:
                logger.debug(f"Error getting ASN information for {asn}: {e}")
            
            return None
    
    def _extract_asn_prefixes(self, asn_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract network prefixes from ASN data
        
        Args:
            asn_data: ASN data from API
            
        Returns:
            List of network prefixes with details
        """
        prefixes = []
        
        # Extract IPv4 prefixes
        for prefix in asn_data.get('prefixes', []):
            prefixes.append({
                'prefix': prefix.get('prefix'),
                'ip_version': 4,
                'name': prefix.get('name'),
                'description': prefix.get('description'),
                'country_code': prefix.get('country_code')
            })
        
        # Extract IPv6 prefixes
        for prefix in asn_data.get('prefixes_v6', []):
            prefixes.append({
                'prefix': prefix.get('prefix'),
                'ip_version': 6,
                'name': prefix.get('name'),
                'description': prefix.get('description'),
                'country_code': prefix.get('country_code')
            })
        
        return prefixes
    
    async def _resolve_domain(self, domain: str, semaphore: asyncio.Semaphore) -> Optional[str]:
        """
        Resolve a domain to an IP address
        
        Args:
            domain: Domain to resolve
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            IP address or None if resolution fails
        """
        async with semaphore:
            logger.debug(f"Resolving domain {domain} to IP")
            
            try:
                # Create a DNS resolver
                resolver = aiodns.DNSResolver()
                
                # Resolve the domain
                result = await resolver.query(domain, 'A')
                
                # Return the first IP
                if result and len(result) > 0:
                    return result[0].host
            
            except Exception as e:
                logger.debug(f"Error resolving domain {domain}: {e}")
            
            return None
    
    async def _find_related_domains(self, registrant: str, domain: str, semaphore: asyncio.Semaphore) -> List[str]:
        """
        Find domains with the same registrant
        
        This is a simplified implementation. In a real-world scenario, you would
        use more robust methods to find related domains.
        
        Args:
            registrant: Registrant name or organization
            domain: Original domain (to exclude from results)
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            List of related domains
        """
        async with semaphore:
            logger.debug(f"Finding domains registered to {registrant}")
            
            related_domains = []
            
            # Check if we have an API key for domain research
            if self.use_api and 'domaintools' in self.api_keys:
                return await self._find_related_domains_api(registrant, domain)
            
            # Simplified implementation for demonstration
            # In a real implementation, you would use more sources
            
            try:
                # Create a session for the request
                async with aiohttp.ClientSession() as session:
                    # Use a search engine to find related domains
                    search_query = f"intext:\"{registrant}\" intitle:\"domain registration information\""
                    encoded_query = urllib.parse.quote(search_query)
                    url = f"https://www.google.com/search?q={encoded_query}&num=100"
                    
                    # Random user agent
                    headers = {
                        "User-Agent": random.choice(self.USER_AGENTS),
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5"
                    }
                    
                    # Make the request
                    async with session.get(url, headers=headers, timeout=self.timeout) as response:
                        if response.status == 200:
                            html = await response.text()
                            
                            # Extract domains from search results
                            domains = self._extract_domains_from_html(html)
                            
                            # Filter out the original domain and limit results
                            related_domains = [d for d in domains if d != domain][:self.max_related]
                        
                        elif response.status == 429:
                            logger.warning("Search engine rate limit hit")
            
            except Exception as e:
                logger.debug(f"Error finding related domains for {registrant}: {e}")
            
            return related_domains
    
    async def _find_related_domains_api(self, registrant: str, domain: str) -> List[str]:
        """
        Find related domains using an API service
        
        Args:
            registrant: Registrant name or organization
            domain: Original domain
            
        Returns:
            List of related domains
        """
        related_domains = []
        
        try:
            # Get the API key
            api_key = self.api_keys.get('domaintools')
            
            if not api_key:
                logger.warning("Domain research API key is missing")
                return related_domains
            
            # Create a session for the request
            async with aiohttp.ClientSession() as session:
                # For example, using the DomainTools Reverse WHOIS API
                url = "https://api.domaintools.com/v1/reverse-whois/"
                params = {
                    'api_key': api_key,
                    'terms': registrant,
                    'mode': 'quote'
                }
                
                # Make the request
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Extract the domains from the API response
                        if 'domains' in data:
                            domains = data['domains']
                            
                            # Filter out the original domain and limit results
                            related_domains = [d for d in domains if d != domain][:self.max_related]
                    else:
                        logger.warning(f"Domain research API request failed: HTTP {response.status}")
        
        except Exception as e:
            logger.debug(f"Error finding related domains using API: {e}")
        
        return related_domains
    
    def _extract_domains_from_html(self, html: str) -> List[str]:
        """
        Extract domain names from HTML
        
        Args:
            html: HTML content
            
        Returns:
            List of extracted domains
        """
        domains = []
        
        # Regular expression to find domains
        domain_pattern = r'(?:https?://)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        matches = re.findall(domain_pattern, html)
        
        for match in matches:
            # Clean up the domain
            domain = match.lower()
            
            # Remove protocol prefix
            if domain.startswith('http://'):
                domain = domain[7:]
            elif domain.startswith('https://'):
                domain = domain[8:]
            
            # Remove trailing slashes and paths
            domain = domain.split('/')[0]
            
            # Add to the list if not already there
            if domain not in domains:
                domains.append(domain)
        
        return domains
    
    def _parse_domain_whois(self, whois_data: str, domain: str) -> Dict[str, Any]:
        """
        Parse WHOIS data for a domain
        
        Args:
            whois_data: Raw WHOIS data
            domain: Target domain
            
        Returns:
            Dictionary with parsed WHOIS data
        """
        parsed = {
            'domain': domain,
            'registrar': None,
            'whois_server': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'status': [],
            'nameservers': [],
            'emails': [],
            'registrant_name': None,
            'registrant_org': None,
            'admin_name': None,
            'admin_email': None,
            'tech_name': None,
            'tech_email': None
        }
        
        # Extract information using regular expressions
        
        # Registrar
        registrar_match = re.search(r'(?i)Registrar:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if registrar_match:
            parsed['registrar'] = registrar_match.group(1).strip()
        
        # WHOIS Server
        whois_server_match = re.search(r'(?i)Whois Server:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if whois_server_match:
            parsed['whois_server'] = whois_server_match.group(1).strip()
        
        # Creation Date
        creation_date_match = re.search(r'(?i)Creation Date:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if creation_date_match:
            parsed['creation_date'] = self._clean_date(creation_date_match.group(1).strip())
        
        # Expiration Date
        expiration_date_match = re.search(r'(?i)Registry Expiry Date:[ \t]*(.+)$|(?i)Expiration Date:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if expiration_date_match:
            expiry = expiration_date_match.group(1) or expiration_date_match.group(2)
            parsed['expiration_date'] = self._clean_date(expiry.strip())
        
        # Updated Date
        updated_date_match = re.search(r'(?i)Updated Date:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if updated_date_match:
            parsed['updated_date'] = self._clean_date(updated_date_match.group(1).strip())
        
        # Status
        status_matches = re.findall(r'(?i)Status:[ \t]*(.+)$', whois_data, re.MULTILINE)
        parsed['status'] = [status.strip() for status in status_matches]
        
        # Name Servers
        ns_matches = re.findall(r'(?i)Name Server:[ \t]*(.+)$', whois_data, re.MULTILINE)
        parsed['nameservers'] = [ns.strip().lower() for ns in ns_matches if ns.strip()]
        
        # Emails
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        parsed['emails'] = list(set(re.findall(email_pattern, whois_data)))
        
        # Registrant Information
        registrant_name_match = re.search(r'(?i)Registrant Name:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if registrant_name_match:
            parsed['registrant_name'] = registrant_name_match.group(1).strip()
        
        registrant_org_match = re.search(r'(?i)Registrant Organization:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if registrant_org_match:
            parsed['registrant_org'] = registrant_org_match.group(1).strip()
        
        # Admin Information
        admin_name_match = re.search(r'(?i)Admin Name:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if admin_name_match:
            parsed['admin_name'] = admin_name_match.group(1).strip()
        
        admin_email_match = re.search(r'(?i)Admin Email:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if admin_email_match:
            parsed['admin_email'] = admin_email_match.group(1).strip()
        
        # Tech Information
        tech_name_match = re.search(r'(?i)Technical Name:[ \t]*(.+)$|(?i)Tech Name:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if tech_name_match:
            parsed['tech_name'] = (tech_name_match.group(1) or tech_name_match.group(2)).strip()
        
        tech_email_match = re.search(r'(?i)Technical Email:[ \t]*(.+)$|(?i)Tech Email:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if tech_email_match:
            parsed['tech_email'] = (tech_email_match.group(1) or tech_email_match.group(2)).strip()
        
        return parsed
    
    def _parse_ip_whois(self, whois_data: str, ip: str) -> Dict[str, Any]:
        """
        Parse WHOIS data for an IP
        
        Args:
            whois_data: Raw WHOIS data
            ip: Target IP
            
        Returns:
            Dictionary with parsed WHOIS data
        """
        parsed = {
            'ip': ip,
            'asn': None,
            'netblock': None,
            'netname': None,
            'organization': None,
            'country': None,
            'address': None,
            'abuse_contact': None,
            'created': None,
            'last_updated': None
        }
        
        # Extract information using regular expressions
        
        # ASN
        asn_match = re.search(r'(?i)origin(?:as)?:[ \t]*([^\s]+)', whois_data, re.MULTILINE)
        if asn_match:
            parsed['asn'] = asn_match.group(1).strip().upper()
        
        # Netblock
        netblock_match = re.search(r'(?i)inetnum:[ \t]*(.+)$|(?i)netrange:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if netblock_match:
            parsed['netblock'] = (netblock_match.group(1) or netblock_match.group(2)).strip()
        
        # Netname
        netname_match = re.search(r'(?i)netname:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if netname_match:
            parsed['netname'] = netname_match.group(1).strip()
        
        # Organization
        org_match = re.search(r'(?i)organization:[ \t]*(.+)$|(?i)orgname:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if org_match:
            parsed['organization'] = (org_match.group(1) or org_match.group(2)).strip()
        
        # Country
        country_match = re.search(r'(?i)country:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if country_match:
            parsed['country'] = country_match.group(1).strip()
        
        # Address (collect all lines)
        address_lines = []
        in_address_block = False
        
        for line in whois_data.split('\n'):
            line = line.strip()
            
            # Check for start of address block
            if re.match(r'(?i)address:', line):
                in_address_block = True
                address_lines.append(line.split(':', 1)[1].strip())
            
            # Continue collecting address lines
            elif in_address_block and line and ':' not in line:
                address_lines.append(line)
            
            # End of address block
            elif in_address_block and ':' in line:
                in_address_block = False
        
        if address_lines:
            parsed['address'] = ', '.join(address_lines)
        
        # Abuse contact
        abuse_match = re.search(r'(?i)abuse-mailbox:[ \t]*(.+)$|(?i)orgabuseemail:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if abuse_match:
            parsed['abuse_contact'] = (abuse_match.group(1) or abuse_match.group(2)).strip()
        
        # Created date
        created_match = re.search(r'(?i)created:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if created_match:
            parsed['created'] = self._clean_date(created_match.group(1).strip())
        
        # Last updated
        updated_match = re.search(r'(?i)last-modified:[ \t]*(.+)$|(?i)changed:[ \t]*(.+)$', whois_data, re.MULTILINE)
        if updated_match:
            parsed['last_updated'] = self._clean_date((updated_match.group(1) or updated_match.group(2)).strip())
        
        return parsed
    
    def _clean_date(self, date_str: str) -> str:
        """
        Clean and normalize a date string from WHOIS
        
        Args:
            date_str: Date string from WHOIS
            
        Returns:
            Cleaned date string
        """
        # Remove timezone indicators and other non-standard formatting
        clean_str = re.sub(r'\([^)]*\)', '', date_str).strip()
        
        return clean_str
    
    def _is_ip_address(self, target: str) -> bool:
        """
        Check if the target is an IP address
        
        Args:
            target: Target string
            
        Returns:
            True if target is an IP, False otherwise
        """
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _process_results(self):
        """
        Process and organize the results
        """
        # Update top-level results from domain info
        if 'domain_info' in self.results and self.results['domain_info']:
            domain_info = self.results['domain_info']
            
            self.results['registrar'] = domain_info.get('registrar')
            self.results['nameservers'] = domain_info.get('nameservers', [])
            self.results['emails'] = domain_info.get('emails', [])
            self.results['creation_date'] = domain_info.get('creation_date')
            self.results['expiration_date'] = domain_info.get('expiration_date')
            self.results['last_updated'] = domain_info.get('updated_date')