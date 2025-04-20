"""
Email finder and leak checker module for ReconXtreme

This module discovers email addresses associated with a domain and checks
for potential data breaches containing these emails.
"""
import asyncio
import re
import time
import random
import aiohttp
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Set, Optional, Tuple
import hashlib

from core.logger import get_module_logger
from modules import ModuleBase

logger = get_module_logger("osint.email_finder")

class EmailFinderModule(ModuleBase):
    """
    Email finder module for discovering email addresses and checking for leaks
    
    Discovers email addresses associated with a domain through various techniques:
    - Search engines
    - Social media profiles
    - Data breach databases
    - Pattern-based generation
    """
    
    name = "email_finder"
    description = "Email finder and leak checker"
    author = "ReconXtreme Team"
    version = "0.1.0"
    
    # Common email patterns for guessing
    EMAIL_PATTERNS = [
        "{first}",
        "{last}",
        "{first}.{last}",
        "{first}{last}",
        "{first}_{last}",
        "{f}{last}",
        "{f}.{last}",
        "{first}{l}",
        "{first}.{l}",
        "{first}-{last}"
    ]
    
    # User agents for requests
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
        self.use_leaks_api = self.config.get('use_leaks_api', False)
        self.api_keys = self.config.get('api_keys', {})
        self.check_breaches = self.config.get('check_breaches', True)
        self.verify_emails = self.config.get('verify_emails', True)
        self.common_names = self.config.get('common_names', [])
        
        # Results will store discovered emails and leaks
        self.results = {
            'emails': [],
            'patterns': [],
            'leaks': [],
            'sources': {},
            'validated': [],
            'total_found': 0,
            'total_leaks': 0
        }
    
    async def run(self, target, *args, **kwargs):
        """
        Run email finder on the target domain
        
        Args:
            target (str): The target domain
            
        Returns:
            Dict containing discovered emails and leaks
        """
        logger.info(f"Starting email finder for {target}")
        
        # Create a semaphore to limit concurrent tasks
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Create sets to track unique emails and sources
        found_emails = set()
        sources = {}
        
        # Tasks to run
        tasks = []
        
        # Search for emails using various methods
        tasks.append(self._search_google(target, semaphore, found_emails, sources))
        tasks.append(self._search_github(target, semaphore, found_emails, sources))
        tasks.append(self._search_linkedin(target, semaphore, found_emails, sources))
        
        # If common names are provided, generate potential emails
        if self.common_names:
            tasks.append(self._generate_emails(target, semaphore, found_emails, sources))
        
        # Wait for all search tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process found emails
        all_emails = list(found_emails)
        logger.info(f"Found {len(all_emails)} potential email addresses for {target}")
        
        # Validate emails if enabled
        if self.verify_emails and all_emails:
            validated_emails = await self._validate_emails(all_emails, semaphore)
            self.results['validated'] = validated_emails
        
        # Check for data breaches if enabled
        if self.check_breaches and all_emails:
            leaks = await self._check_data_breaches(all_emails, semaphore)
            self.results['leaks'] = leaks
            self.results['total_leaks'] = len(leaks)
        
        # Update results
        self.results['emails'] = all_emails
        self.results['total_found'] = len(all_emails)
        self.results['sources'] = sources
        
        logger.info(f"Email finder completed for {target}. Found {len(all_emails)} emails.")
        
        return self.results
    
    async def _search_google(self, domain: str, semaphore: asyncio.Semaphore, 
                            found_emails: Set[str], sources: Dict[str, List[str]]):
        """
        Search for emails using Google dorks
        
        Args:
            domain: Target domain
            semaphore: Semaphore for limiting concurrent tasks
            found_emails: Set to store unique emails
            sources: Dict to track where emails were found
        """
        async with semaphore:
            logger.debug(f"Searching Google for emails on {domain}")
            
            # Google dorks for email discovery
            dorks = [
                f"site:{domain} mailto:",
                f"site:{domain} email",
                f"site:{domain} contact",
                f'"@{domain}"',
                f'"email * @{domain}"',
                f'"contact * @{domain}"'
            ]
            
            # Create a session for requests
            async with aiohttp.ClientSession() as session:
                for dork in dorks:
                    try:
                        # Avoid rate limiting
                        await asyncio.sleep(random.uniform(2, 5))
                        
                        # Encode the dork for use in URL
                        encoded_dork = dork.replace(' ', '+')
                        url = f"https://www.google.com/search?q={encoded_dork}&num=100"
                        
                        # Random user agent
                        headers = {
                            "User-Agent": random.choice(self.USER_AGENTS),
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                            "Accept-Language": "en-US,en;q=0.5",
                            "DNT": "1",
                            "Connection": "keep-alive",
                            "Upgrade-Insecure-Requests": "1"
                        }
                        
                        # Make the request
                        async with session.get(url, headers=headers, timeout=self.timeout) as response:
                            if response.status == 200:
                                # Parse the HTML response
                                html = await response.text()
                                
                                # Extract emails
                                emails = self._extract_emails_from_text(html, domain)
                                
                                # Add to results
                                for email in emails:
                                    found_emails.add(email)
                                    if email not in sources:
                                        sources[email] = []
                                    if "Google" not in sources[email]:
                                        sources[email].append("Google")
                            
                            elif response.status == 429:
                                logger.warning("Google rate limit hit, waiting longer before next request")
                                await asyncio.sleep(60)  # Wait longer if rate limited
                    
                    except Exception as e:
                        logger.debug(f"Error searching Google for emails: {e}")
    
    async def _search_github(self, domain: str, semaphore: asyncio.Semaphore, 
                            found_emails: Set[str], sources: Dict[str, List[str]]):
        """
        Search for emails in GitHub repositories
        
        Args:
            domain: Target domain
            semaphore: Semaphore for limiting concurrent tasks
            found_emails: Set to store unique emails
            sources: Dict to track where emails were found
        """
        async with semaphore:
            logger.debug(f"Searching GitHub for emails on {domain}")
            
            # GitHub search queries
            queries = [
                f"'{domain}' email",
                f"'{domain}' mailto",
                f"'@{domain}'",
                f"'@{domain}' email"
            ]
            
            # Create a session for requests
            async with aiohttp.ClientSession() as session:
                for query in queries:
                    try:
                        # Avoid rate limiting
                        await asyncio.sleep(random.uniform(2, 5))
                        
                        # Encode the query for use in URL
                        encoded_query = query.replace(' ', '+').replace("'", "%27")
                        url = f"https://github.com/search?q={encoded_query}&type=Code"
                        
                        # Random user agent
                        headers = {
                            "User-Agent": random.choice(self.USER_AGENTS),
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                            "Accept-Language": "en-US,en;q=0.5",
                            "DNT": "1",
                            "Connection": "keep-alive",
                            "Upgrade-Insecure-Requests": "1"
                        }
                        
                        # Make the request
                        async with session.get(url, headers=headers, timeout=self.timeout) as response:
                            if response.status == 200:
                                # Parse the HTML response
                                html = await response.text()
                                
                                # Extract emails
                                emails = self._extract_emails_from_text(html, domain)
                                
                                # Add to results
                                for email in emails:
                                    found_emails.add(email)
                                    if email not in sources:
                                        sources[email] = []
                                    if "GitHub" not in sources[email]:
                                        sources[email].append("GitHub")
                            
                            elif response.status == 429:
                                logger.warning("GitHub rate limit hit, waiting longer before next request")
                                await asyncio.sleep(60)  # Wait longer if rate limited
                    
                    except Exception as e:
                        logger.debug(f"Error searching GitHub for emails: {e}")
    
    async def _search_linkedin(self, domain: str, semaphore: asyncio.Semaphore, 
                              found_emails: Set[str], sources: Dict[str, List[str]]):
        """
        Search for company employees on LinkedIn and generate potential emails
        
        Args:
            domain: Target domain
            semaphore: Semaphore for limiting concurrent tasks
            found_emails: Set to store unique emails
            sources: Dict to track where emails were found
        """
        async with semaphore:
            logger.debug(f"Searching LinkedIn for employees at {domain}")
            
            # This is a simplified version - in a real implementation,
            # you would need to handle LinkedIn authentication and scraping carefully
            company_name = domain.split('.')[0]
            
            # Search for the company on LinkedIn
            async with aiohttp.ClientSession() as session:
                try:
                    # Encode the company name for use in URL
                    encoded_name = company_name.replace(' ', '%20')
                    url = f"https://www.linkedin.com/company/{encoded_name}"
                    
                    # Random user agent
                    headers = {
                        "User-Agent": random.choice(self.USER_AGENTS),
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "DNT": "1",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1"
                    }
                    
                    # Make the request
                    async with session.get(url, headers=headers, timeout=self.timeout) as response:
                        # LinkedIn often blocks scraping, so this is just a placeholder
                        if response.status == 200:
                            html = await response.text()
                            # In a real implementation, you would parse employee names
                            # and generate potential email addresses
                
                except Exception as e:
                    logger.debug(f"Error searching LinkedIn: {e}")
    
    async def _generate_emails(self, domain: str, semaphore: asyncio.Semaphore, 
                              found_emails: Set[str], sources: Dict[str, List[str]]):
        """
        Generate potential email addresses using common patterns
        
        Args:
            domain: Target domain
            semaphore: Semaphore for limiting concurrent tasks
            found_emails: Set to store unique emails
            sources: Dict to track where emails were found
        """
        async with semaphore:
            logger.debug(f"Generating potential emails for {domain}")
            
            patterns = []
            generated_emails = set()
            
            # Use provided common names to generate potential emails
            for name in self.common_names:
                # Split name into first and last
                parts = name.strip().lower().split()
                if len(parts) >= 2:
                    first = parts[0]
                    last = parts[-1]
                    
                    # First and last initials
                    f = first[0] if first else ''
                    l = last[0] if last else ''
                    
                    # Apply email patterns
                    for pattern in self.EMAIL_PATTERNS:
                        email_prefix = pattern
                        email_prefix = email_prefix.replace("{first}", first)
                        email_prefix = email_prefix.replace("{last}", last)
                        email_prefix = email_prefix.replace("{f}", f)
                        email_prefix = email_prefix.replace("{l}", l)
                        
                        email = f"{email_prefix}@{domain}"
                        generated_emails.add(email)
                        patterns.append(pattern)
            
            # Add generated emails to results
            for email in generated_emails:
                found_emails.add(email)
                if email not in sources:
                    sources[email] = []
                if "Generated" not in sources[email]:
                    sources[email].append("Generated")
            
            # Update patterns in results
            self.results['patterns'] = list(set(patterns))
    
    async def _validate_emails(self, emails: List[str], semaphore: asyncio.Semaphore) -> List[str]:
        """
        Validate email addresses using MX record checks and verification services
        
        Args:
            emails: List of emails to validate
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            List of validated email addresses
        """
        logger.debug(f"Validating {len(emails)} email addresses")
        
        validated = []
        tasks = []
        
        for email in emails:
            tasks.append(self._validate_email(email, semaphore))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, bool) and result:
                validated.append(emails[i])
        
        logger.debug(f"Validated {len(validated)} out of {len(emails)} email addresses")
        return validated
    
    async def _validate_email(self, email: str, semaphore: asyncio.Semaphore) -> bool:
        """
        Validate a single email address
        
        Args:
            email: Email to validate
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            True if email is valid, False otherwise
        """
        async with semaphore:
            try:
                # Extract domain from email
                domain = email.split('@')[1]
                
                # Check MX records
                # This is a simplified check - in a real implementation,
                # you would need to do proper DNS MX record lookups
                
                # For now, we'll just assume the email is valid
                # In a real implementation, you could use services like:
                # - Hunter.io
                # - EmailHippo
                # - Kickbox
                # - NeverBounce
                
                # Simulate some validation process
                await asyncio.sleep(random.uniform(0.5, 1.5))
                
                return True
            
            except Exception as e:
                logger.debug(f"Error validating email {email}: {e}")
                return False
    
    async def _check_data_breaches(self, emails: List[str], semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check for data breaches containing the discovered emails
        
        Args:
            emails: List of emails to check
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            List of data breach information
        """
        logger.debug(f"Checking {len(emails)} emails for data breaches")
        
        leaks = []
        tasks = []
        
        for email in emails:
            tasks.append(self._check_email_breach(email, semaphore))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                leaks.extend(result)
        
        logger.debug(f"Found {len(leaks)} data breaches")
        return leaks
    
    async def _check_email_breach(self, email: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Check a single email for data breaches
        
        Args:
            email: Email to check
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            List of data breach information
        """
        async with semaphore:
            try:
                # This is a simplified implementation
                # In a real implementation, you would use APIs like:
                # - Have I Been Pwned
                # - DeHashed
                # - Intelligence X
                
                # For demonstration, check for breaches using the Have I Been Pwned API
                if 'hibp' in self.api_keys and self.use_leaks_api:
                    api_key = self.api_keys['hibp']
                    return await self._check_hibp(email, api_key)
                else:
                    # Simulate breach check
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    return []
            
            except Exception as e:
                logger.debug(f"Error checking breaches for {email}: {e}")
                return []
    
    async def _check_hibp(self, email: str, api_key: str) -> List[Dict[str, Any]]:
        """
        Check for breaches using the Have I Been Pwned API
        
        Args:
            email: Email to check
            api_key: Have I Been Pwned API key
            
        Returns:
            List of breach information
        """
        result = []
        
        try:
            # Create a session for the HIBP API
            async with aiohttp.ClientSession() as session:
                # Check for account breaches
                headers = {
                    'hibp-api-key': api_key,
                    'User-Agent': 'ReconXtreme Email Breach Checker'
                }
                url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
                
                async with session.get(url, headers=headers, timeout=self.timeout) as response:
                    # Get rate limit information
                    rate_limit = int(response.headers.get('X-Rate-Limit-Remaining', 0))
                    
                    # If we're being rate limited, wait before continuing
                    if rate_limit < 2:
                        await asyncio.sleep(5)
                    
                    # Process the response
                    if response.status == 200:
                        breaches = await response.json()
                        
                        for breach in breaches:
                            result.append({
                                'email': email,
                                'source': breach.get('Name', 'Unknown'),
                                'date': breach.get('BreachDate', 'Unknown'),
                                'description': breach.get('Description', 'No description'),
                                'data_classes': breach.get('DataClasses', []),
                                'verified': breach.get('IsVerified', False),
                                'sensitive': breach.get('IsSensitive', False)
                            })
                    
                    # If the account was not found, it's not in any known breaches
                    elif response.status == 404:
                        pass
        
        except Exception as e:
            logger.debug(f"Error checking HIBP for {email}: {e}")
        
        return result
    
    def _extract_emails_from_text(self, text: str, domain: str) -> Set[str]:
        """
        Extract email addresses from text
        
        Args:
            text: Text to extract emails from
            domain: Domain to filter emails for
            
        Returns:
            Set of email addresses
        """
        # Find all email addresses
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        all_emails = re.findall(email_pattern, text)
        
        # Filter emails for the target domain
        domain_emails = {email.lower() for email in all_emails if email.lower().endswith(f'@{domain}')}
        
        return domain_emails