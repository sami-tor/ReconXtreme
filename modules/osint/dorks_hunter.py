"""
Dorks Hunter module for ReconXtreme

This module implements Google and GitHub dorks to discover exposed sensitive information,
vulnerable endpoints, and security misconfigurations.
"""
import asyncio
import re
import time
import random
import aiohttp
import json
import os
import urllib.parse
from typing import Dict, Any, List, Set, Optional, Tuple

from core.logger import get_module_logger
from modules import ModuleBase

logger = get_module_logger("osint.dorks_hunter")

class DorksHunterModule(ModuleBase):
    """
    Dorks Hunter module for discovering sensitive information using search engines
    
    Utilizes Google and GitHub dorks to find:
    - Exposed sensitive files
    - Configuration files
    - API keys and credentials
    - Information disclosure vulnerabilities
    - Development artifacts
    """
    
    name = "dorks_hunter"
    description = "Hunt for sensitive information using Google and GitHub dorks"
    author = "ReconXtreme Team"
    version = "0.1.0"
    
    # User agents for requests
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
    ]
    
    # Common Google dorks categories
    GOOGLE_DORKS_CATEGORIES = {
        'sensitive_files': [
            "site:{target} ext:sql | ext:db | ext:backup | ext:bak",
            "site:{target} ext:log | ext:txt | ext:conf | ext:cnf | ext:config",
            "site:{target} ext:env | ext:.env | ext:ini",
            "site:{target} intext:\"index of\" \"config\"",
            "site:{target} intext:\"index of\" \"password\"",
            "site:{target} ext:xml | ext:json | ext:yaml | ext:yml",
            "site:{target} ext:inc | ext:bak | ext:old | ext:sql",
            "site:{target} ext:tar | ext:zip | ext:gz | ext:rar | ext:7z",
            "site:{target} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"
        ],
        'exposed_credentials': [
            "site:{target} intext:\"password\" | intext:\"passwd\" | intext:\"pwd\"",
            "site:{target} intext:\"username\" | intext:\"userid\"",
            "site:{target} intext:\"api_key\" | intext:\"apikey\" | intext:\"token\"",
            "site:{target} intext:\"secret_key\" | intext:\"client_secret\"",
            "site:{target} ext:env | ext:yml | ext:json intext:DB_USERNAME | intext:DB_USER | intext:DB_PASSWORD",
            "site:{target} DB_PASSWORD",
            "site:{target} intext:\"mysql_query\" | intext:\"mysqli_query\"",
            "site:{target} intext:\"S3_KEY\" | intext:\"S3_SECRET\""
        ],
        'vulnerable_endpoints': [
            "site:{target} inurl:admin | inurl:login | inurl:logout | inurl:register | inurl:upload",
            "site:{target} inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | inurl:hack",
            "site:{target} inurl:\"*%27\" | inurl:\"?*=\"",
            "site:{target} inurl:php?id= | inurl:view=",
            "site:{target} inurl:\"dashboard\" | inurl:\"cpanel\" | inurl:\"admin-console\"",
            "site:{target} inurl:wp-admin | inurl:wp-login",
            "site:{target} inurl:api/ | inurl:api/v1/ | inurl:api/v2/",
            "site:{target} inurl:download.php | inurl:download?"
        ],
        'server_information': [
            "site:{target} intitle:\"Index of\" | intext:\"Directory Listing\"",
            "site:{target} intext:\"Powered by\" | intext:\"Built with\" | intext:\"Running on\"",
            "site:{target} intext:\"Fatal error\" | intext:\"Warning:\" | intext:\"Error\"",
            "site:{target} intitle:\"Apache HTTP Server Test Page\"",
            "site:{target} intext:\"Internal Server Error\" | intext:\"404 Not Found\"",
            "site:{target} intext:\"SQL syntax\"",
            "site:{target} intext:\"Debug Information\"",
            "site:{target} intext:phpinfo"
        ],
        'development_artifacts': [
            "site:{target} ext:php intitle:phpinfo \"published by the PHP Group\"",
            "site:{target} intext:\"Dumping data for table\"",
            "site:{target} ext:inc | ext:include | ext:tpl | ext:src",
            "site:{target} \"# Git log\" | \"commit hash\"",
            "site:{target} intext:\"Unexpected end of file\" | intext:\"syntax error\"",
            "site:{target} intext:\"localhost\" | intext:\"127.0.0.1\" | intext:\"dev\"",
            "site:{target} intitle:\"Test Page for the Apache HTTP Server\"",
            "site:{target} \"DEBUG\" intext:true | intext:false",
            "site:{target} intext:\"staging\" | intext:\"test\" | intext:\"development\"",
        ]
    }
    
    # GitHub dorks
    GITHUB_DORKS = [
        # API keys and tokens
        "{target} api_key",
        "{target} api_secret",
        "{target} apikey",
        "{target} app_key",
        "{target} app_secret",
        "{target} application_key",
        "{target} appsecret",
        "{target} appkey",
        "{target} appkeysecret",
        "{target} access_key",
        "{target} access_token",
        "{target} auth",
        "{target} authentication",
        "{target} aws_access",
        "{target} aws_secret",
        "{target} bearer",
        "{target} client_secret",
        "{target} db_password",
        "{target} encryption_key",
        "{target} github_token",
        "{target} jwt_secret",
        "{target} oauth_token",
        "{target} passwd",
        "{target} password",
        "{target} private_key",
        "{target} secret",
        "{target} secretkey",
        "{target} slack_token",
        "{target} stripe",
        
        # Development artifacts
        "{target} config",
        "{target} credentials",
        "{target} dump",
        "{target} backup",
        "{target} private",
        "{target} todo",
        "{target} access",
        "{target} configuration.php",
        "{target} settings.py",
        "{target} database.yml",
        "{target} .env",
        "{target} application.yml",
        "{target} wp-config.php",
        "{target} config.js",
        "{target} config.json",
        "{target} connections.xml",
        
        # Specific file types and extensions
        "{target} extension:pem private",
        "{target} extension:ppk private",
        "{target} extension:sql mysql dump",
        "{target} extension:json api.key",
        "{target} extension:yaml id_rsa",
        "{target} extension:env",
        "{target} extension:ini password",
        "{target} extension:log username password",
        
        # Infrastructure
        "{target} filename:wp-config.php",
        "{target} filename:id_rsa",
        "{target} filename:shadow",
        "{target} filename:known_hosts",
        "{target} filename:id_dsa",
        "{target} filename:htpasswd",
        "{target} filename:env.example",
        "{target} filename:settings.py",
        
        # Specific service configurations
        "{target} jenkins",
        "{target} mongodb",
        "{target} mongo",
        "{target} aws",
        "{target} firebase",
        "{target} ftp",
        "{target} ldap"
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = self.config.get('timeout', 10)
        self.max_concurrent = self.config.get('max_concurrent', 3)
        self.use_google = self.config.get('use_google', True)
        self.use_github = self.config.get('use_github', True)
        self.max_results_per_dork = self.config.get('max_results_per_dork', 10)
        self.min_delay = self.config.get('min_delay', 5)
        self.max_delay = self.config.get('max_delay', 15)
        self.custom_dorks = self.config.get('custom_dorks', [])
        self.github_token = self.config.get('github_token', '')
        
        # Results will store discovered information
        self.results = {
            'google_results': {},
            'github_results': {},
            'summary': {
                'total_google_findings': 0,
                'total_github_findings': 0,
                'categories': {}
            },
            'high_severity_findings': []
        }
    
    async def run(self, target, *args, **kwargs):
        """
        Run dorks hunter on the target domain
        
        Args:
            target (str): The target domain
            
        Returns:
            Dict containing discovered sensitive information
        """
        logger.info(f"Starting dorks hunter for {target}")
        
        # Create a semaphore to limit concurrent tasks
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        tasks = []
        
        # Run Google dorks
        if self.use_google:
            tasks.append(self._run_google_dorks(target, semaphore))
        
        # Run GitHub dorks
        if self.use_github:
            tasks.append(self._run_github_dorks(target, semaphore))
        
        # Wait for all tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process high severity findings
        self._process_high_severity_findings()
        
        # Update summary statistics
        self.results['summary']['total_google_findings'] = sum(
            len(findings) for findings in self.results['google_results'].values()
        )
        
        self.results['summary']['total_github_findings'] = sum(
            len(findings) for findings in self.results['github_results'].values()
        )
        
        # Count by category
        category_counts = {}
        for category, findings in self.results['google_results'].items():
            category_counts[category] = len(findings)
        
        self.results['summary']['categories'] = category_counts
        
        logger.info(f"Dorks hunter completed for {target}. " +
                    f"Found {self.results['summary']['total_google_findings']} Google results and " +
                    f"{self.results['summary']['total_github_findings']} GitHub results.")
        
        return self.results
    
    async def _run_google_dorks(self, target: str, semaphore: asyncio.Semaphore):
        """
        Run Google dorks on the target domain
        
        Args:
            target: Target domain
            semaphore: Semaphore for limiting concurrent tasks
        """
        logger.info(f"Running Google dorks for {target}")
        
        # Initialize results for all categories
        for category in self.GOOGLE_DORKS_CATEGORIES:
            self.results['google_results'][category] = []
        
        # Process each category
        for category, dorks in self.GOOGLE_DORKS_CATEGORIES.items():
            logger.debug(f"Processing {category} dorks for {target}")
            
            for dork in dorks:
                # Format dork with target
                formatted_dork = dork.replace("{target}", target)
                
                # Run the dork
                results = await self._run_google_dork(formatted_dork, category, semaphore)
                
                # Add results to the category
                if results:
                    self.results['google_results'][category].extend(results)
                
                # Avoid rate limiting
                delay = random.uniform(self.min_delay, self.max_delay)
                await asyncio.sleep(delay)
        
        # Process custom dorks
        if self.custom_dorks:
            logger.debug(f"Processing custom dorks for {target}")
            self.results['google_results']['custom'] = []
            
            for dork in self.custom_dorks:
                # Format dork with target
                formatted_dork = dork.replace("{target}", target)
                
                # Run the dork
                results = await self._run_google_dork(formatted_dork, 'custom', semaphore)
                
                # Add results to the custom category
                if results:
                    self.results['google_results']['custom'].extend(results)
                
                # Avoid rate limiting
                delay = random.uniform(self.min_delay, self.max_delay)
                await asyncio.sleep(delay)
    
    async def _run_google_dork(self, dork: str, category: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Run a single Google dork and extract results
        
        Args:
            dork: Google dork query
            category: Category of the dork
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            List of dork results
        """
        async with semaphore:
            logger.debug(f"Running Google dork: {dork}")
            
            results = []
            
            try:
                # Create a session for the request
                async with aiohttp.ClientSession() as session:
                    # Encode the dork for use in URL
                    encoded_dork = urllib.parse.quote(dork)
                    url = f"https://www.google.com/search?q={encoded_dork}&num={self.max_results_per_dork}"
                    
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
                            html = await response.text()
                            
                            # Extract search results
                            parsed_results = self._parse_google_results(html, dork, category)
                            if parsed_results:
                                results.extend(parsed_results)
                        
                        elif response.status == 429:
                            logger.warning(f"Google rate limit hit for dork: {dork}")
                            await asyncio.sleep(30)  # Wait longer if rate limited
            
            except Exception as e:
                logger.debug(f"Error running Google dork {dork}: {e}")
            
            return results
    
    def _parse_google_results(self, html: str, dork: str, category: str) -> List[Dict[str, Any]]:
        """
        Parse Google search results from HTML
        
        Args:
            html: HTML content of search results
            dork: Original dork query
            category: Category of the dork
            
        Returns:
            List of parsed search results
        """
        results = []
        
        try:
            # Extract search result items
            # This is a simplified parser - in a real-world scenario, you'd want to use more robust parsing
            result_pattern = r'<div class="[^"]*?g[^"]*?".*?<a href="([^"]+)"[^>]*>(.*?)</a>.*?<div class="[^"]*?">(.*?)</div>'
            matches = re.findall(result_pattern, html, re.DOTALL)
            
            for url, title, snippet in matches:
                # Skip Google's own URLs
                if 'google.com' in url:
                    continue
                
                # Clean up title and snippet
                title = re.sub(r'<[^>]+>', '', title).strip()
                snippet = re.sub(r'<[^>]+>', '', snippet).strip()
                
                # Add to results
                results.append({
                    'url': url,
                    'title': title,
                    'snippet': snippet,
                    'dork': dork,
                    'category': category
                })
        
        except Exception as e:
            logger.debug(f"Error parsing Google results: {e}")
        
        return results
    
    async def _run_github_dorks(self, target: str, semaphore: asyncio.Semaphore):
        """
        Run GitHub dorks on the target domain
        
        Args:
            target: Target domain
            semaphore: Semaphore for limiting concurrent tasks
        """
        logger.info(f"Running GitHub dorks for {target}")
        
        # Initialize results
        self.results['github_results'] = {}
        
        # Run each dork
        for dork in self.GITHUB_DORKS:
            # Format dork with target
            formatted_dork = dork.replace("{target}", target)
            
            # Create a key for the results based on the dork pattern
            key = dork.replace("{target}", "TARGET")
            
            # Run the dork
            results = await self._run_github_dork(formatted_dork, semaphore)
            
            # Store results
            if results:
                self.results['github_results'][key] = results
            
            # Avoid rate limiting
            delay = random.uniform(self.min_delay, self.max_delay)
            await asyncio.sleep(delay)
    
    async def _run_github_dork(self, dork: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
        """
        Run a single GitHub dork and extract results
        
        Args:
            dork: GitHub dork query
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            List of dork results
        """
        async with semaphore:
            logger.debug(f"Running GitHub dork: {dork}")
            
            results = []
            
            try:
                # Create a session for the request
                async with aiohttp.ClientSession() as session:
                    # Build the GitHub search URL
                    encoded_dork = urllib.parse.quote(dork)
                    url = f"https://api.github.com/search/code?q={encoded_dork}&per_page={self.max_results_per_dork}"
                    
                    # Set headers with authentication if token is provided
                    headers = {
                        "Accept": "application/vnd.github.v3+json",
                        "User-Agent": "ReconXtreme-GitHubDorkScanner"
                    }
                    
                    if self.github_token:
                        headers["Authorization"] = f"token {self.github_token}"
                    
                    # Make the request
                    async with session.get(url, headers=headers, timeout=self.timeout) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Process search results
                            if 'items' in data and data['items']:
                                for item in data['items']:
                                    result = {
                                        'repository': item.get('repository', {}).get('full_name', ''),
                                        'path': item.get('path', ''),
                                        'name': item.get('name', ''),
                                        'url': item.get('html_url', ''),
                                        'dork': dork
                                    }
                                    results.append(result)
                        
                        elif response.status == 403:
                            rate_info = {}
                            if 'X-RateLimit-Remaining' in response.headers:
                                rate_info['remaining'] = response.headers['X-RateLimit-Remaining']
                            if 'X-RateLimit-Reset' in response.headers:
                                rate_info['reset'] = response.headers['X-RateLimit-Reset']
                            
                            logger.warning(f"GitHub API rate limit hit: {rate_info}")
                            if 'reset' in rate_info:
                                # Calculate time to wait until rate limit reset
                                reset_time = int(rate_info['reset'])
                                current_time = int(time.time())
                                wait_time = max(reset_time - current_time, 0) + 5
                                
                                logger.warning(f"Waiting {wait_time} seconds for GitHub rate limit reset")
                                await asyncio.sleep(wait_time)
            
            except Exception as e:
                logger.debug(f"Error running GitHub dork {dork}: {e}")
            
            return results
    
    def _process_high_severity_findings(self):
        """
        Process results to identify high severity findings
        """
        high_severity_keywords = [
            'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'api_key', 'apikey',
            'aws', 'credentials', 'db_password', 'private_key', 'ssh', 'ftp', 'auth'
        ]
        
        # Check Google results
        for category, findings in self.results['google_results'].items():
            for finding in findings:
                snippet = finding.get('snippet', '').lower()
                
                if any(keyword in snippet for keyword in high_severity_keywords):
                    self.results['high_severity_findings'].append({
                        'source': 'google',
                        'category': category,
                        'url': finding.get('url', ''),
                        'title': finding.get('title', ''),
                        'reason': 'Contains potentially sensitive information'
                    })
        
        # Check GitHub results
        for dork, findings in self.results['github_results'].items():
            for finding in findings:
                if any(keyword in dork.lower() for keyword in high_severity_keywords):
                    self.results['high_severity_findings'].append({
                        'source': 'github',
                        'dork': dork,
                        'url': finding.get('url', ''),
                        'repository': finding.get('repository', ''),
                        'path': finding.get('path', ''),
                        'reason': 'Contains potentially sensitive information'
                    })