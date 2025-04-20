"""
Web crawler module for ReconXtreme

This module implements an asynchronous web crawler that identifies URLs, endpoints,
forms, JavaScript files, and other useful information from web applications.
"""
import asyncio
import platform
if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
import re
import urllib.parse
from typing import Dict, List, Set, Any, Optional, Tuple
import aiohttp
from bs4 import BeautifulSoup
import logging

from core.logger import get_module_logger
from modules import ModuleBase

logger = get_module_logger("web_crawler.crawler")

class WebCrawlerModule(ModuleBase):
    """Web crawler module for discovering website content and structure"""
    
    name = "web_crawler"
    description = "Asynchronous web crawler for discovering website content"
    author = "ReconXtreme Team"
    version = "0.1.0"
    
    # Default User-Agent
    DEFAULT_USER_AGENT = "ReconXtreme/0.1.0 Web Crawler (https://github.com/recon-xtreme/recon-xtreme)"
    
    # Default ignored extensions
    DEFAULT_IGNORED_EXTENSIONS = [
        '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.tiff', '.bmp', '.svg', 
        '.mp3', '.mp4', '.avi', '.wmv', '.mov', '.flv', '.zip', '.tar', '.gz',
        '.rar', '.7z', '.css', '.ico', '.woff', '.woff2', '.ttf', '.eot'
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        
        # Set configuration with defaults
        self.max_depth = self.config.get('max_depth', 3)
        self.max_urls = self.config.get('max_urls', 500)
        self.timeout = self.config.get('timeout', 10)
        self.max_concurrent = self.config.get('max_concurrent', 10)
        self.user_agent = self.config.get('user_agent', self.DEFAULT_USER_AGENT)
        self.respect_robots = self.config.get('respect_robots', True)
        self.follow_redirects = self.config.get('follow_redirects', True)
        self.include_subdomains = self.config.get('include_subdomains', False)
        self.cookies = self.config.get('cookies', {})
        self.headers = self.config.get('headers', {})
        self.ignored_extensions = self.config.get('ignored_extensions', self.DEFAULT_IGNORED_EXTENSIONS)
        
        # Add default User-Agent if not provided in headers
        if 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = self.user_agent
        
        # Results will store discovered URLs, forms, scripts, etc.
        self.results = {
            'urls': set(),
            'visited': set(),
            'endpoints': set(),
            'forms': [],
            'javascript_files': set(),
            'technologies': set(),
            'emails': set(),
            'parameters': set(),
            'content_types': {},
            'status_codes': {},
            'unique_paths': set(),
            'total_urls': 0
        }
        
        # Track already visited URLs and robots.txt rules
        self._visited_urls = set()
        self._robots_rules = set()
        self._base_domain = None
    
    async def run(self, target, *args, **kwargs):
        """
        Run web crawler on the target
        
        Args:
            target (str): The target URL
            
        Returns:
            Dict containing discovered web content and structure
        """
        logger.info(f"Starting web crawler for {target}")
        
        # Normalize the target URL
        target = self._normalize_url(target)
        
        # Extract base domain for subdomain checking
        self._base_domain = self._extract_domain(target)
        logger.info(f"Base domain: {self._base_domain}")
        
        # Check robots.txt if enabled
        if self.respect_robots:
            await self._fetch_robots_txt(target)
        
        # Create session for all requests
        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            # Start crawling from the target URL
            await self._crawl_url(session, target, depth=0)
        
        # Process results
        self.results['total_urls'] = len(self.results['urls'])
        self.results['urls'] = list(self.results['urls'])
        self.results['visited'] = list(self.results['visited'])
        self.results['endpoints'] = list(self.results['endpoints'])
        self.results['javascript_files'] = list(self.results['javascript_files'])
        self.results['technologies'] = list(self.results['technologies'])
        self.results['emails'] = list(self.results['emails'])
        self.results['parameters'] = list(self.results['parameters'])
        self.results['unique_paths'] = list(self.results['unique_paths'])
        
        logger.info(f"Web crawling completed for {target}. "
                   f"Found {len(self.results['urls'])} URLs, "
                   f"visited {len(self.results['visited'])}, "
                   f"discovered {len(self.results['endpoints'])} endpoints.")
        
        return self.results
    
    async def _crawl_url(self, session: aiohttp.ClientSession, url: str, depth: int = 0):
        """
        Crawl a single URL and extract information
        
        Args:
            session: HTTP client session
            url: URL to crawl
            depth: Current crawl depth
        """
        # Check if we've reached maximum depth or URLs
        if depth > self.max_depth or len(self.results['visited']) >= self.max_urls:
            return
        
        # Check if URL has already been visited
        if url in self._visited_urls:
            return
        
        # Check if URL should be excluded based on extension
        if self._should_skip_url(url):
            return
        
        # Check if URL is allowed by robots.txt
        if self.respect_robots and not self._is_allowed_by_robots(url):
            logger.debug(f"Skipping {url} (disallowed by robots.txt)")
            return
        
        # Mark URL as visited
        self._visited_urls.add(url)
        self.results['visited'].add(url)
        self.results['urls'].add(url)
        
        # Add the path to unique paths
        path = urllib.parse.urlparse(url).path
        if path:
            self.results['unique_paths'].add(path)
        
        # Extract parameters
        query = urllib.parse.urlparse(url).query
        if query:
            params = urllib.parse.parse_qs(query)
            for param in params.keys():
                self.results['parameters'].add(param)
        
        try:
            # Fetch the URL
            async with session.get(
                url, 
                headers=self.headers, 
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            ) as response:
                # Record status code
                status_code = response.status
                self.results['status_codes'][url] = status_code
                
                # Skip if not a successful response
                if status_code != 200:
                    logger.debug(f"Skipping {url} (status code: {status_code})")
                    return
                
                # Get content type
                content_type = response.headers.get('Content-Type', '').lower()
                self.results['content_types'][url] = content_type
                
                # Process HTML content
                if 'text/html' in content_type:
                    html = await response.text()
                    await self._process_html(session, url, html, depth)
                    await asyncio.sleep(0)  # Allow other coroutines to run
                
                # Process JavaScript content
                elif 'javascript' in content_type or url.endswith('.js'):
                    self.results['javascript_files'].add(url)
                    js_content = await response.text()
                    self._extract_from_javascript(url, js_content)
        
        except asyncio.TimeoutError:
            logger.debug(f"Timeout while fetching {url}")
        
        except Exception as e:
            logger.debug(f"Error while crawling {url}: {e}")
    
    async def _process_html(self, session: aiohttp.ClientSession, url: str, html: str, depth: int):
        """
        Process HTML content and extract links, forms, etc.
        
        Args:
            session: HTTP client session
            url: Source URL
            html: HTML content
            depth: Current crawl depth
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
            base_url = self._get_base_url(url, soup)
            
            # Extract all links
            links = self._extract_links(soup, base_url)
            
            # Extract forms
            self._extract_forms(soup, base_url)
            
            # Extract scripts
            self._extract_scripts(soup, base_url)
            
            # Extract emails
            self._extract_emails(html)
            
            # Detect technologies
            self._detect_technologies(soup, url)
            
            # Extract API endpoints
            self._extract_api_endpoints(html)
            
            # Create tasks to crawl discovered links
            tasks = []
            for link in links:
                # Only proceed if we haven't hit our limits
                if len(self.results['visited']) < self.max_urls:
                    # Check if the link belongs to the same domain or subdomains are included
                    if self._is_same_domain(link) or (self.include_subdomains and self._is_subdomain(link)):
                        tasks.append(self._crawl_url(session, link, depth + 1))
            
            # Run link crawling tasks concurrently with a limit
            semaphore = asyncio.Semaphore(self.max_concurrent)
            
            async def crawl_with_semaphore(link):
                async with semaphore:
                    await self._crawl_url(session, link, depth + 1)
            
            await asyncio.gather(*[crawl_with_semaphore(link) for link in links], 
                                return_exceptions=True)
            
        except Exception as e:
            logger.debug(f"Error processing HTML from {url}: {e}")
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        Extract links from HTML
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving relative URLs
            
        Returns:
            List of absolute URLs
        """
        links = []
        
        # Extract links from <a> tags
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            absolute_url = self._make_absolute_url(href, base_url)
            if absolute_url:
                links.append(absolute_url)
                self.results['urls'].add(absolute_url)
        
        # Extract links from <link> tags
        for link_tag in soup.find_all('link', href=True):
            href = link_tag['href']
            absolute_url = self._make_absolute_url(href, base_url)
            if absolute_url:
                links.append(absolute_url)
                self.results['urls'].add(absolute_url)
        
        # Extract links from <script> tags
        for script_tag in soup.find_all('script', src=True):
            src = script_tag['src']
            absolute_url = self._make_absolute_url(src, base_url)
            if absolute_url:
                links.append(absolute_url)
                self.results['urls'].add(absolute_url)
                self.results['javascript_files'].add(absolute_url)
        
        # Extract links from <img> tags
        for img_tag in soup.find_all('img', src=True):
            src = img_tag['src']
            absolute_url = self._make_absolute_url(src, base_url)
            if absolute_url:
                links.append(absolute_url)
                self.results['urls'].add(absolute_url)
        
        return list(set(links))
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str):
        """
        Extract forms from HTML
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving relative URLs
        """
        for form in soup.find_all('form'):
            form_data = {
                'action': '',
                'method': 'GET',
                'inputs': []
            }
            
            # Get form action
            if form.get('action'):
                action = form['action']
                form_data['action'] = self._make_absolute_url(action, base_url) or action
            else:
                form_data['action'] = base_url
            
            # Get form method
            if form.get('method'):
                form_data['method'] = form['method'].upper()
            
            # Get form inputs
            for input_tag in form.find_all('input'):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.get('required') is not None
                }
                form_data['inputs'].append(input_data)
            
            # Add form to results
            self.results['forms'].append(form_data)
    
    def _extract_scripts(self, soup: BeautifulSoup, base_url: str):
        """
        Extract scripts from HTML
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving relative URLs
        """
        for script in soup.find_all('script', src=True):
            src = script['src']
            absolute_url = self._make_absolute_url(src, base_url)
            if absolute_url:
                self.results['javascript_files'].add(absolute_url)
    
    def _extract_emails(self, html: str):
        """
        Extract email addresses from content
        
        Args:
            html: HTML content
        """
        # Simple regex for email addresses
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, html)
        for email in emails:
            self.results['emails'].add(email)
    
    def _detect_technologies(self, soup: BeautifulSoup, url: str):
        """
        Detect web technologies used by the website
        
        Args:
            soup: BeautifulSoup object
            url: URL of the page
        """
        # Check for common JS frameworks
        scripts = [script.get('src', '') for script in soup.find_all('script', src=True)]
        
        # React
        if any('react' in script.lower() for script in scripts):
            self.results['technologies'].add('React')
        
        # Angular
        if any('angular' in script.lower() for script in scripts):
            self.results['technologies'].add('Angular')
        
        # Vue.js
        if any('vue' in script.lower() for script in scripts):
            self.results['technologies'].add('Vue.js')
        
        # jQuery
        if any('jquery' in script.lower() for script in scripts):
            self.results['technologies'].add('jQuery')
        
        # Bootstrap (CSS check)
        if soup.find('link', href=lambda href: href and 'bootstrap' in href.lower()):
            self.results['technologies'].add('Bootstrap')
        
        # WordPress check
        if soup.find('meta', {'name': 'generator', 'content': lambda content: content and 'wordpress' in content.lower()}):
            self.results['technologies'].add('WordPress')
        
        # Drupal check
        if 'drupal' in str(soup).lower():
            self.results['technologies'].add('Drupal')
    
    def _extract_api_endpoints(self, html: str):
        """
        Extract potential API endpoints from content
        
        Args:
            html: HTML content
        """
        # Common API endpoint patterns
        api_patterns = [
            r'/api/v\d+/[a-zA-Z0-9_-]+',
            r'/api/[a-zA-Z0-9_-]+',
            r'/v\d+/[a-zA-Z0-9_-]+',
            r'/rest/[a-zA-Z0-9_-]+',
            r'/graphql'
        ]
        
        for pattern in api_patterns:
            endpoints = re.findall(pattern, html)
            for endpoint in endpoints:
                self.results['endpoints'].add(endpoint)
    
    def _extract_from_javascript(self, url: str, js_content: str):
        """
        Extract endpoints and other information from JavaScript files
        
        Args:
            url: URL of the JavaScript file
            js_content: JavaScript content
        """
        # Extract URLs
        url_pattern = r'(https?://[^\s\'"]+)'
        urls = re.findall(url_pattern, js_content)
        for found_url in urls:
            # Remove any trailing quotes, commas, etc.
            clean_url = re.sub(r'[\'",)]$', '', found_url)
            self.results['urls'].add(clean_url)
        
        # Extract API endpoints
        api_patterns = [
            r'"(/api/v\d+/[^"]+)"',
            r'"(/api/[^"]+)"',
            r'"(/v\d+/[^"]+)"',
            r'"(/rest/[^"]+)"',
            r"'(/api/v\d+/[^']+)'",
            r"'(/api/[^']+)'",
            r"'(/v\d+/[^']+)'",
            r"'(/rest/[^']+)'"
        ]
        
        for pattern in api_patterns:
            endpoints = re.findall(pattern, js_content)
            for endpoint in endpoints:
                self.results['endpoints'].add(endpoint)
    
    async def _fetch_robots_txt(self, url: str):
        """
        Fetch and parse robots.txt file
        
        Args:
            url: Base URL for the website
        """
        try:
            # Construct robots.txt URL
            parsed_url = urllib.parse.urlparse(url)
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(robots_url, timeout=self.timeout) as response:
                    if response.status == 200:
                        robots_content = await response.text()
                        self._parse_robots_txt(robots_content)
                        logger.debug(f"Parsed robots.txt: {len(self._robots_rules)} rules found")
        
        except Exception as e:
            logger.debug(f"Error fetching robots.txt: {e}")
    
    def _parse_robots_txt(self, content: str):
        """
        Parse robots.txt content
        
        Args:
            content: robots.txt content
        """
        # Simple robots.txt parser
        lines = content.splitlines()
        current_agent = None
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Check for User-agent
            if line.lower().startswith('user-agent:'):
                agent = line[11:].strip()
                current_agent = agent
            
            # Check for Disallow directive
            elif current_agent and line.lower().startswith('disallow:'):
                if current_agent == '*' or current_agent.lower() == self.user_agent.lower():
                    path = line[9:].strip()
                    if path:
                        self._robots_rules.add(path)
    
    def _is_allowed_by_robots(self, url: str) -> bool:
        """
        Check if URL is allowed by robots.txt rules
        
        Args:
            url: URL to check
            
        Returns:
            True if allowed, False if disallowed
        """
        # If no rules, everything is allowed
        if not self._robots_rules:
            return True
        
        # Get the path part of the URL
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path
        
        # Check if path matches any disallow rule
        for rule in self._robots_rules:
            if rule == '/' or path.startswith(rule):
                return False
        
        return True
    
    def _should_skip_url(self, url: str) -> bool:
        """
        Check if URL should be skipped based on extension
        
        Args:
            url: URL to check
            
        Returns:
            True if should skip, False otherwise
        """
        for ext in self.ignored_extensions:
            if url.lower().endswith(ext):
                return True
        return False
    
    def _is_same_domain(self, url: str) -> bool:
        """
        Check if URL belongs to the same domain
        
        Args:
            url: URL to check
            
        Returns:
            True if same domain, False otherwise
        """
        try:
            domain = self._extract_domain(url)
            return domain == self._base_domain
        except Exception:
            return False
    
    def _is_subdomain(self, url: str) -> bool:
        """
        Check if URL is a subdomain of the base domain
        
        Args:
            url: URL to check
            
        Returns:
            True if subdomain, False otherwise
        """
        try:
            domain = self._extract_domain(url)
            return domain.endswith(f".{self._base_domain}")
        except Exception:
            return False
    
    def _extract_domain(self, url: str) -> str:
        """
        Extract domain from URL
        
        Args:
            url: URL to extract domain from
            
        Returns:
            Domain name
        """
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Handle www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain
    
    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL for consistency
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Remove trailing slash
        if url.endswith('/'):
            url = url[:-1]
        
        return url
    
    def _get_base_url(self, url: str, soup: BeautifulSoup) -> str:
        """
        Get base URL for resolving relative URLs
        
        Args:
            url: Current URL
            soup: BeautifulSoup object
            
        Returns:
            Base URL
        """
        # Check for <base> tag
        base_tag = soup.find('base', href=True)
        if base_tag:
            return base_tag['href']
        
        # Otherwise use the current URL
        parsed_url = urllib.parse.urlparse(url)
        return f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    def _make_absolute_url(self, url: str, base_url: str) -> Optional[str]:
        """
        Convert relative URL to absolute URL
        
        Args:
            url: URL to convert
            base_url: Base URL for resolving
            
        Returns:
            Absolute URL or None if invalid
        """
        try:
            # Skip data: URLs, javascript: URLs, anchors, etc.
            if not url or url.startswith(('data:', 'javascript:', 'mailto:', '#')):
                return None
            
            # Join relative URL with base URL
            absolute_url = urllib.parse.urljoin(base_url, url)
            
            # Validate the URL
            parsed = urllib.parse.urlparse(absolute_url)
            if not parsed.scheme or not parsed.netloc:
                return None
            
            # Only return http/https URLs
            if parsed.scheme not in ('http', 'https'):
                return None
            
            return absolute_url
        
        except Exception:
            return None