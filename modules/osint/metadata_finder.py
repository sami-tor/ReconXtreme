"""
Metadata finder module for ReconXtreme

This module extracts metadata from various file types found on target websites,
including PDF, Office documents, images, and more.
"""
import asyncio
import aiohttp
import tempfile
import os
import re
import time
import random
from typing import Dict, Any, List, Set, Optional, Tuple
import io

from core.logger import get_module_logger
from modules import ModuleBase

logger = get_module_logger("osint.metadata_finder")

class MetadataFinderModule(ModuleBase):
    """
    Metadata finder module for extracting information from documents
    
    Searches for and downloads files from target websites, then extracts
    metadata such as:
    - Author names
    - Creation dates
    - Software versions
    - GPS coordinates (from images)
    - Comments and hidden text
    """
    
    name = "metadata_finder"
    description = "Metadata extraction from files and documents"
    author = "ReconXtreme Team"
    version = "0.1.0"
    
    # File extensions to search for
    FILE_EXTENSIONS = [
        # Documents
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp',
        # Images
        'jpg', 'jpeg', 'png', 'gif', 'tiff', 'bmp',
        # Archives
        'zip', 'rar', '7z', 'tar', 'gz',
        # Others
        'xml', 'svg'
    ]
    
    # User agents for requests
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
    ]
    
    # Tool dependencies
    REQUIRED_TOOLS = {
        'exiftool': 'for extracting metadata from various file types',
        'pdfinfo': 'for extracting PDF metadata',
        'strings': 'for extracting text from binary files'
    }
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = self.config.get('timeout', 10)
        self.max_concurrent = self.config.get('max_concurrent', 5)
        self.max_files = self.config.get('max_files', 50)
        self.max_file_size = self.config.get('max_file_size', 10 * 1024 * 1024)  # 10MB
        self.extensions = self.config.get('extensions', self.FILE_EXTENSIONS)
        self.temp_dir = self.config.get('temp_dir', tempfile.gettempdir())
        
        # Results will store discovered files and their metadata
        self.results = {
            'files': [],
            'authors': set(),
            'emails': set(),
            'usernames': set(),
            'software': set(),
            'locations': [],
            'interesting_findings': [],
            'summary': {
                'total_files': 0,
                'files_with_metadata': 0,
                'unique_authors': 0,
                'unique_emails': 0,
                'unique_software': 0
            }
        }
        
        # Check for required tools
        self._check_requirements()
    
    async def run(self, target, *args, **kwargs):
        """
        Run metadata finder on the target website
        
        Args:
            target (str): The target domain or URL
            
        Returns:
            Dict containing discovered files and metadata
        """
        logger.info(f"Starting metadata finder for {target}")
        
        # Create a semaphore to limit concurrent tasks
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Ensure the target is a URL with scheme
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Find files to download
        file_urls = await self._discover_files(target, semaphore)
        
        logger.info(f"Found {len(file_urls)} files for metadata extraction")
        
        # Limit the number of files to download
        if len(file_urls) > self.max_files:
            logger.info(f"Limiting to {self.max_files} files for processing")
            file_urls = file_urls[:self.max_files]
        
        # Download and process files
        tasks = []
        for url in file_urls:
            tasks.append(self._download_and_extract_metadata(url, semaphore))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect unique values
        unique_authors = self.results['authors']
        unique_emails = self.results['emails']
        unique_software = self.results['software']
        
        # Update summary statistics
        self.results['summary']['total_files'] = len(file_urls)
        self.results['summary']['files_with_metadata'] = len(self.results['files'])
        self.results['summary']['unique_authors'] = len(unique_authors)
        self.results['summary']['unique_emails'] = len(unique_emails)
        self.results['summary']['unique_software'] = len(unique_software)
        
        # Convert sets to lists for JSON serialization
        self.results['authors'] = list(unique_authors)
        self.results['emails'] = list(unique_emails)
        self.results['software'] = list(unique_software)
        
        logger.info(f"Metadata finder completed for {target}. Processed {len(self.results['files'])} files.")
        
        return self.results
    
    async def _discover_files(self, target: str, semaphore: asyncio.Semaphore) -> List[str]:
        """
        Discover files on the target website
        
        Args:
            target: Target domain or URL
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            List of file URLs
        """
        async with semaphore:
            logger.debug(f"Discovering files on {target}")
            
            # This would typically use the web crawling module to find files
            # For this example, we'll use a simplified approach with Google dorks
            
            discovered_urls = set()
            
            # Create a session for requests
            async with aiohttp.ClientSession() as session:
                for ext in self.extensions:
                    try:
                        # Avoid rate limiting
                        await asyncio.sleep(random.uniform(2, 5))
                        
                        # Google dork query
                        dork = f"site:{target.replace('https://', '').replace('http://', '')} filetype:{ext}"
                        encoded_dork = dork.replace(' ', '+')
                        url = f"https://www.google.com/search?q={encoded_dork}&num=100"
                        
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
                                
                                # Extract file URLs
                                file_urls = self._extract_file_urls(html, ext, target)
                                discovered_urls.update(file_urls)
                            
                            elif response.status == 429:
                                logger.warning("Google rate limit hit, waiting longer before next request")
                                await asyncio.sleep(60)
                    
                    except Exception as e:
                        logger.debug(f"Error searching for {ext} files: {e}")
            
            return list(discovered_urls)
    
    def _extract_file_urls(self, html: str, extension: str, base_url: str) -> Set[str]:
        """
        Extract file URLs from HTML
        
        Args:
            html: HTML content
            extension: File extension to look for
            base_url: Base URL for relative paths
            
        Returns:
            Set of file URLs
        """
        file_urls = set()
        
        # Extract links from Google search results
        pattern = r'href="(https?://[^"]+\.' + re.escape(extension) + r')"'
        matches = re.findall(pattern, html)
        
        for url in matches:
            # Exclude Google's own URLs
            if 'google.com' not in url:
                file_urls.add(url)
        
        return file_urls
    
    async def _download_and_extract_metadata(self, url: str, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        """
        Download a file and extract its metadata
        
        Args:
            url: URL of the file to download
            semaphore: Semaphore for limiting concurrent tasks
            
        Returns:
            Dictionary with extracted metadata
        """
        async with semaphore:
            try:
                logger.debug(f"Downloading and processing {url}")
                
                # Create a temporary file
                with tempfile.NamedTemporaryFile(delete=False, dir=self.temp_dir) as temp_file:
                    temp_path = temp_file.name
                
                try:
                    # Download the file
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, timeout=self.timeout) as response:
                            if response.status != 200:
                                logger.debug(f"Failed to download {url}: HTTP {response.status}")
                                os.unlink(temp_path)
                                return None
                            
                            # Check content length
                            content_length = int(response.headers.get('Content-Length', 0))
                            if content_length > self.max_file_size:
                                logger.debug(f"Skipping {url}: file too large ({content_length} bytes)")
                                os.unlink(temp_path)
                                return None
                            
                            # Read the file data with a size limit
                            with open(temp_path, 'wb') as f:
                                chunk_size = 8192
                                total_size = 0
                                
                                async for chunk in response.content.iter_chunked(chunk_size):
                                    total_size += len(chunk)
                                    
                                    if total_size > self.max_file_size:
                                        logger.debug(f"Skipping {url}: file too large (streaming)")
                                        os.unlink(temp_path)
                                        return None
                                    
                                    f.write(chunk)
                    
                    # Extract metadata based on file type
                    extension = url.split('.')[-1].lower()
                    
                    if extension in ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']:
                        metadata = await self._extract_document_metadata(temp_path, extension)
                    elif extension in ['jpg', 'jpeg', 'png', 'tiff']:
                        metadata = await self._extract_image_metadata(temp_path)
                    else:
                        metadata = await self._extract_generic_metadata(temp_path)
                    
                    # Add URL and file type
                    metadata['url'] = url
                    metadata['file_type'] = extension
                    
                    # Update collected data
                    if 'author' in metadata and metadata['author']:
                        self.results['authors'].add(metadata['author'])
                    
                    if 'emails' in metadata:
                        self.results['emails'].update(metadata['emails'])
                    
                    if 'software' in metadata and metadata['software']:
                        self.results['software'].add(metadata['software'])
                    
                    if 'gps_coordinates' in metadata and metadata['gps_coordinates']:
                        self.results['locations'].append({
                            'url': url,
                            'coordinates': metadata['gps_coordinates']
                        })
                    
                    if 'interesting' in metadata and metadata['interesting']:
                        self.results['interesting_findings'].append({
                            'url': url,
                            'finding': metadata['interesting']
                        })
                    
                    # Add to results
                    self.results['files'].append(metadata)
                    
                    return metadata
                
                finally:
                    # Always clean up the temporary file
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
            
            except Exception as e:
                logger.debug(f"Error processing {url}: {e}")
                return None
    
    async def _extract_document_metadata(self, file_path: str, extension: str) -> Dict[str, Any]:
        """
        Extract metadata from document files (PDF, Office)
        
        Args:
            file_path: Path to the document file
            extension: File extension
            
        Returns:
            Dictionary with extracted metadata
        """
        metadata = {
            'author': None,
            'creation_date': None,
            'modification_date': None,
            'software': None,
            'emails': set(),
            'interesting': None
        }
        
        # Extract metadata using exiftool
        try:
            if extension == 'pdf':
                # For PDF files, use pdfinfo if available
                result = await self._run_command(['pdfinfo', file_path])
                
                if result:
                    # Parse pdfinfo output
                    lines = result.strip().split('\n')
                    
                    for line in lines:
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            
                            if key == 'Author':
                                metadata['author'] = value.strip()
                            elif key == 'Creator':
                                metadata['software'] = value.strip()
                            elif key == 'CreationDate':
                                metadata['creation_date'] = value.strip()
                            elif key == 'ModDate':
                                metadata['modification_date'] = value.strip()
            
            # Use exiftool for all document types
            result = await self._run_command(['exiftool', file_path])
            
            if result:
                # Parse exiftool output
                lines = result.strip().split('\n')
                
                for line in lines:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if key in ['Author', 'Creator', 'Last Author']:
                            if not metadata['author']:
                                metadata['author'] = value
                        elif key in ['Create Date', 'Creation Date']:
                            if not metadata['creation_date']:
                                metadata['creation_date'] = value
                        elif key in ['Modify Date', 'Last Modified']:
                            if not metadata['modification_date']:
                                metadata['modification_date'] = value
                        elif key in ['Producer', 'Application', 'Software']:
                            if not metadata['software']:
                                metadata['software'] = value
            
            # Extract text for email addresses and other interesting information
            if extension == 'pdf':
                text_result = await self._run_command(['pdftotext', file_path, '-'])
            else:
                # For non-PDF documents, try to extract text with strings
                text_result = await self._run_command(['strings', file_path])
            
            if text_result:
                # Find emails
                emails = self._extract_emails_from_text(text_result)
                if emails:
                    metadata['emails'].update(emails)
                
                # Look for interesting patterns
                interesting = self._find_interesting_patterns(text_result)
                if interesting:
                    metadata['interesting'] = interesting
        
        except Exception as e:
            logger.debug(f"Error extracting document metadata: {e}")
        
        return metadata
    
    async def _extract_image_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Extract metadata from image files
        
        Args:
            file_path: Path to the image file
            
        Returns:
            Dictionary with extracted metadata
        """
        metadata = {
            'author': None,
            'creation_date': None,
            'software': None,
            'gps_coordinates': None,
            'camera': None,
            'interesting': None
        }
        
        try:
            # Use exiftool for image metadata
            result = await self._run_command(['exiftool', file_path])
            
            if result:
                # Parse exiftool output
                lines = result.strip().split('\n')
                
                for line in lines:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if key in ['Artist', 'Author', 'Creator']:
                            metadata['author'] = value
                        elif key in ['Create Date', 'Date/Time Original']:
                            metadata['creation_date'] = value
                        elif key in ['Software', 'Processing Software']:
                            metadata['software'] = value
                        elif key == 'Camera Model Name':
                            metadata['camera'] = value
                        elif key in ['GPS Position', 'GPS Coordinates']:
                            metadata['gps_coordinates'] = value
                
                # Check for interesting EXIF tags
                if any(key in result for key in ['GPS', 'Location']):
                    metadata['interesting'] = "Contains GPS/location information"
        
        except Exception as e:
            logger.debug(f"Error extracting image metadata: {e}")
        
        return metadata
    
    async def _extract_generic_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Extract metadata from other file types
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with extracted metadata
        """
        metadata = {
            'author': None,
            'creation_date': None,
            'modification_date': None,
            'software': None,
            'emails': set(),
            'interesting': None
        }
        
        try:
            # Use exiftool for generic metadata
            result = await self._run_command(['exiftool', file_path])
            
            if result:
                # Parse exiftool output
                lines = result.strip().split('\n')
                
                for line in lines:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if key in ['Author', 'Creator']:
                            metadata['author'] = value
                        elif key in ['Create Date', 'Creation Date']:
                            metadata['creation_date'] = value
                        elif key in ['Modify Date', 'Last Modified']:
                            metadata['modification_date'] = value
                        elif key in ['Software', 'Producer', 'Application']:
                            metadata['software'] = value
            
            # Extract text with strings command
            text_result = await self._run_command(['strings', file_path])
            
            if text_result:
                # Find emails
                emails = self._extract_emails_from_text(text_result)
                if emails:
                    metadata['emails'].update(emails)
                
                # Look for interesting patterns
                interesting = self._find_interesting_patterns(text_result)
                if interesting:
                    metadata['interesting'] = interesting
        
        except Exception as e:
            logger.debug(f"Error extracting generic metadata: {e}")
        
        return metadata
    
    def _extract_emails_from_text(self, text: str) -> Set[str]:
        """
        Extract email addresses from text
        
        Args:
            text: Text to extract emails from
            
        Returns:
            Set of email addresses
        """
        # Find all email addresses
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        all_emails = re.findall(email_pattern, text)
        
        # Return unique emails
        return {email.lower() for email in all_emails}
    
    def _find_interesting_patterns(self, text: str) -> Optional[str]:
        """
        Look for interesting patterns in text
        
        Args:
            text: Text to analyze
            
        Returns:
            Description of interesting pattern if found, None otherwise
        """
        # Keywords that might indicate sensitive information
        sensitive_keywords = [
            # Credentials
            'password', 'passwd', 'pass', 'pwd', 'username', 'user', 'login',
            'credential', 'auth', 'key', 'secret', 'token', 'api_key', 'apikey',
            
            # Sensitive terms
            'confidential', 'classified', 'private', 'internal', 'restricted',
            'draft', 'sensitive', 'not for distribution', 'do not distribute',
            
            # Database
            'database', 'db', 'sql', 'query', 'select', 'insert', 'update',
            'delete', 'where', 'join', 'from', 'table',
            
            # Server/infrastructure
            'server', 'host', 'ip', 'domain', 'dns', 'vpn', 'ssh', 'ftp',
            'administrator', 'admin', 'root', 'config', 'configuration'
        ]
        
        # Check for sensitive keywords
        for keyword in sensitive_keywords:
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text.lower()):
                return f"Contains potentially sensitive information (keyword: {keyword})"
        
        # Check for potential API keys, tokens
        api_key_pattern = r'[a-zA-Z0-9]{32,}'
        api_keys = re.findall(api_key_pattern, text)
        if api_keys:
            return "Contains potential API keys or tokens"
        
        # Check for AWS keys
        aws_key_pattern = r'AKIA[0-9A-Z]{16}'
        aws_keys = re.findall(aws_key_pattern, text)
        if aws_keys:
            return "Contains potential AWS keys"
        
        # Check for IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        if len(ips) > 5:  # If there are multiple IPs, it might be interesting
            return f"Contains multiple IP addresses ({len(ips)})"
        
        return None
    
    async def _run_command(self, command: List[str]) -> Optional[str]:
        """
        Run a shell command asynchronously
        
        Args:
            command: Command to run as a list of arguments
            
        Returns:
            Command output or None if error
        """
        try:
            # Create a subprocess
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for the command to complete with timeout
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            
            # Check if the command was successful
            if proc.returncode == 0:
                return stdout.decode('utf-8', errors='ignore')
            else:
                logger.debug(f"Command failed: {command} - {stderr.decode('utf-8', errors='ignore')}")
                return None
        
        except asyncio.TimeoutError:
            logger.debug(f"Command timeout: {command}")
            return None
        
        except Exception as e:
            logger.debug(f"Error running command {command}: {e}")
            return None
    
    def _check_requirements(self):
        """Check if required tools are installed"""
        missing_tools = []
        
        for tool, description in self.REQUIRED_TOOLS.items():
            try:
                # Use 'where' command on Windows, 'which' on Unix
                if os.name == 'nt':
                    cmd = f"where {tool}"
                else:
                    cmd = f"which {tool}"
                
                # Run the command
                subprocess.run(
                    cmd, 
                    shell=True, 
                    check=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE
                )
            
            except subprocess.CalledProcessError:
                missing_tools.append(f"{tool} ({description})")
        
        if missing_tools:
            logger.warning(f"Missing tools for optimal metadata extraction: {', '.join(missing_tools)}")
            logger.warning("Some features may not work properly. Install missing tools for full functionality.")