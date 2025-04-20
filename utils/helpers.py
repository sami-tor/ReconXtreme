"""
Common utility functions for ReconXtreme
"""
import os
import re
import socket
import ipaddress
import random
import string
import subprocess
import json
import requests
from typing import List, Dict, Any, Optional, Union, Set, Tuple
from urllib.parse import urlparse

def is_valid_domain(domain: str) -> bool:
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

def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address
    
    Args:
        ip: IP address to check
        
    Returns:
        True if the IP is valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_ip_in_cidr(ip: str, cidr: str) -> bool:
    """
    Check if an IP address is within a CIDR range
    
    Args:
        ip: IP address to check
        cidr: CIDR range to check against
        
    Returns:
        True if the IP is in the CIDR range, False otherwise
    """
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
    except ValueError:
        return False

def generate_random_string(length: int = 10) -> str:
    """
    Generate a random string of a given length
    
    Args:
        length: Length of the string to generate
        
    Returns:
        Random string
    """
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def extract_domain_from_url(url: str) -> str:
    """
    Extract domain from URL
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Domain name
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Handle www prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    return domain

def run_command(command: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    """
    Run a command and return its output
    
    Args:
        command: Command to run as a list of arguments
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (return code, stdout, stderr)
    """
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        process.kill()
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)

def is_valid_cidr(cidr: str) -> bool:
    """
    Check if a string is a valid CIDR notation
    
    Args:
        cidr: CIDR to check
        
    Returns:
        True if the CIDR is valid, False otherwise
    """
    try:
        ipaddress.ip_network(cidr)
        return True
    except ValueError:
        return False

def expand_cidr(cidr: str) -> List[str]:
    """
    Expand a CIDR notation to a list of IP addresses
    
    Args:
        cidr: CIDR to expand
        
    Returns:
        List of IP addresses
    """
    try:
        return [str(ip) for ip in ipaddress.ip_network(cidr)]
    except ValueError:
        return []

def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if a port is open on a host
    
    Args:
        host: Host to check
        port: Port to check
        timeout: Timeout in seconds
        
    Returns:
        True if the port is open, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except Exception:
        return False

def download_file(url: str, output_path: str, timeout: int = 30) -> bool:
    """
    Download a file from a URL
    
    Args:
        url: URL to download from
        output_path: Path to save the file to
        timeout: Timeout in seconds
        
    Returns:
        True if the download was successful, False otherwise
    """
    try:
        response = requests.get(url, stream=True, timeout=timeout)
        if response.status_code == 200:
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
        return False
    except Exception:
        return False

def parse_target(target: str) -> Dict[str, Any]:
    """
    Parse a target string into its components
    
    Args:
        target: Target string (domain, IP, CIDR, or URL)
        
    Returns:
        Dictionary with target information
    """
    result = {
        'type': None,
        'value': target,
        'is_domain': False,
        'is_ip': False,
        'is_cidr': False,
        'is_url': False
    }
    
    # Check if target is a URL
    if target.startswith(('http://', 'https://')):
        result['type'] = 'url'
        result['is_url'] = True
        parsed_url = urlparse(target)
        result['domain'] = parsed_url.netloc
        
        # Check if domain is an IP
        if is_valid_ip(parsed_url.netloc):
            result['is_ip'] = True
        else:
            result['is_domain'] = True
        
        return result
    
    # Check if target is a CIDR
    if '/' in target and is_valid_cidr(target):
        result['type'] = 'cidr'
        result['is_cidr'] = True
        return result
    
    # Check if target is an IP
    if is_valid_ip(target):
        result['type'] = 'ip'
        result['is_ip'] = True
        return result
    
    # Check if target is a domain
    if is_valid_domain(target):
        result['type'] = 'domain'
        result['is_domain'] = True
        return result
    
    # Default to unknown
    result['type'] = 'unknown'
    return result

def extract_ips_from_text(text: str) -> List[str]:
    """
    Extract IP addresses from text
    
    Args:
        text: Text to extract IPs from
        
    Returns:
        List of IP addresses
    """
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    return [ip for ip in ips if is_valid_ip(ip)]

def extract_domains_from_text(text: str) -> List[str]:
    """
    Extract domain names from text
    
    Args:
        text: Text to extract domains from
        
    Returns:
        List of domain names
    """
    # This is a simplified pattern, real-world usage may need a more complex pattern
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = re.findall(domain_pattern, text)
    return [domain for domain in domains if is_valid_domain(domain)]