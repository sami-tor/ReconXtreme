"""
Configuration management for ReconXtreme
"""
import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

class Config:
    """Configuration manager for ReconXtreme"""
    
    _instance = None
    _config_data = {}
    _config_file = None
    _verbose = False
    
    @classmethod
    def initialize(cls, config_file: Optional[str] = None, verbose: bool = False):
        """Initialize the configuration"""
        cls._verbose = verbose
        cls._config_file = config_file
        
        # Load default configuration
        cls._load_default_config()
        
        # If config file is provided, load it
        if config_file and os.path.exists(config_file):
            cls._load_config_file(config_file)
    
    @classmethod
    def _load_default_config(cls):
        """Load default configuration values"""
        cls._config_data = {
            "general": {
                "max_threads": 10,
                "timeout": 30,
                "user_agent": "ReconXtreme/0.1.0 (https://github.com/recon-xtreme/recon-xtreme)",
                "output_dir": os.path.join(os.getcwd(), "results"),
                "debug": False
            },
            "modules": {
                "subdomain_enumeration": {
                    "enabled": True,
                    "bruteforce": True,
                    "wordlist": "default"
                },
                "port_scanning": {
                    "enabled": True,
                    "ports": "1-1000",
                    "scan_type": "fast"
                },
                "web_crawling": {
                    "enabled": True,
                    "max_depth": 3,
                    "max_urls": 500,
                    "respect_robots": True
                },
                "screenshot": {
                    "enabled": True,
                    "timeout": 10
                },
                "vulnerability_scanning": {
                    "enabled": True,
                    "risk_level": "medium"
                }
            },
            "api_keys": {
                "shodan": "",
                "censys": "",
                "securitytrails": "",
                "virustotal": ""
            },
            "notifications": {
                "slack": {
                    "enabled": False,
                    "webhook_url": ""
                },
                "discord": {
                    "enabled": False,
                    "webhook_url": ""
                },
                "telegram": {
                    "enabled": False,
                    "bot_token": "",
                    "chat_id": ""
                }
            }
        }
    
    @classmethod
    def _load_config_file(cls, config_file: str):
        """Load configuration from file"""
        try:
            ext = os.path.splitext(config_file)[1].lower()
            
            if ext in ('.yaml', '.yml'):
                with open(config_file, 'r') as f:
                    custom_config = yaml.safe_load(f)
            elif ext == '.json':
                with open(config_file, 'r') as f:
                    custom_config = json.load(f)
            else:
                raise ValueError(f"Unsupported config file format: {ext}")
            
            # Merge the loaded config with the default config
            cls._merge_configs(custom_config)
            
        except Exception as e:
            if cls._verbose:
                print(f"Error loading config file: {e}")
    
    @classmethod
    def _merge_configs(cls, custom_config: Dict[str, Any]):
        """Recursively merge custom config with default config"""
        for key, value in custom_config.items():
            if (key in cls._config_data and isinstance(cls._config_data[key], dict) 
                    and isinstance(value, dict)):
                cls._merge_configs(value)
            else:
                cls._config_data[key] = value
    
    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        keys = key.split('.')
        config = cls._config_data
        
        for k in keys:
            if isinstance(config, dict) and k in config:
                config = config[k]
            else:
                return default
        
        return config
    
    @classmethod
    def set(cls, key: str, value: Any):
        """Set a configuration value"""
        keys = key.split('.')
        config = cls._config_data
        
        # Navigate to the correct level
        for i, k in enumerate(keys[:-1]):
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
    
    @classmethod
    def save(cls, output_file: Optional[str] = None):
        """Save the current configuration to a file"""
        file_path = output_file or cls._config_file
        
        if not file_path:
            file_path = os.path.join(os.getcwd(), 'config.yaml')
        
        try:
            ext = os.path.splitext(file_path)[1].lower()
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            if ext in ('.yaml', '.yml'):
                with open(file_path, 'w') as f:
                    yaml.dump(cls._config_data, f, default_flow_style=False)
            elif ext == '.json':
                with open(file_path, 'w') as f:
                    json.dump(cls._config_data, f, indent=4)
            else:
                raise ValueError(f"Unsupported config file format: {ext}")
            
            return True
        
        except Exception as e:
            if cls._verbose:
                print(f"Error saving config file: {e}")
            return False