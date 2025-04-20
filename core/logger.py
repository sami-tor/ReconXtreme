"""
Logging module for ReconXtreme
"""
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

def setup_logger(verbose: bool = False) -> logging.Logger:
    """
    Setup and configure the logger for ReconXtreme
    
    Args:
        verbose (bool): Whether to enable verbose logging
        
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Generate log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"recon_xtreme_{timestamp}.log"
    
    # Setup logging configuration
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create logger
    logger = logging.getLogger("recon_xtreme")
    logger.setLevel(log_level)
    
    # Clear any existing handlers
    if logger.handlers:
        logger.handlers.clear()
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add formatter to handlers
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"Logging initialized. Log file: {log_file}")
    if verbose:
        logger.debug("Verbose logging enabled")
    
    return logger

def get_module_logger(module_name: str) -> logging.Logger:
    """
    Get a module-specific logger
    
    Args:
        module_name (str): Name of the module requesting the logger
        
    Returns:
        logging.Logger: Module-specific logger
    """
    logger = logging.getLogger(f"recon_xtreme.{module_name}")
    return logger