#!/usr/bin/env python3
"""
ReconXtreme - Advanced Web Application Security Reconnaissance Tool
"""
import sys
import time
import typer
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint
from typing import List, Optional
import importlib.util

# Add module root to path for imports
sys.path.append('.')

# Import core modules
from core.config import Config
from core.logger import setup_logger
from core.async_engine import AsyncEngine
from modules import module_manager
from modules.subdomain.cloudflare_bypass import CloudflareProtectedError

# Initialize app
app = typer.Typer(
    help="ReconXtreme: Advanced Web Application Security Reconnaissance",
    add_completion=True,
)
console = Console()

# Setup logger
logger = None  # Will be initialized in the callback

@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file"),
):
    """
    ReconXtreme: Advanced Web Application Security Reconnaissance Tool
    
    Designed for legal, authorized security testing only.
    """
    global logger
    
    # Display banner
    banner = """
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗████████╗██████╗ ███████╗███╗   ███╗███████╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝╚══██╔══╝██╔══██╗██╔════╝████╗ ████║██╔════╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝    ██║   ██████╔╝█████╗  ██╔████╔██║█████╗  
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗    ██║   ██╔══██╗██╔══╝  ██║╚██╔╝██║██╔══╝  
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗   ██║   ██║  ██║███████╗██║ ╚═╝ ██║███████╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝
    """
    console.print(Panel.fit(banner, border_style="blue"))
    console.print("[bold red]⚠️  Legal and authorized use only[/bold red]")
    
    # Initialize logger
    logger = setup_logger(verbose)
    
    # Initialize config
    Config.initialize(config_file, verbose)
    
    # Check for required dependencies
    check_dependencies()

def check_dependencies():
    """Check if required external tools are installed."""
    required_packages = ["httpx", "aiohttp", "rich", "typer", "asyncio"]
    missing_packages = []
    
    for package in required_packages:
        if importlib.util.find_spec(package) is None:
            missing_packages.append(package)
    
    if missing_packages:
        console.print(f"[bold red]Missing required packages: {', '.join(missing_packages)}[/bold red]")
        console.print("[yellow]Please install required packages using: pip install -r requirements.txt[/yellow]")
        sys.exit(1)

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain or URL"),
    modules: List[str] = typer.Option(None, "--module", "-m", help="Specific modules to run"),
    output: str = typer.Option("json", "--output", "-o", help="Output format (json, html, pdf)"),
    threads: int = typer.Option(10, "--threads", "-t", help="Number of threads for scanning"),
    timeout: int = typer.Option(30, "--timeout", help="Request timeout in seconds"),
):
    """
    Perform a security reconnaissance scan on the target.
    """
    console.print(f"[bold]Starting scan on target:[/bold] {target}")
    console.print(f"[bold]Modules enabled:[/bold] {'All' if not modules else ', '.join(modules)}")
    console.print(f"[bold]Output format:[/bold] {output}")
    
    # Initialize scan config
    scan_config = {
        'general': {
            'max_threads': threads,
            'timeout': timeout,
            'output_dir': 'results'
        },
        'modules': {
            'port_scanning': {
                'enabled': True,
                'ports': '1-1000',
                'max_concurrent': threads
            },
            'web_crawling': {
                'enabled': True,
                'max_depth': 3,
                'max_urls': 500,
                'max_concurrent': threads,
                'timeout': timeout
            },
            'osint': {
                'enabled': True,
                'max_concurrent': 3,
                'timeout': timeout
            }
        }
    }

    try:
        # Initialize module manager
        module_manager.discover_modules()
        available_modules = module_manager.list_modules()
        
        # Filter modules if specific ones were requested
        if modules:
            scan_modules = [m for m in modules if m in available_modules]
            if not scan_modules:
                console.print("[bold red]Error: No valid modules specified[/bold red]")
                return
        else:
            scan_modules = list(available_modules.keys())
        
        # Initialize async engine
        engine = AsyncEngine(
            max_concurrent_tasks=threads,
            timeout=timeout,
            retry_count=3
        )
        
        # Create results directory
        from pathlib import Path
        results_dir = Path('results')
        results_dir.mkdir(exist_ok=True)
        
        # Run each module
        import asyncio
        results = {}
        
        async def run_scans():
            for module_id in scan_modules:
                try:
                    # Load and run module
                    module = module_manager.load_module(module_id, scan_config)
                    console.print(f"[green]Running module:[/green] {module.name}")
                    
                    try:
                        module_result = await module_manager.run_module(module_id, target)
                        results[module_id] = module_result
                        console.print(f"[green]✓[/green] Completed {module.name}")
                    except CloudflareProtectedError as cf_error:
                        console.print(f"[yellow]⚠️  {str(cf_error)}[/yellow]")
                        console.print("[yellow]Scanning aborted to respect Cloudflare protection[/yellow]")
                        return  # Exit all scanning
                
                except Exception as e:
                    logger.error(f"Error running module {module_id}: {e}")
                    console.print(f"[red]✗[/red] Error in {module_id}: {e}")
        
        # Run event loop
        loop = asyncio.get_event_loop()
        loop.run_until_complete(run_scans())
        
        # Save results
        if results:
            import json
            output_file = results_dir / f"scan_{target.replace('://', '_')}_{int(time.time())}.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            console.print(f"[bold green]Scan completed! Results saved to:[/bold green] {output_file}")
        else:
            console.print("[bold red]No results were produced by any module[/bold red]")
    
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        console.print(f"[bold red]Error during scan: {e}[/bold red]")

@app.command()
def version():
    """Display ReconXtreme version information."""
    console.print("ReconXtreme v0.1.0")
    console.print("An advanced web application security reconnaissance tool")
    console.print("Copyright 2025. For legal and authorized use only.")

if __name__ == "__main__":
    app()