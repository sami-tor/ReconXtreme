"""
ReconXtreme modules package

This package contains all the scanning and reconnaissance modules.
"""

from pathlib import Path
import importlib
import inspect
import pkgutil
import sys
import logging

from core.logger import get_module_logger

logger = get_module_logger("modules")

class ModuleBase:
    """Base class for all ReconXtreme modules"""
    
    # Module metadata
    name = "base"
    description = "Base module class"
    author = "ReconXtreme Team"
    version = "0.1.0"
    
    # Module configuration
    enabled = True
    requires = []  # Dependencies on other modules
    
    def __init__(self, config=None):
        self.config = config or {}
        self.results = {}
    
    async def run(self, target, *args, **kwargs):
        """
        Run the module against the target
        
        Args:
            target: The target to scan
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
            
        Returns:
            Dict containing the results
        """
        raise NotImplementedError("Modules must implement the run method")
    
    def get_results(self):
        """Return the module results"""
        return self.results

class ModuleManager:
    """Module manager for loading and running modules"""
    
    def __init__(self):
        self.modules: Dict[str, Type[ModuleBase]] = {}
        self.loaded_modules: Dict[str, ModuleBase] = {}
    
    def discover_modules(self):
        """Discover and load all available modules"""
        modules_path = Path(__file__).parent
        logger.info(f"Discovering modules in {modules_path}")
        
        # Walk through all packages in the modules directory
        for _, name, is_pkg in pkgutil.iter_modules([str(modules_path)]):
            if is_pkg:  # Only process packages, not individual modules
                try:
                    # Import the package directly
                    package = importlib.import_module(f"modules.{name}")
                    
                    # Look for module implementation files within the package
                    for _, module_name, _ in pkgutil.iter_modules([str(modules_path / name)]):
                        try:
                            # Import the module directly
                            module = importlib.import_module(f"modules.{name}.{module_name}")
                            
                            # Find all ModuleBase subclasses in the module
                            for item_name, item in inspect.getmembers(module, inspect.isclass):
                                if (issubclass(item, ModuleBase) and 
                                    item is not ModuleBase):
                                    # Register the module
                                    module_id = f"{name}.{module_name}"
                                    self.modules[module_id] = item
                                    logger.debug(f"Discovered module: {module_id} - {item.description}")
                        
                        except Exception as e:
                            logger.error(f"Error loading module {name}.{module_name}: {e}")
                
                except Exception as e:
                    logger.error(f"Error loading module package {name}: {e}")
        
        logger.info(f"Discovered {len(self.modules)} modules")
        return self.modules
    
    def get_module(self, module_id):
        """Get a module by ID"""
        return self.modules.get(module_id)
    
    def list_modules(self):
        """List all available modules"""
        return {module_id: {
            "name": module.name,
            "description": module.description,
            "author": module.author,
            "version": module.version,
            "enabled": module.enabled
        } for module_id, module in self.modules.items()}
    
    def load_module(self, module_id, config=None):
        """Load and initialize a module"""
        if module_id not in self.modules:
            raise ValueError(f"Module {module_id} not found")
        
        # Initialize the module
        module_class = self.modules[module_id]
        module_instance = module_class(config)
        self.loaded_modules[module_id] = module_instance
        
        logger.debug(f"Loaded module: {module_id}")
        return module_instance
    
    async def run_module(self, module_id, target, *args, **kwargs):
        """Run a specific module"""
        if module_id not in self.loaded_modules:
            self.load_module(module_id)
        
        module = self.loaded_modules[module_id]
        logger.info(f"Running module: {module_id} against {target}")
        
        try:
            results = await module.run(target, *args, **kwargs)
            return results
        except Exception as e:
            logger.error(f"Error running module {module_id}: {e}")
            raise

# Create a singleton module manager instance
module_manager = ModuleManager()