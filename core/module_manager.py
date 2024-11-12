import importlib
import os
import sys
import logging
from .event_dispatcher import EventDispatcher

class ModuleManager:
    def __init__(self, modules_path, event_dispatcher, core_framework):
        """
        Initializes the ModuleManager with the path to the modules directory.

        :param modules_path: Path to the protocol modules.
        :param event_dispatcher: Instance of EventDispatcher.
        :param core_framework: Instance of CoreFramework.
        """
        self.modules_path = modules_path
        self.modules = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.event_dispatcher = event_dispatcher
        self.core_framework = core_framework
        self.load_modules()

    def load_modules(self):
        """
        Dynamically loads all modules from the specified directory.
        """
        self.logger.info(f"Loading modules from {self.modules_path}")
        sys.path.insert(0, self.modules_path)  # Add modules_path to sys.path

        for filename in os.listdir(self.modules_path):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                try:
                    module = importlib.import_module(module_name)
                    # Check if module has a class inheriting from BaseProtocol
                    for attribute_name in dir(module):
                        attribute = getattr(module, attribute_name)
                        if isinstance(attribute, type):
                            from protocols.base_protocol import BaseProtocol
                            if issubclass(attribute, BaseProtocol) and attribute != BaseProtocol:
                                instance = attribute(interface='wlan0mon', core=self.core_framework)
                                instance.register(self.event_dispatcher)
                                self.modules[module_name] = instance
                                self.logger.info(f"Loaded and registered protocol module: {module_name}")
                except Exception as e:
                    self.logger.error(f"Failed to load module {module_name}: {e}")

        sys.path.pop(0)  # Remove modules_path from sys.path

    def get_module(self, module_name):
        """
        Retrieves a loaded module by name.
        """
        return self.modules.get(module_name, None)

    def list_modules(self):
        """
        Returns a list of all loaded modules.
        """
        return list(self.modules.keys())
