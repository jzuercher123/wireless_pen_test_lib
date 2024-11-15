import importlib
import os
import sys
import logging


class ModuleManager:
    def __init__(self, modules_path, event_dispatcher, core_framework):
        self.modules_path = modules_path
        self.modules = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.event_dispatcher = event_dispatcher
        self.core_framework = core_framework
        self.load_modules()

    def load_modules(self):
        self.logger.info(f"Loading modules from {self.modules_path}")
        sys.path.insert(0, self.modules_path)

        for filename in os.listdir(self.modules_path):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                try:
                    module = importlib.import_module(module_name)
                    for attribute_name in dir(module):
                        attribute = getattr(module, attribute_name)
                        if isinstance(attribute, type):
                            from core.config.protocols.base_protocol import BaseProtocol
                            if issubclass(attribute, BaseProtocol) and attribute != BaseProtocol:
                                instance = attribute(interface='wlan0mon', core=self.core_framework)
                                instance.register(self.event_dispatcher)
                                self.modules[module_name] = instance
                                self.logger.info(f"Loaded and registered protocol module: {module_name}")
                except Exception as e:
                    self.logger.error(f"Failed to load module {module_name}: {e}")

        sys.path.pop(0)

    def get_module(self, module_name):
        return self.modules.get(module_name, None)

    def list_modules(self):
        return list(self.modules.keys())
