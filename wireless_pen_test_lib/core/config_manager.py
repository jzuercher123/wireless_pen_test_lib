# wireless_pen_test_lib/core/config_manager.py

"""
ConfigManager Module

This module defines the ConfigManager class, which handles loading and managing
configuration settings for the WirelessPenTestLib application using YAML files
and Pydantic models for validation.
"""

import os
import yaml
import logging
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, ValidationError


# Define configuration models using Pydantic for validation
class GeneralConfig(BaseModel):
    interface: str
    report_directory: str
    log_level: str = Field(default='INFO')  # Added default value


class EncryptionScannerConfig(BaseModel):
    scan_duration: int


class AuthBypassScannerConfig(BaseModel):
    scan_duration: int


class DosScannerConfig(BaseModel):
    scan_duration: int


class LocalScannerConfig(BaseModel):
    scan_duration: int
    interface: str
    vendor_lookup: bool


class ScannersConfig(BaseModel):
    encryption_scanner: EncryptionScannerConfig
    auth_bypass_scanner: AuthBypassScannerConfig
    dos_scanner: DosScannerConfig
    local_scanner: LocalScannerConfig


class SessionHijackingConfig(BaseModel):
    max_packets: int


class CredentialExtractionConfig(BaseModel):
    pass  # No required fields


class PayloadDeliveryConfig(BaseModel):
    payload_types: list
    default_duration: int


class ExploitsConfig(BaseModel):
    session_hijacking: SessionHijackingConfig
    credential_extraction: CredentialExtractionConfig
    payload_delivery: PayloadDeliveryConfig


class UIConfig(BaseModel):
    theme: str = Field(default='light')  # Default theme


class ConfigModel(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    scanners: ScannersConfig
    exploits: ExploitsConfig
    ui: UIConfig = Field(default_factory=UIConfig)


class ConfigManager:
    """
    ConfigManager Class

    Responsible for loading, validating, and providing access to configuration settings.
    It manages default configurations and allows user-specific overrides.
    """

    def __init__(self, config_dir: Optional[str] = None, config_file: str = 'configs.yaml'):
        """
        Initializes the ConfigManager.

        Args:
            config_dir (Optional[str]): Directory where the configuration files are located.
                                        If None, defaults to the 'configs' directory within the project root.
            config_file (str): Name of the user-specific configuration file.
        """
        self.project_root = os.path.abspath(os.path.dirname(__file__))
        self.config_dir = config_dir or os.path.join(self.project_root, 'configs')
        self.default_config_path = os.path.join(self.config_dir, 'default_config.yaml')
        self.user_config_path = os.path.join(self.config_dir, config_file)
        self.config: Optional[ConfigModel] = None

        # Initialize logger
        self.logger = self._setup_logger()

        # Load configurations
        self.load_config()

    def _setup_logger(self) -> logging.Logger:
        """
        Sets up the logger for ConfigManager.

        Returns:
            logging.Logger: Configured logger instance.
        """
        logger = logging.getLogger('ConfigManager')
        logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed trace

        # Create handlers if they haven't been created yet
        if not logger.handlers:
            # Console handler
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)  # Default console log level

            # File handler
            fh = logging.FileHandler(os.path.join(self.config_dir, 'config_manager.log'))
            fh.setLevel(logging.DEBUG)

            # Formatter
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            fh.setFormatter(formatter)

            # Add handlers to logger
            logger.addHandler(ch)
            logger.addHandler(fh)

        return logger

    def create_default_config(self):
        """
        Creates default configuration files if they do not exist.
        """
        if not os.path.exists(self.default_config_path):
            default_config = {
                'general': {
                    'interface': 'wlan0mon',
                    'report_directory': 'reports',
                    'log_level': 'INFO',
                },
                'scanners': {
                    'encryption_scanner': {'scan_duration': 10},
                    'auth_bypass_scanner': {'scan_duration': 15},
                    'dos_scanner': {'scan_duration': 5},
                    'local_scanner': {
                        'scan_duration': 8,
                        'interface': 'wlan0mon',
                        'vendor_lookup': True
                    },
                },
                'exploits': {
                    'session_hijacking': {'max_packets': 100},
                    'credential_extraction': {},
                    'payload_delivery': {
                        'payload_types': ['reverse_shell', 'malicious_script'],
                        'default_duration': 30
                    },
                },
                'ui': {
                    'theme': 'dark'
                }
            }
            os.makedirs(self.config_dir, exist_ok=True)
            try:
                with open(self.default_config_path, 'w') as f:
                    yaml.dump(default_config, f)
                self.logger.info(f"Default configuration created at {self.default_config_path}")
            except IOError as e:
                self.logger.error(f"Failed to create default configuration: {e}")
                raise

    def load_config(self):
        """
        Loads and merges default and user-specific configurations.
        Validates the merged configuration against the Pydantic models.
        """
        try:
            self.create_default_config()

            # Load default configuration
            with open(self.default_config_path, 'r') as f:
                default_config = yaml.safe_load(f)
            self.logger.debug("Default configuration loaded.")

            # Load user configuration if it exists
            if os.path.exists(self.user_config_path):
                with open(self.user_config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                self.logger.debug("User configuration loaded.")
            else:
                user_config = {}
                self.logger.info("User configuration file not found. Using default configurations.")

            # Merge configurations: user_config overrides default_config
            merged_config = self._merge_configs(default_config, user_config)
            self.logger.debug("Configurations merged successfully.")

            # Validate and parse the merged configuration using Pydantic
            self.config = ConfigModel(**merged_config)
            self.logger.info("Configuration validated and loaded successfully.")

        except (yaml.YAMLError, ValidationError) as e:
            self.logger.error(f"Error loading configuration: {e}")
            raise e
        except Exception as e:
            self.logger.error(f"Unexpected error during configuration loading: {e}")
            raise e

    @staticmethod
    def _merge_configs(default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merges two dictionaries. Values from 'override' take precedence.

        Args:
            default (Dict[str, Any]): The default configuration dictionary.
            override (Dict[str, Any]): The overriding configuration dictionary.

        Returns:
            Dict[str, Any]: The merged configuration dictionary.
        """
        for key, value in override.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                default[key] = ConfigManager._merge_configs(default[key], value)
            else:
                default[key] = value
        return default

    def get_config(self) -> ConfigModel:
        """
        Retrieves the loaded configuration.

        Returns:
            ConfigModel: The validated configuration model.
        """
        if not self.config:
            self.logger.error("Configuration has not been loaded.")
            raise ValueError("Configuration has not been loaded.")
        return self.config

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieves a specific configuration value using dot notation.

        Args:
            key (str): Configuration key in dot notation (e.g., 'general.interface').
            default (Any, optional): Default value if key is not found. Defaults to None.

        Returns:
            Any: The configuration value or default.
        """
        keys = key.split('.')
        value = self.config
        try:
            for k in keys:
                value = getattr(value, k)
            return value
        except AttributeError:
            self.logger.warning(f"Configuration key '{key}' not found. Returning default value.")
            return default

    def reload_config(self):
        """
        Reloads the configuration from the YAML files.

        Useful for applying configuration changes without restarting the application.
        """
        self.logger.info("Reloading configuration...")
        self.load_config()
        self.logger.info("Configuration reloaded successfully.")


if __name__ == "__main__":
    # Example usage
    try:
        config_manager = ConfigManager()
        config = config_manager.get_config()
        print("Configuration Loaded Successfully:")
        print(config.json(indent=4))
    except Exception as e:
        print(f"Failed to load configuration: {e}")
