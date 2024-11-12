import os
import yaml
from pydantic import BaseModel, Field, ValidationError
from typing import List, Optional, Dict
import logging
from dotenv import load_dotenv


# Define Pydantic models for configuration sections

class GeneralConfig(BaseModel):
    interface: str = Field(default="wlan0mon", description="Wireless interface in monitor mode.")
    log_level: str = Field(default="INFO", description="Logging level.")
    report_directory: str = Field(default="reports", description="Directory to store reports.")

class EncryptionScannerConfig(BaseModel):
    scan_duration: int = Field(default=15, description="Duration to run the encryption scan (seconds).")

class AuthBypassScannerConfig(BaseModel):
    scan_duration: int = Field(default=10, description="Duration to run the authentication bypass scan (seconds).")

class DoSScannerConfig(BaseModel):
    scan_duration: int = Field(default=10, description="Duration to run the DoS scan (seconds).")

class ScannersConfig(BaseModel):
    encryption_scanner: EncryptionScannerConfig
    auth_bypass_scanner: AuthBypassScannerConfig
    dos_scanner: DoSScannerConfig

class SessionHijackingConfig(BaseModel):
    max_packets: int = Field(default=100, description="Maximum number of packets to send during ARP spoofing.")

class CredentialExtractionConfig(BaseModel):
    capture_duration: int = Field(default=20, description="Duration to capture handshakes (seconds).")

class PayloadDeliveryConfig(BaseModel):
    payload_types: List[str] = Field(default_factory=lambda: ["reverse_shell", "malicious_script"], description="Supported payload types.")
    default_duration: int = Field(default=10, description="Default duration to run payload delivery (seconds).")

class ExploitsConfig(BaseModel):
    session_hijacking: SessionHijackingConfig
    credential_extraction: CredentialExtractionConfig
    payload_delivery: PayloadDeliveryConfig

class UIConfig(BaseModel):
    theme: str = Field(default="default", description="Theme for GUI.")

class Config(BaseModel):
    general: GeneralConfig
    scanners: ScannersConfig
    exploits: ExploitsConfig
    ui: UIConfig


class ConfigManager:
    def __init__(self, config_dir: str = "config"):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config_dir = config_dir
        self.default_config_path = os.path.join(self.config_dir, "config_defaults.yaml")
        self.user_config_path = os.path.join(self.config_dir, "config.yaml")

        # Load environment variables from .env file if it exists
        dotenv_path = os.path.join(os.getcwd(), '.env')
        if os.path.exists(dotenv_path):
            load_dotenv(dotenv_path)
            self.logger.debug("Loaded environment variables from .env file.")

        self.config: Optional[Config] = None
        self.load_config()

    # ... rest of the ConfigManager class remains unchanged ...

    def load_yaml(self, path: str) -> Dict:
        if not os.path.exists(path):
            self.logger.warning(f"Configuration file {path} does not exist.")
            return {}
        with open(path, 'r') as f:
            try:
                data = yaml.safe_load(f) or {}
                self.logger.debug(f"Loaded configuration from {path}")
                return data
            except yaml.YAMLError as e:
                self.logger.error(f"Error parsing YAML file {path}: {e}")
                return {}

    def merge_configs(self, default: Dict, override: Dict) -> Dict:
        """
        Recursively merge two dictionaries.
        """
        for key, value in override.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                default[key] = self.merge_configs(default[key], value)
            else:
                default[key] = value
        return default

    def load_config(self):
        """
        Load and validate configuration from YAML files and environment variables.
        """
        # Load default and user configurations
        default_config = self.load_yaml(self.default_config_path)
        user_config = self.load_yaml(self.user_config_path)
        merged_config = self.merge_configs(default_config, user_config)

        # Override with environment variables if set
        merged_config = self.override_with_env(merged_config)

        # Validate the merged configuration
        try:
            self.config = Config(**merged_config)
            self.logger.info("Configuration loaded and validated successfully.")
        except ValidationError as e:
            self.logger.error(f"Configuration validation error: {e}")
            raise e

    def override_with_env(self, config: Dict) -> Dict:
        """
        Override configuration with environment variables if they exist.
        The environment variables should be in uppercase and use underscores to separate sections.
        Example: GENERAL_INTERFACE, SCANNERS_ENCRYPTION_SCANNER_SCAN_DURATION
        """
        for section in config:
            for key in config[section]:
                env_var = f"{section.upper()}_{key.upper()}"
                if isinstance(config[section][key], dict):
                    for sub_key in config[section][key]:
                        sub_env_var = f"{env_var}_{sub_key.upper()}"
                        if sub_env_var in os.environ:
                            config[section][key][sub_key] = self.parse_env_value(os.environ[sub_env_var])
                else:
                    if env_var in os.environ:
                        config[section][key] = self.parse_env_value(os.environ[env_var])
        return config

    def parse_env_value(self, value: str):
        """
        Parse environment variable string to appropriate type.
        """
        # Attempt to parse integers
        if value.isdigit():
            return int(value)
        # Attempt to parse booleans
        if value.lower() in ['true', 'false']:
            return value.lower() == 'true'
        # Return as string
        return value

    def get_config(self) -> Config:
        if not self.config:
            self.logger.error("Configuration not loaded.")
            raise Exception("Configuration not loaded.")
        return self.config

    def update_user_config(self, updates: Dict):
        """
        Update the user configuration file with the provided updates.
        """
        user_config = self.load_yaml(self.user_config_path)
        merged_config = self.merge_configs(user_config, updates)
        with open(self.user_config_path, 'w') as f:
            yaml.dump(merged_config, f)
        self.logger.info(f"User configuration updated: {updates}")
        self.load_config()
