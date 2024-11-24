import os
import yaml
import logging
from pydantic import BaseModel, Field, ValidationError

# Define configuration models
class GeneralConfig(BaseModel):
    interface: str
    report_directory: str
    log_level: str = 'INFO'  # Added missing field with default value

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
    theme: str = 'light'  # Default theme

class ConfigModel(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    scanners: ScannersConfig
    exploits: ExploitsConfig
    ui: UIConfig = Field(default_factory=UIConfig)

class ConfigManager:
    """
    A class to manage application configuration.
    """
    def __init__(self, config_dir: str = None):
        self.project_root = os.path.abspath(os.path.dirname(__file__))
        self.config_dir = config_dir or os.path.join(self.project_root, 'config')
        self.default_config_path = os.path.join(self.config_dir, 'default_config.yaml')
        self.user_config_path = os.path.join(self.config_dir, 'config.yaml')
        self.config = None
        self.logger = logging.getLogger(__name__)
        self.load_config()

    def create_default_config(self):
        # Create default config if it doesn't exist
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
                        'payload_types': ['type1', 'type2'],
                        'default_duration': 30
                    },
                },
                'ui': {
                    'theme': 'dark'
                }
            }
            os.makedirs(self.config_dir, exist_ok=True)
            with open(self.default_config_path, 'w') as f:
                yaml.dump(default_config, f)

    def load_config(self):
        try:
            self.create_default_config()
            with open(self.default_config_path, 'r') as f:
                default_config = yaml.safe_load(f)
            self.logger.debug("Loaded default configuration.")

            if os.path.exists(self.user_config_path):
                with open(self.user_config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                self.logger.debug("Loaded user configuration.")
            else:
                user_config = {}
                self.logger.info("User configuration file not found. Using defaults.")

            # Merge configurations: user_config overrides default_config
            merged_config = self.merge_configs(default_config, user_config)

            self.config = ConfigModel(**merged_config)
        except (yaml.YAMLError, ValidationError) as e:
            self.logger.error(f"Error loading configuration: {e}")
            raise e

    def merge_configs(self, default, override):
        merged = default.copy()
        for key, value in override.items():
            if key in merged and isinstance(merged[key], dict):
                merged[key] = self.merge_configs(merged[key], value)
            else:
                merged[key] = value
        return merged

    def get_config(self):
        return self.config

if __name__=="__main__":
    configmgr = ConfigManager()
    print(configmgr.project_root)