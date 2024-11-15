import unittest
import os
import shutil
from core.config_manager import ConfigManager
from pydantic import ValidationError


class TestConfigManager(unittest.TestCase):
    def setUp(self):
        # Set up a temporary config directory
        self.test_config_dir = "test_config"
        os.makedirs(self.test_config_dir, exist_ok=True)

        # Create default config
        default_config = {
            "general": {
                "interface": "wlan0mon",
                "log_level": "INFO",
                "report_directory": "reports"
            },
            "scanners": {
                "encryption_scanner": {
                    "scan_duration": 15
                },
                "auth_bypass_scanner": {
                    "scan_duration": 10
                },
                "dos_scanner": {
                    "scan_duration": 10
                }
            },
            "exploits": {
                "session_hijacking": {
                    "max_packets": 100
                },
                "credential_extraction": {
                    "capture_duration": 20
                },
                "payload_delivery": {
                    "payload_types": ["reverse_shell", "malicious_script"],
                    "default_duration": 10
                }
            },
            "ui": {
                "theme": "default"
            }
        }

        with open(os.path.join(self.test_config_dir, "config.yaml"), 'w') as f:
            import yaml
            yaml.dump(default_config, f)

        # Create user config with some overrides
        user_config = {
            "general": {
                "interface": "wlan1mon"
            },
            "scanners": {
                "encryption_scanner": {
                    "scan_duration": 20
                }
            }
        }

        with open(os.path.join(self.test_config_dir, "config.yaml"), 'w') as f:
            yaml.dump(user_config, f)

        # Set environment variables to override configurations
        os.environ['GENERAL_LOG_LEVEL'] = 'DEBUG'
        os.environ['EXPLOITS_PAYLOAD_DELIVERY_DEFAULT_DURATION'] = '15'

    def tearDown(self):
        # Remove temporary config directory and environment variables
        shutil.rmtree(self.test_config_dir)
        del os.environ['GENERAL_LOG_LEVEL']
        del os.environ['EXPLOITS_PAYLOAD_DELIVERY_DEFAULT_DURATION']

    def test_load_config(self):
        cm = ConfigManager(config_dir=self.test_config_dir)
        config = cm.get_config()

        # Test overridden general.interface
        self.assertEqual(config.general.interface, "wlan1mon")

        # Test overridden scanners.encryption_scanner.scan_duration
        self.assertEqual(config.scanners.encryption_scanner.scan_duration, 20)

        # Test environment variable override for general.log_level
        self.assertEqual(config.general.log_level, "DEBUG")

        # Test environment variable override for exploits.payload_delivery.default_duration
        self.assertEqual(config.exploits.payload_delivery.default_duration, 15)

        # Test default values that were not overridden
        self.assertEqual(config.scanners.auth_bypass_scanner.scan_duration, 10)
        self.assertEqual(config.exploits.credential_extraction.capture_duration, 20)
        self.assertEqual(config.ui.theme, "default")

    def test_invalid_config(self):
        # Write invalid log_level
        with open(os.path.join(self.test_config_dir, "config.yaml"), 'a') as f:
            f.write("\ngeneral:\n  log_level: 'VERBOSE'\n")

        with self.assertRaises(ValidationError):
            cm = ConfigManager(config_dir=self.test_config_dir)
            cm.get_config()


if __name__ == '__main__':
    unittest.main()
