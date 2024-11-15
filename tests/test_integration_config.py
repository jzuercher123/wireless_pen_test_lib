import unittest
import os
import shutil
from core.config_manager import ConfigManager
from core import CoreFramework


class TestIntegrationConfig(unittest.TestCase):
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

        # Initialize Core Framework
        self.core = CoreFramework(modules_path=os.path.join(os.getcwd(), 'protocols'), config_path=self.test_config_dir)

    def tearDown(self):
        # Remove temporary config directory and environment variables
        shutil.rmtree(self.test_config_dir)
        del os.environ['GENERAL_LOG_LEVEL']
        del os.environ['EXPLOITS_PAYLOAD_DELIVERY_DEFAULT_DURATION']

    def test_core_configuration(self):
        # Access Core Framework configuration
        config = self.core.config

        # Verify general settings
        self.assertEqual(config.general.interface, "wlan1mon")
        self.assertEqual(config.general.log_level, "DEBUG")
        self.assertEqual(config.general.report_directory, "reports")

        # Verify scanner settings
        self.assertEqual(config.scanners.encryption_scanner.scan_duration, 20)
        self.assertEqual(config.scanners.auth_bypass_scanner.scan_duration, 10)
        self.assertEqual(config.scanners.dos_scanner.scan_duration, 10)

        # Verify exploit settings
        self.assertEqual(config.exploits.session_hijacking.max_packets, 100)
        self.assertEqual(config.exploits.credential_extraction.capture_duration, 20)
        self.assertEqual(config.exploits.payload_delivery.default_duration, 15)
        self.assertListEqual(config.exploits.payload_delivery.payload_types, ["reverse_shell", "malicious_script"])

        # Verify UI settings
        self.assertEqual(config.ui.theme, "default")

    def test_invalid_core_configuration(self):
        # Write invalid log_level
        with open(os.path.join(self.test_config_dir, "config.yaml"), 'a') as f:
            f.write("\ngeneral:\n  log_level: 'VERBOSE'\n")

        with self.assertRaises(Exception):
            self.core = CoreFramework(modules_path=os.path.join(os.getcwd(), 'protocols'),
                                      config_path=self.test_config_dir)


if __name__ == '__main__':
    unittest.main()
