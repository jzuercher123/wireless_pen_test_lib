import unittest
import os
from core.config_manager import ConfigManager
from core.log_manager import LogManager
import logging


class TestLogManager(unittest.TestCase):
    def setUp(self):
        # Set up a temporary config directory
        self.test_config_dir = "test_config"
        os.makedirs(self.test_config_dir, exist_ok=True)

        # Create default config
        default_config = {
            "general": {
                "interface": "wlan0mon",
                "log_level": "DEBUG",
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

        with open(os.path.join(self.test_config_dir, "config_defaults.yaml"), 'w') as f:
            import yaml
            yaml.dump(default_config, f)

        # Create user config with some overrides
        user_config = {
            "general": {
                "interface": "wlan1mon",
                "log_level": "INFO"
            }
        }

        with open(os.path.join(self.test_config_dir, "config.yaml"), 'w') as f:
            yaml.dump(user_config, f)

        # Initialize Config Manager
        self.config_manager = ConfigManager(config_dir=self.test_config_dir)

        # Initialize Log Manager
        self.log_manager = LogManager(self.config_manager)
        self.logger = logging.getLogger('TestLogger')
        self.logger.setLevel(logging.DEBUG)

    def tearDown(self):
        # Remove temporary config directory
        shutil.rmtree(self.test_config_dir)

        # Remove log handlers
        handlers = self.logger.handlers[:]
        for handler in handlers:
            handler.close()
            self.logger.removeHandler(handler)

    def test_logging_output(self):
        # Log messages
        self.logger.debug("This is a DEBUG message.")
        self.logger.info("This is an INFO message.")
        self.logger.warning("This is a WARNING message.")
        self.logger.error("This is an ERROR message.")
        self.logger.critical("This is a CRITICAL message.")

        # Check if log file exists
        log_file = os.path.join(self.config_manager.get_config().general.report_directory, '..', 'logs', 'app.log')
        self.assertTrue(os.path.exists(log_file))

        # Read log file and verify contents
        with open(log_file, 'r') as f:
            logs = f.read()
            self.assertIn("This is a DEBUG message.", logs)
            self.assertIn("This is an INFO message.", logs)
            self.assertIn("This is a WARNING message.", logs)
            self.assertIn("This is an ERROR message.", logs)
            self.assertIn("This is a CRITICAL message.", logs)


if __name__ == '__main__':
    unittest.main()
