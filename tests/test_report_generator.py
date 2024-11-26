import unittest
import os
from wireless_pen_test_lib.core import ConfigManager
from wireless_pen_test_lib.core.log_manager import LogManager
from wireless_pen_test_lib.core import ReportGenerator
from wireless_pen_test_lib.scanners import EncryptionWeaknessScanner
from wireless_pen_test_lib.exploits import SessionHijacking
import shutil


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        # Set up a temporary configs directory
        self.test_config_dir = "test_config"
        os.makedirs(self.test_config_dir, exist_ok=True)

        # Create default configs
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

        with open(os.path.join(self.test_config_dir, "configs.yaml"), 'w') as f:
            import yaml
            yaml.dump(default_config, f)

        # Initialize Config Manager
        self.config_manager = ConfigManager(config_dir=self.test_config_dir)

        # Initialize Log Manager
        self.log_manager = LogManager(self.config_manager)

        # Initialize Scanners and Exploits with mock data
        self.encryption_scanner = EncryptionWeaknessScanner(None,
                                                            self.config_manager.get_config().scanners.encryption_scanner.dict())
        self.encryption_scanner.detected_vulnerabilities = [
            {
                'ssid': 'TestNetwork',
                'bssid': '00:11:22:33:44:55',
                'protocol': 'WEP',
                'description': 'Weak encryption detected.',
                'action': 'Upgrade to WPA2.'
            }
        ]

        self.session_hijacking = SessionHijacking(None,
                                                  self.config_manager.get_config().exploits.session_hijacking.dict())
        self.session_hijacking.detected_vulnerabilities = [
            {
                'target': '192.168.1.10',
                'description': 'Session hijacking successful.',
                'status': 'Compromised',
                'action_taken': 'Gained unauthorized access.'
            }
        ]

        self.scanners = {
            'encryption_scanner': self.encryption_scanner
        }

        self.exploits = {
            'session_hijacking': self.session_hijacking
        }

        # Initialize Report Generator
        self.report_generator = ReportGenerator(self.config_manager.get_config(), self.scanners, self.exploits)
        self.report_generator.create_html_template()

    def tearDown(self):
        # Remove temporary configs directory
        shutil.rmtree(self.test_config_dir)

        # Remove report files
        report_dir = os.path.join(os.getcwd(), 'reports')
        if os.path.exists(report_dir):
            shutil.rmtree(report_dir)

    def test_generate_json_report(self):
        self.report_generator.generate_reports()
        json_report_path = os.path.join(self.config_manager.get_config().general.report_directory, 'json',
                                        'report.json')
        self.assertTrue(os.path.exists(json_report_path))

        with open(json_report_path, 'r') as f:
            report_data = json.load(f)
            self.assertIn('scanners', report_data)
            self.assertIn('exploits', report_data)
            self.assertIn('encryption_scanner', report_data['scanners'])
            self.assertIn('session_hijacking', report_data['exploits'])
            self.assertEqual(len(report_data['scanners']['encryption_scanner']['results']), 1)
            self.assertEqual(len(report_data['exploits']['session_hijacking']['results']), 1)

    def test_generate_html_report(self):
        self.report_generator.generate_reports()
        html_report_path = os.path.join(self.config_manager.get_config().general.report_directory, 'html',
                                        'report.html')
        self.assertTrue(os.path.exists(html_report_path))

        with open(html_report_path, 'r') as f:
            html_content = f.read()
            self.assertIn('<h1>WirelessPenTestLib Report</h1>', html_content)
            self.assertIn('Encryption Weakness Scan', html_content)
            self.assertIn('Session Hijacking', html_content)
            self.assertIn('Weak encryption detected.', html_content)
            self.assertIn('Session hijacking successful.', html_content)

    def test_generate_pdf_report(self):
        # Ensure wkhtmltopdf is installed; skip test if not
        try:
            import pdfkit
            self.report_generator.generate_reports()
            pdf_report_path = os.path.join(self.config_manager.get_config().general.report_directory, 'pdf',
                                           'report.pdf')
            self.assertTrue(os.path.exists(pdf_report_path))
        except OSError:
            self.skipTest("wkhtmltopdf not installed. Skipping PDF report generation test.")


if __name__ == '__main__':
    unittest.main()
