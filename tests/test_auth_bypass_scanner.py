import unittest
from unittest.mock import MagicMock, patch
from wireless_pen_test_lib.scanners import AuthBypassScanner

class TestAuthBypassScanner(unittest.TestCase):
    def setUp(self):
        self.core_framework = MagicMock()
        self.scanner = AuthBypassScanner(self.core_framework, scan_duration=5)
        self.target = {'bssid': '00:11:22:33:44:55'}

    @patch('scapy.all.sniff')
    @patch('scapy.all.sendp')
    def starts_scan_and_detects_vulnerability(self, mock_sendp, mock_sniff):
        mock_sniff.return_value = []
        self.scanner.scan(self.target)
        self.assertTrue(self.scanner.detected_vulnerabilities)
        self.assertIn('AUTH_BYPASS', self.core_framework.vulnerability_db)

    @patch('scapy.all.sniff')
    @patch('scapy.all.sendp')
    def starts_scan_and_detects_no_vulnerability(self, mock_sendp, mock_sniff):
        mock_sniff.return_value = [MagicMock()]
        self.scanner.scan(self.target)
        self.assertFalse(self.scanner.detected_vulnerabilities)
        self.assertNotIn('AUTH_BYPASS', self.core_framework.vulnerability_db)

    def does_not_start_scan_without_bssid(self):
        self.scanner.scan({})
        self.assertFalse(self.scanner.detected_vulnerabilities)
        self.core_framework.send_continuous_packets.assert_not_called()

    def generates_report_with_vulnerabilities(self):
        self.scanner.detected_vulnerabilities = [{'bssid': '00:11:22:33:44:55', 'description': 'Test', 'action': 'Test action'}]
        with patch('builtins.print') as mock_print:
            self.scanner.report()
            mock_print.assert_called()

    def generates_report_without_vulnerabilities(self):
        self.scanner.detected_vulnerabilities = []
        with patch('builtins.print') as mock_print:
            self.scanner.report()
            mock_print.assert_not_called()

    def finalizes_scan(self):
        self.scanner.finalize()
        self.core_framework.stop_continuous_packets.assert_called()

