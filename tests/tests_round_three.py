import unittest
from unittest.mock import patch, MagicMock, ANY
from click.testing import CliRunner
import os
from wireless_pen_test_lib.ui import cli


class TestCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = CliRunner()
        cls.sample_target = {
            'ssid': 'TestSSID',
            'bssid': 'AA:BB:CC:DD:EE:FF'
        }

    @patch('ui.cli.CoreFramework')
    def test_initialize_cli(self, mock_coreframework):
        mock_core = MagicMock()
        mock_coreframework.return_value = mock_core
        result = self.runner.invoke(cli, ['--version'])
        print(result.output)  # Debugging output
        self.assertEqual(result.exit_code, 0)
        mock_coreframework.assert_called_once()

    @patch('ui.cli.CoreFramework')
    def test_scan_command(self, mock_coreframework):
        mock_core = MagicMock()
        mock_core.scanners = {'encryption_scanner': MagicMock(), 'dos_scanner': MagicMock()}
        mock_coreframework.return_value = mock_core
        result = self.runner.invoke(cli, ['scan', '-s', 'encryption_scanner', '--target-ssid', 'TestSSID', '--target-bssid', 'AA:BB:CC:DD:EE:FF'])
        print(result.output)  # Debugging output
        self.assertEqual(result.exit_code, 0)
        mock_core.run_scanner.assert_called_once_with('encryption_scanner', self.sample_target)

    @patch('ui.cli.CoreFramework')
    def test_exploit_command(self, mock_coreframework):
        mock_core = MagicMock()
        mock_core.exploits = {'session_hijacking': MagicMock(), 'credential_extraction': MagicMock()}
        mock_coreframework.return_value = mock_core
        with patch('click.prompt', return_value='mock_value'):
            result = self.runner.invoke(cli, ['exploit', '-e', 'session_hijacking', '--target-ssid', 'TestSSID', '--target-bssid', 'AA:BB:CC:DD:EE:FF'])
        print(result.output)  # Debugging output
        self.assertEqual(result.exit_code, 0)
        mock_core.run_exploit.assert_called_once_with('session_hijacking', ANY)

    @patch('ui.cli.CoreFramework')
    def test_configure_command(self, mock_coreframework):
        mock_core = MagicMock()
        mock_coreframework.return_value = mock_core
        result = self.runner.invoke(cli, ['configure', '--set', 'general.interface', 'wlan0mon'])
        print(result.output)  # Debugging output
        self.assertEqual(result.exit_code, 0)
        mock_core.config_manager.set_config.assert_called_once_with('general.interface', 'wlan0mon')

    @patch('ui.cli.CoreFramework')
    def test_report_command(self, mock_coreframework):
        mock_core = MagicMock()
        mock_core.config_manager.general.report_directory = os.getcwd()
        mock_coreframework.return_value = mock_core
        result = self.runner.invoke(cli, ['report', '--format', 'txt'])
        print(result.output)  # Debugging output
        self.assertEqual(result.exit_code, 0)
        mock_core.finalize.assert_called_once()

    @patch('ui.cli.CoreFramework')
    @patch('subprocess.run')
    def test_test_network_command(self, mock_subprocess, mock_coreframework):
        mock_core = MagicMock()
        mock_coreframework.return_value = mock_core
        mock_subprocess.return_value.stdout = 'Network started successfully'
        result = self.runner.invoke(cli, ['test_network', '--action', 'start'])
        print(result.output)  # Debugging output
        self.assertEqual(result.exit_code, 0)
        mock_subprocess.assert_called_once_with(['python', ANY, 'start'], check=True, capture_output=True, text=True)

if __name__ == '__main__':
    unittest.main()