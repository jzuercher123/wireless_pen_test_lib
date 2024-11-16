import unittest
from unittest.mock import patch, MagicMock
from project_specifc_utils.network_interface_manager import NetworkInterfaceManager
import logging

class TestNetworkInterfaceManager(unittest.TestCase):
    def setUp(self):
        # Set up the logger to capture log outputs for assertions
        self.logger = logging.getLogger('NetworkInterfaceManager')
        self.logger.setLevel(logging.DEBUG)
        self.network_manager = NetworkInterfaceManager()

    @patch('project_specifc_utils.network_interface_manager.subprocess.run')
    def test_enable_monitor_mode_success(self, mock_run):
        # Mock successful execution of airmon-ng commands
        mock_run.return_value = subprocess.CompletedProcess(args=['airmon-ng', 'start', 'wlan0'], returncode=0, stdout='Monitor mode enabled', stderr='')

        try:
            self.network_manager.enable_monitor_mode('wlan0')
        except Exception as e:
            self.fail(f"enable_monitor_mode raised an exception {e}")

        # Ensure commands were called correctly
        expected_calls = [
            patch.call(['sudo', 'airmon-ng', 'check', 'kill'], check=True, stdout=patch.ANY, stderr=patch.ANY, text=True),
            patch.call(['sudo', 'airmon-ng', 'start', 'wlan0'], check=True, stdout=patch.ANY, stderr=patch.ANY, text=True)
        ]
        self.assertEqual(mock_run.call_count, 2)

    @patch('project_specifc_utils.network_interface_manager.subprocess.run')
    def test_enable_monitor_mode_failure(self, mock_run):
        # Mock failure in airmon-ng start command
        mock_run.side_effect = subprocess.CalledProcessError(returncode=1, cmd=['sudo', 'airmon-ng', 'start', 'wlan0'], stderr='Failed to start monitor mode')

        with self.assertRaises(subprocess.CalledProcessError):
            self.network_manager.enable_monitor_mode('wlan0')

    @patch('project_specifc_utils.network_interface_manager.subprocess.run')
    def test_get_interface_status_monitor(self, mock_run):
        # Mock iwconfig output indicating monitor mode
        mock_run.return_value = subprocess.CompletedProcess(args=['iwconfig', 'wlan0mon'], returncode=0, stdout='wlan0mon    IEEE 802.11  Mode:Monitor  Frequency:2.437 GHz  Tx-Power=20 dBm\n', stderr='')

        status = self.network_manager.get_interface_status('wlan0mon')
        self.assertEqual(status, "Monitor Mode")

    @patch('project_specifc_utils.network_interface_manager.subprocess.run')
    def test_get_interface_status_managed(self, mock_run):
        # Mock iwconfig output indicating managed mode
        mock_run.return_value = subprocess.CompletedProcess(args=['iwconfig', 'wlan0'], returncode=0, stdout='wlan0     IEEE 802.11  ESSID:"TestNetwork"  Nickname:"<WIFI@REALTEK>\n Mode:Managed  Frequency:2.437 GHz  Access Point: 00:11:22:33:44:55 \n', stderr='')

        status = self.network_manager.get_interface_status('wlan0')
        self.assertEqual(status, "Managed Mode")

    @patch('project_specifc_utils.network_interface_manager.subprocess.run')
    def test_get_interface_status_unknown(self, mock_run):
        # Mock iwconfig output with unknown mode
        mock_run.return_value = subprocess.CompletedProcess(args=['iwconfig', 'wlan0'], returncode=0, stdout='wlan0     IEEE 802.11  ESSID:"TestNetwork"\n Mode:Unknown\n', stderr='')

        status = self.network_manager.get_interface_status('wlan0')
        self.assertEqual(status, "Unknown")

if __name__ == '__main__':
    unittest.main()
