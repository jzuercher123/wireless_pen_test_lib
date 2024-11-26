# tests/test_wep_scanner.py

import unittest
from unittest.mock import MagicMock, patch
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from wireless_pen_test_lib.scanners.wep_scanner import WEPScanner


class TestWEPScanner(unittest.TestCase):
    def setUp(self):
        # Mock CoreFramework with a mock logger and network_manager
        self.mock_core_framework = MagicMock()
        self.mock_core_framework.logger = MagicMock()
        self.mock_core_framework.network_manager.interface = "wlan0mon"

        # Initialize WEPScanner with mocked CoreFramework
        self.wep_scanner = WEPScanner(core_framework=self.mock_core_framework)
        # Assuming WEPScanner has a scan_duration attribute
        self.wep_scanner.scan_duration = 10

    def test_init(self):
        self.assertEqual(self.wep_scanner.core_framework, self.mock_core_framework)
        self.assertEqual(self.wep_scanner.scan_duration, 10)

    def test_scan_no_wep_networks(self):
        target_info = {"ssid": "TestSSID", "bssid": "00:11:22:33:44:55"}
        stop_event = MagicMock()
        stop_event.is_set.return_value = False

        with patch('scapy.all.sniff') as mock_sniff:
            # Simulate sniff not finding any WEP networks
            mock_sniff.side_effect = lambda iface, prn, timeout, stop_filter: None
            result = self.wep_scanner.scan(target_info, stop_event)
            self.assertIn("wep_networks", result)
            self.assertEqual(result["wep_networks"], {})

    def test_scan_with_wep_networks(self):
        target_info = {"ssid": "TestSSID", "bssid": "00:11:22:33:44:55"}
        stop_event = MagicMock()
        stop_event.is_set.return_value = False

        # Create a fake WEP packet
        pkt = Dot11(addr3="00:11:22:33:44:55") / Dot11Beacon() / Dot11Elt(ID="SSID", info="TestSSID") / Dot11Elt(
            ID="Rates", info="some rates") / Dot11Elt(ID="RSN", info="some rsn info")

        with patch('scapy.all.sniff') as mock_sniff:
            # Simulate sniff calling packet_handler with the fake packet
            def side_effect(*args, **kwargs):
                prn = kwargs.get('prn')
                prn(pkt)

            mock_sniff.side_effect = side_effect
            result = self.wep_scanner.scan(target_info, stop_event)
            self.assertIn("wep_networks", result)
            self.assertIn("00:11:22:33:44:55", result["wep_networks"])
            self.assertEqual(result["wep_networks"]["00:11:22:33:44:55"]["SSID"], "TestSSID")
            self.assertEqual(result["wep_networks"]["00:11:22:33:44:55"]["BSSID"], "00:11:22:33:44:55")
            self.assertEqual(result["wep_networks"]["00:11:22:33:44:55"]["Security"],
                             ['WEP'])  # Assuming 'WEP' is in security
            self.assertEqual(result["wep_networks"]["00:11:22:33:44:55"]["Key_Strength"], "Unknown")

    def test_assess_key_strength(self):
        pkt = Dot11()
        result = self.wep_scanner.assess_key_strength(pkt)
        self.assertEqual(result, "Unknown")  # Based on the current implementation

    def tearDown(self):
        # Clean up after each test if necessary
        pass


if __name__ == '__main__':
    print("Running WEPScanner tests...")
    print(f"{'*' * 40}\n")

    unittest.main()
