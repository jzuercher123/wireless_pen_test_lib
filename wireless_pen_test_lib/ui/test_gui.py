import unittest
from .gui import WirelessPenTestGUI
from wireless_pen_test_lib.ui.frames.live_network_frame import LiveNetworkFrame


def create_fake_test_data():
    return {
        "wpa_networks": {
            "00:11:22:33:44:55": {
                "SSID": "TestNetwork",
                "BSSID": "00:11:22:33:44:55",
                "Security": "WPA2",
                "WPS_Enabled": False
            }
        },
        "wep_networks": {
            "00:11:22:33:44:66": {
                "SSID": "TestNetwork",
                "BSSID": "00:11:22:33:44:66",
                "Security": "WEP",
                "Key_Strength": "Weak"
            }
        }
    }

class TestGui(unittest.TestCase):
    def test_gui(self):
        # Create a fake test data
        test_data = create_fake_test_data()

        # Create a GUI instance
        gui = WirelessPenTestGUI()

        # Create a LiveNetworkFrame instance
        live_network_frame = LiveNetworkFrame(gui, core_framework=None)

        # Update the GUI with the test data
        live_network_frame.update_gui(test_data)

        # Check if the GUI has been updated correctly
        self.assertEqual(gui.wpa_networks, test_data["wpa_networks"])
        self.assertEqual(gui.wep_networks, test_data["wep_networks"])

if __name__ == '__main__':
    unittest.main()