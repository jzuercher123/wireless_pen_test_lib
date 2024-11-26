# scanners/wpa_wpa2_scanner.py

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import threading
import subprocess
import time
from .base_scanner import BaseScanner


class WPAWPA2Scanner(BaseScanner):
    """
    A scanner to detect WPA/WPA2 networks and check for weak PSKs and WPS status.
    """
    def scan(self, core_framework, target_info=None, scan_duration=10, gui_update_callback=None, stop_event=None):
        """
        Scan for WPA/WPA2 networks, check for weak PSKs, and detect WPS status.

        Args:
            target_info (dict): Information about the target network (optional).
            stop_event (threading.Event): Event to signal stopping the scan.

        Returns:
            dict: Detected WPA/WPA2 networks with their details.
            :param stop_event:
            :param gui_update_callback:
            :param target_info:
            :param scan_duration:
            :param core_framework:
        """
        self.logger.info("Starting WPA/WPA2 scan...")
        detected_wpa_networks = {}

        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                bssid = pkt[Dot11].addr3
                stats = pkt[Dot11Beacon].network_stats()
                security = stats.get("crypto")
                if "WPA2" in security or "WPA" in security:
                    if bssid not in detected_wpa_networks:
                        detected_wpa_networks[bssid] = {
                            "SSID": ssid,
                            "BSSID": bssid,
                            "Security": security,
                            "WPS_Enabled": self.check_wps(bssid)
                        }
                        self.logger.info(
                            f"Detected WPA/WPA2 Network: SSID='{ssid}', BSSID={bssid}, WPS Enabled={detected_wpa_networks[bssid]['WPS_Enabled']}")
                        if self.gui_update_callback:
                            self.gui_update_callback(
                                f"Detected WPA/WPA2 Network: SSID='{ssid}', BSSID={bssid}, WPS Enabled={detected_wpa_networks[bssid]['WPS_Enabled']}")

        try:
            # Start sniffing in a separate thread
            sniff_thread = threading.Thread(target=sniff, kwargs={
                "iface": self.core_framework.network_manager.interface,
                "prn": packet_handler,
                "timeout": 15,
                "stop_filter": lambda x: stop_event.is_set()
            })
            sniff_thread.start()

            # Monitor the stop_event
            while sniff_thread.is_alive():
                if stop_event.is_set():
                    self.logger.info("Stop event detected. Terminating WPA/WPA2 scan...")
                    break
                time.sleep(0.5)

            sniff_thread.join()
        except Exception as e:
            self.logger.error(f"Error during WPA/WPA2 scan: {e}")

        self.logger.info("WPA/WPA2 scan completed.")
        return {"wpa_networks": detected_wpa_networks}

    def check_wps(self, bssid):
        """
        Check if WPS is enabled on the network using 'wash' tool.

        Args:
            bssid (str): The BSSID of the target network.

        Returns:
            str: 'Yes' if WPS is enabled, 'No' otherwise.
        """
        try:
            # Run wash command to check WPS status
            # Ensure 'wash' is installed and available in the system PATH
            result = subprocess.run(['wash', '-i', self.core_framework.network_manager.interface, '-b', bssid],
                                    capture_output=True, text=True, timeout=5)
            if "WPS Enabled" in result.stdout:
                return "Yes"
            else:
                return "No"
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout while checking WPS status for BSSID: {bssid}")
            return "No"
        except FileNotFoundError:
            self.logger.error("The 'wash' tool is not installed or not found in PATH.")
            return "Unknown"
        except Exception as e:
            self.logger.error(f"Error checking WPS status for BSSID {bssid}: {e}")
            return "Unknown"
