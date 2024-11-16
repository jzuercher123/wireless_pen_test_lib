# scanners/wpa3_scanner.py

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import threading
import time
from .base_scanner import BaseScanner


class WPA3Scanner(BaseScanner):
    def scan(self, core_framework, target_info=None, scan_duration=10, gui_update_callback=None, stop_event=None):
        """
        Scan for WPA3 networks and assess downgrade attack possibilities.

        Args:
            target_info (dict): Information about the target network (optional).
            stop_event (threading.Event): Event to signal stopping the scan.

        Returns:
            dict: Detected WPA3 networks with their details.
            :param scan_duration:
            :param target_info:
            :param core_framework:
            :param gui_update_callback:
        """
        self.logger.info("Starting WPA3 scan...")
        detected_wpa3_networks = {}

        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                bssid = pkt[Dot11].addr3
                stats = pkt[Dot11Beacon].network_stats()
                security = stats.get("crypto")
                # WPA3 networks include 'SAE' in crypto
                if "SAE" in security:
                    if bssid not in detected_wpa3_networks:
                        detected_wpa3_networks[bssid] = {
                            "SSID": ssid,
                            "BSSID": bssid,
                            "Security": security,
                            "Downgrade_Possible": self.assess_downgrade(bssid)
                        }
                        self.logger.info(
                            f"Detected WPA3 Network: SSID='{ssid}', BSSID={bssid}, Downgrade Possible={detected_wpa3_networks[bssid]['Downgrade_Possible']}")
                        if self.gui_update_callback:
                            self.gui_update_callback(
                                f"Detected WPA3 Network: SSID='{ssid}', BSSID={bssid}, Downgrade Possible={detected_wpa3_networks[bssid]['Downgrade_Possible']}")

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
                    self.logger.info("Stop event detected. Terminating WPA3 scan...")
                    break
                time.sleep(0.5)

            sniff_thread.join()
        except Exception as e:
            self.logger.error(f"Error during WPA3 scan: {e}")

        self.logger.info("WPA3 scan completed.")
        return {"wpa3_networks": detected_wpa3_networks}

    def assess_downgrade(self, bssid):
        """
        Assess if the network allows WPA2 downgrades.

        Args:
            bssid (str): The BSSID of the target network.

        Returns:
            str: 'Yes' if downgrade is possible, 'No' otherwise.
        """
        # Placeholder for downgrade assessment logic
        # Implement actual analysis based on information elements in beacon frames
        # For demonstration, we'll return a dummy value
        return "Unknown"
