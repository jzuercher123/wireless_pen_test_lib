# scanners/wep_scanner.py

from scapy.all import sniff, hexdump
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import threading
import sys
import time
from .base_scanner import BaseScanner



class WEPScanner(BaseScanner):
    """
    A scanner to detect WEP networks and assess key strength.
    """
    def __init__(self, core_framework, scan_duration: int = 10):
        super().__init__(core_framework, scan_duration)
        self.logger = core_framework.logger.getChild(self.__class__.__name__)
        self.network_manager = core_framework.network_manager

    def scan(self, core_framework, target_info=None, stop_event=None):
        """
        Scan for WEP networks and assess key strength.

        Args:
            target_info (dict): Information about the target network (optional).
            stop_event (threading.Event): Event to signal stopping the scan.

        Returns:
            dict: Detected WEP networks with their details.
            :param stop_event:
            :param target_info:
            :param core_framework:
        """
        self.logger.info("Starting WEP scan...")
        detected_wep_networks = {}

        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                bssid = pkt[Dot11].addr3
                stats = pkt[Dot11Beacon].network_stats()
                security = stats.get("crypto")
                if "WEP" in security:
                    if bssid not in detected_wep_networks:
                        detected_wep_networks[bssid] = {
                            "SSID": ssid,
                            "BSSID": bssid,
                            "Security": security,
                            "Key_Strength": self.assess_key_strength(pkt)
                        }
                        self.logger.info(f"Detected WEP Network: SSID='{ssid}', BSSID={bssid}")
                        if self.gui_update_callback:
                            self.gui_update_callback(f"Detected WEP Network: SSID='{ssid}', BSSID={bssid}")

        try:
            # Start sniffing in a separate thread
            sniff_thread = threading.Thread(target=sniff, kwargs={
                "iface": "eth0",
                "prn": packet_handler,
                "timeout": 15,
                "stop_filter": lambda x: stop_event.is_set()
            })
            sniff_thread.start()

            # Monitor the stop_event
            while sniff_thread.is_alive():
                if stop_event.is_set():
                    self.logger.info("Stop event detected. Terminating WEP scan...")
                    break
                time.sleep(0.5)

            sniff_thread.join()
        except Exception as e:
            self.logger.error(f"Error during WEP scan: {e}")

        self.logger.info("WEP scan completed.")
        return {"wep_networks": detected_wep_networks}

    def assess_key_strength(self, pkt):
        """
        Assess the strength of the WEP key based on IV reuse.

        Args:
            pkt: The captured packet.

        Returns:
            str: Assessment of key strength.
        """
        # Placeholder for key strength assessment logic
        # Implement actual analysis based on IV patterns and other factors
        # For demonstration, we'll return a dummy value
        return "Unknown"

    def gui_update_callback(self, message):
        """
        Update the GUI with the provided message.

        Args:
            message (str): The message to display to the user.
        """
        self.logger.info(f"GUI Update: {message}")
        if self.core_framework.gui:
            self.core_framework.gui.update_feedback(message)
        else:
            print(message)


if __name__ == '__main__':
    # Placeholder for testing WEPScanner
    from core.__init__ import CoreFramework

    core = CoreFramework(modules_path="../core/config/protocols/")
    wep_scanner = WEPScanner(core)
    stop_event = threading.Event()
    scan_results = wep_scanner.scan(core, stop_event=stop_event)
    print(scan_results)
    stop_event.set()
    sys.exit(0)