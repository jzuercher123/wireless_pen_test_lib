# wireless_pen_test_lib/scanners/network_discovery.py

import threading
import logging
from scapy.all import sniff
from scapy.layers.dot11 import Dot11Elt, Dot11, Dot11Elt, Dot11Beacon


class NetworkDiscovery:
    """
    Discovers nearby wireless networks by sniffing beacon frames.
    """
    def __init__(self, interface, timeout=10):
        """
        Initializes the NetworkDiscovery scanner.

        Args:
            interface (str): Network interface in monitor mode.
            timeout (int): Duration to run the discovery in seconds.
        """
        self.interface = interface
        self.timeout = timeout
        self.networks = {}
        self.logger = logging.getLogger(self.__class__.__name__)

    def _packet_handler(self, packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode(errors='ignore')
            bssid = packet[Dot11].addr3
            stats = packet[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            encryption = self._get_encryption(packet)
            signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "N/A"

            if bssid not in self.networks:
                self.networks[bssid] = {
                    "SSID": ssid,
                    "BSSID": bssid,
                    "Channel": channel,
                    "Encryption": encryption,
                    "Signal": signal_strength
                }
                self.logger.debug(f"Discovered Network: {self.networks[bssid]}")

    def _get_encryption(self, packet):
        encryption = "Open"
        if packet.haslayer(Dot11Elt):
            elems = packet.getlayer(Dot11Elt).payload
            while isinstance(elems, Dot11Elt):
                if elems.ID == 48:
                    encryption = "WPA2"
                elif elems.ID == 221 and elems.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    encryption = "WPA"
                elems = elems.payload
        return encryption

    def scan(self):
        """
        Starts the network discovery process.

        Returns:
            dict: A dictionary of discovered networks.
        """
        self.logger.info(f"Starting network discovery on interface {self.interface} for {self.timeout} seconds.")
        try:
            sniff(iface=self.interface, prn=self._packet_handler, timeout=self.timeout, store=False)
            self.logger.info(f"Network discovery completed. {len(self.networks)} networks found.")
            return self.networks
        except Exception as e:
            self.logger.exception(f"Error during network discovery: {e}")
            return self.networks
