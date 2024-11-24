# wireless_pen_test_lib/scanners/client_discovery.py

import threading
import logging
from scapy.all import sniff
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt

class ClientDiscovery:

    """
    Discovers clients connected to wireless networks by sniffing data frames.
    """
    def __init__(self, interface, bssid_list, timeout=10):
        """
        Initializes the ClientDiscovery scanner.

        Args:
            interface (str): Network interface in monitor mode.
            bssid_list (list): List of BSSIDs to monitor.
            timeout (int): Duration to run the discovery in seconds.
        """
        self.interface = interface
        self.bssid_list = [bssid.lower() for bssid in bssid_list]
        self.timeout = timeout
        self.clients = {bssid: set() for bssid in self.bssid_list}
        self.logger = logging.getLogger(self.__class__.__name__)

    def _packet_handler(self, packet):
        if packet.haslayer(Dot11):
            bssid = packet[Dot11].addr3.lower()
            if bssid in self.bssid_list:
                client_mac = packet[Dot11].addr1.lower()
                if client_mac and client_mac not in self.clients[bssid]:
                    self.clients[bssid].add(client_mac)
                    self.logger.debug(f"Discovered Client: {client_mac} on BSSID: {bssid}")

    def scan(self):
        """
        Starts the client discovery process.

        Returns:
            dict: A dictionary mapping BSSIDs to sets of client MAC addresses.
        """
        self.logger.info(f"Starting client discovery on interface {self.interface} for {self.timeout} seconds.")
        try:
            sniff(iface=self.interface, prn=self._packet_handler, timeout=self.timeout, store=False)
            for bssid, clients in self.clients.items():
                self.logger.info(f"BSSID {bssid} has {len(clients)} clients.")
            return self.clients
        except Exception as e:
            self.logger.exception(f"Error during client discovery: {e}")
            return self.clients
