# core/modules/network_enumeration/beacon_analysis.py

from scapy.all import *
import threading
from typing import List, Dict

from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11


class BeaconAnalyzer:
    """
    Analyzes beacon frames to detect nearby access points
    """
    def __init__(self, interface: str, stop_event: threading.Event):
        """
        Initializes the BeaconAnalyzer.

        Args:
            interface (str): The network interface to capture packets on.
            stop_event (threading.Event): Event to signal stopping the packet capture.
        """
        self.interface = interface
        self.stop_event = stop_event
        self.access_points: Dict[str, Dict[str, Any]] = {}

    def start_capture(self):
        """
        Starts capturing beacon frames on the specified interface.
        """
        sniff(iface=self.interface, prn=self.process_packet, stop_filter=self.should_stop)

    def should_stop(self, packet) -> bool:
        """
        Determines whether to stop packet capturing.

        Args:
            packet: The captured packet.

        Returns:
            bool: True if capture should stop, False otherwise.
        """
        return self.stop_event.is_set()

    def process_packet(self, packet):
        """
        Processes each captured packet.

        Args:
            packet: The captured packet.
        """
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr3
            ssid = packet[Dot11Elt].info.decode(errors='ignore')
            capabilities = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+')
            timestamp = packet.time

            if bssid not in self.access_points:
                self.access_points[bssid] = {
                    'SSID': ssid,
                    'Capabilities': capabilities,
                    'Last Seen': timestamp
                }
            else:
                self.access_points[bssid]['Last Seen'] = timestamp

    def get_access_points(self) -> List[Dict[str, Any]]:
        """
        Retrieves the list of detected access points.

        Returns:
            List[Dict[str, Any]]: A list of access point details.
        """
        return list(self.access_points.values())

    def run(self):
        """
        Runs the packet capture in a separate thread.
        """
        capture_thread = threading.Thread(target=self.start_capture, daemon=True)
        capture_thread.start()
