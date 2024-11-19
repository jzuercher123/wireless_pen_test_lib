# core/modules/network_enumeration/hidden_ssid_reveal.py

from scapy.all import *
import threading
from typing import List, Dict

from scapy.layers.dot11 import Dot11ProbeReq, Dot11, Dot11Elt


class HiddenSSIDRevealer:
    def __init__(self, interface: str, stop_event: threading.Event):
        self.interface = interface
        self.stop_event = stop_event
        self.hidden_ssids: Dict[str, Dict[str, Any]] = {}

    def start_capture(self):
        sniff(iface=self.interface, prn=self.process_packet, stop_filter=self.should_stop)

    def should_stop(self, packet) -> bool:
        return self.stop_event.is_set()

    def process_packet(self, packet):
        if packet.haslayer(Dot11ProbeReq):
            mac = packet[Dot11].addr2
            ssid = packet[Dot11Elt].info.decode(errors='ignore')
            timestamp = packet.time

            if ssid == "":
                ssid = "Hidden SSID"
            if mac not in self.hidden_ssids:
                self.hidden_ssids[mac] = {
                    'SSID': ssid,
                    'Last Seen': timestamp
                }
            else:
                self.hidden_ssids[mac]['Last Seen'] = timestamp

    def get_hidden_ssids(self) -> List[Dict[str, Any]]:
        return list(self.hidden_ssids.values())

    def run(self):
        capture_thread = threading.Thread(target=self.start_capture, daemon=True)
        capture_thread.start()
