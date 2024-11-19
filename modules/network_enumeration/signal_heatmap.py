# core/modules/network_enumeration/signal_heatmap.py

from scapy.all import *
import threading
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Dict

from scapy.layers.dot11 import Dot11Beacon, Dot11


class SignalHeatmap:
    def __init__(self, interface: str, stop_event: threading.Event):
        self.interface = interface
        self.stop_event = stop_event
        self.signal_data: Dict[str, List[int]] = {}  # BSSID: List of signal strengths

    def start_capture(self):
        sniff(iface=self.interface, prn=self.process_packet, stop_filter=self.should_stop)

    def should_stop(self, packet) -> bool:
        return self.stop_event.is_set()

    def process_packet(self, packet):
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr3
            signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 0
            if bssid not in self.signal_data:
                self.signal_data[bssid] = []
            self.signal_data[bssid].append(signal_strength)

    def get_average_signals(self) -> Dict[str, float]:
        return {bssid: sum(signals)/len(signals) for bssid, signals in self.signal_data.items()}

    def generate_heatmap(self):
        average_signals = self.get_average_signals()
        bssids = list(average_signals.keys())
        signals = list(average_signals.values())

        plt.figure(figsize=(10, len(bssids)*0.5))
        sns.heatmap([signals], annot=True, fmt=".1f", cmap="coolwarm",
                    xticklabels=bssids, yticklabels=["Signal Strength (dBm)"])
        plt.title("Signal Strength Heatmap")
        plt.xlabel("BSSID")
        plt.ylabel("")
        plt.show()

    def run(self):
        capture_thread = threading.Thread(target=self.start_capture, daemon=True)
        capture_thread.start()
