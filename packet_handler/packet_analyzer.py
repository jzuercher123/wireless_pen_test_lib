from scapy.all import *
import logging

from scapy.layers.dot11 import Dot11Elt, Dot11Deauth, Dot11Beacon, Dot11


class PacketAnalyzer:
    def __init__(self, event_dispatcher):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.event_dispatcher = event_dispatcher

    def analyze_packet(self, packet):
        self.logger.debug(f"Analyzing packet: {packet.summary()}")

        if packet.haslayer(Dot11):
            dot11 = packet.getlayer(Dot11)

            # Beacon Frames
            if packet.haslayer(Dot11Beacon):
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                bssid = dot11.addr3
                self.logger.info(f"Beacon Frame - SSID: {ssid}, BSSID: {bssid}")
                self.event_dispatcher.dispatch('beacon_detected', ssid=ssid, bssid=bssid)

            # Deauthentication Frames
            elif packet.haslayer(Dot11Deauth):
                reason = packet[Dot11Deauth].reason
                addr1 = dot11.addr1
                addr2 = dot11.addr2
                bssid = dot11.addr3
                self.logger.info(f"Deauth Frame - Addr1: {addr1}, Addr2: {addr2}, BSSID: {bssid}, Reason: {reason}")
                self.event_dispatcher.dispatch('deauth_detected', addr1=addr1, addr2=addr2, bssid=bssid, reason=reason)

            # Probe Request Frames
            elif packet.type == 0 and packet.subtype == 4:
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore') if packet.haslayer(Dot11Elt) else ''
                client_mac = dot11.addr2
                self.logger.info(f"Probe Request - SSID: {ssid}, Client MAC: {client_mac}")
                self.event_dispatcher.dispatch('probe_request_detected', ssid=ssid, client_mac=client_mac)

            # Add more analyses as needed
