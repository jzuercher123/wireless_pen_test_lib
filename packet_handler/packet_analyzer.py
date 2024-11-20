# Concrete Handlers
from scapy.all import *
import logging
from scapy.layers.dot11 import Dot11Elt, Dot11Deauth, Dot11Beacon, Dot11
from scapy.layers.inet import UDP, TCP
from scapy.layers.l2 import Ether
from .base_packet_handler import PacketHandler
from scapy.all import Raw
from scapy.layers.inet import IP


class Dot11BeaconHandler(PacketHandler):
    def handle(self, packet):
        if packet.haslayer(Dot11Beacon):
            dot11 = packet.getlayer(Dot11)
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
            bssid = dot11.addr3
            self.logger.info(f"Beacon Frame - SSID: {ssid}, BSSID: {bssid}")
            self.event_dispatcher.dispatch('beacon_detected', ssid=ssid, bssid=bssid)
        elif self.next_handler:
            self.next_handler.handle(packet)

class Dot11DeauthHandler(PacketHandler):
    def handle(self, packet):
        if packet.haslayer(Dot11Deauth):
            dot11 = packet.getlayer(Dot11)
            reason = packet[Dot11Deauth].reason
            addr1 = dot11.addr1
            addr2 = dot11.addr2
            bssid = dot11.addr3
            self.logger.info(f"Deauth Frame - Addr1: {addr1}, Addr2: {addr2}, BSSID: {bssid}, Reason: {reason}")
            self.event_dispatcher.dispatch('deauth_detected', addr1=addr1, addr2=addr2, bssid=bssid, reason=reason)
        elif self.next_handler:
            self.next_handler.handle(packet)

class Dot11ProbeRequestHandler(PacketHandler):
    def handle(self, packet):
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 4:
            dot11 = packet.getlayer(Dot11)
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore') if packet.haslayer(Dot11Elt) else ''
            client_mac = dot11.addr2
            self.logger.info(f"Probe Request - SSID: {ssid}, Client MAC: {client_mac}")
            self.event_dispatcher.dispatch('probe_request_detected', ssid=ssid, client_mac=client_mac)
        elif self.next_handler:
            self.next_handler.handle(packet)

class EtherHandler(PacketHandler):
    def handle(self, packet):
        if packet.haslayer(Ether):
            eth_layer = packet.getlayer(Ether)
            self.logger.info(f"Ethernet Frame - Source MAC: {eth_layer.src}, Destination MAC: {eth_layer.dst}")
            # Continue to next handler if needed
        if self.next_handler:
            self.next_handler.handle(packet)

class IPHandler(PacketHandler):
    def handle(self, packet):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            self.logger.info(f"IP Packet - Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}, TTL: {ip_layer.ttl}")
            # Continue to next handler if needed
        if self.next_handler:
            self.next_handler.handle(packet)

class TCPHandler(PacketHandler):
    def handle(self, packet):
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            self.logger.info(f"TCP Segment - Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}, Flags: {tcp_layer.flags}")
            # Continue to next handler if needed
        elif self.next_handler:
            self.next_handler.handle(packet)

class UDPHandler(PacketHandler):
    def handle(self, packet):
        if packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            self.logger.info(f"UDP Datagram - Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")
            # Continue to next handler if needed
        elif self.next_handler:
            self.next_handler.handle(packet)

class RawDataHandler(PacketHandler):
    def handle(self, packet):
        if packet.haslayer(Raw):
            raw_data = packet.getlayer(Raw).load
            self.logger.info(f"Raw Data: {raw_data}")
            # Continue to next handler if needed
        if self.next_handler:
            self.next_handler.handle(packet)

# PacketAnalyzer Using Chain of Responsibility
class PacketAnalyzer:
    def __init__(self, event_dispatcher):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.event_dispatcher = event_dispatcher
        self.handler_chain = self.build_handler_chain()

    def build_handler_chain(self):
        # Build the chain by linking handlers
        raw_data_handler = RawDataHandler(self.event_dispatcher)
        udp_handler = UDPHandler(self.event_dispatcher, next_handler=raw_data_handler)
        tcp_handler = TCPHandler(self.event_dispatcher, next_handler=udp_handler)
        ip_handler = IPHandler(self.event_dispatcher, next_handler=tcp_handler)
        ether_handler = EtherHandler(self.event_dispatcher, next_handler=ip_handler)
        probe_request_handler = Dot11ProbeRequestHandler(self.event_dispatcher, next_handler=ether_handler)
        deauth_handler = Dot11DeauthHandler(self.event_dispatcher, next_handler=probe_request_handler)
        beacon_handler = Dot11BeaconHandler(self.event_dispatcher, next_handler=deauth_handler)
        return beacon_handler  # Start of the chain

    def analyze_packet(self, packet):
        self.logger.debug(f"Analyzing packet: {packet.summary()}")
        self.handler_chain.handle(packet)
