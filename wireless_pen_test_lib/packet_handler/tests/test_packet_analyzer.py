import unittest
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.inet import IP, TCP, UDP
import logging
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.l2 import Ether
from scapy.all import Raw
from wireless_pen_test_lib.packet_handler.packet_analyzer import PacketAnalyzer


class MockEventDispatcher:
    def __init__(self):
        self.events = []

    def dispatch(self, event_name, **kwargs):
        self.events.append((event_name, kwargs))


class TestPacketAnalyzer(unittest.TestCase):
    def setUp(self):
        self.event_dispatcher = MockEventDispatcher()
        self.packet_analyzer = PacketAnalyzer(self.event_dispatcher)
        self.logger = logging.getLogger('PacketAnalyzerTest')
        logging.basicConfig(level=logging.INFO)

    def test_beacon_handler(self):
        # Create a mock Beacon frame
        ssid = 'TestNetwork'
        beacon_packet = RadioTap() / Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                                           addr2='00:11:22:33:44:55',
                                           addr3='00:11:22:33:44:55') / Dot11Beacon() / Dot11Elt(ID='SSID', info=ssid)
        self.packet_analyzer.analyze_packet(beacon_packet)

        # Check if the event was dispatched
        self.assertIn(('beacon_detected', {'ssid': ssid, 'bssid': '00:11:22:33:44:55'}), self.event_dispatcher.events)

    def test_deauth_handler(self):
        # Create a mock Deauthentication frame
        deauth_packet = RadioTap() / Dot11(type=0, subtype=12, addr1='00:11:22:33:44:66',
                                           addr2='00:11:22:33:44:55', addr3='00:11:22:33:44:55') / Dot11Deauth(reason=3)
        self.packet_analyzer.analyze_packet(deauth_packet)

        # Check if the event was dispatched
        expected_event = ('deauth_detected',
                          {'addr1': '00:11:22:33:44:66', 'addr2': '00:11:22:33:44:55', 'bssid': '00:11:22:33:44:55',
                           'reason': 3})
        self.assertIn(expected_event, self.event_dispatcher.events)

    def test_probe_request_handler(self):
        # Create a mock Probe Request frame
        ssid = 'TestProbe'
        probe_packet = RadioTap() / Dot11(type=0, subtype=4, addr1='ff:ff:ff:ff:ff:ff',
                                          addr2='00:11:22:33:44:77', addr3='ff:ff:ff:ff:ff:ff') / Dot11Elt(ID='SSID',
                                                                                                           info=ssid)
        self.packet_analyzer.analyze_packet(probe_packet)

        # Check if the event was dispatched
        expected_event = ('probe_request_detected', {'ssid': ssid, 'client_mac': '00:11:22:33:44:77'})
        self.assertIn(expected_event, self.event_dispatcher.events)

    def test_ether_handler(self):
        # Create a mock Ethernet frame
        ether_packet = Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb')
        self.packet_analyzer.analyze_packet(ether_packet)
        # Since EtherHandler doesn't dispatch events, we'll check the logs or ensure no errors occur

    def test_ip_handler(self):
        # Create a mock IP packet
        ip_packet = IP(src='192.168.1.1', dst='192.168.1.2')
        self.packet_analyzer.analyze_packet(ip_packet)
        # Similar to EtherHandler, check logs or no exceptions

    def test_tcp_handler(self):
        # Create a mock TCP segment
        tcp_packet = IP(src='192.168.1.1', dst='192.168.1.2') / TCP(sport=12345, dport=80, flags='S')
        self.packet_analyzer.analyze_packet(tcp_packet)
        # Check logs or no exceptions

    def test_udp_handler(self):
        # Create a mock UDP datagram
        udp_packet = IP(src='192.168.1.1', dst='192.168.1.2') / UDP(sport=12345, dport=53)
        self.packet_analyzer.analyze_packet(udp_packet)
        # Check logs or no exceptions

    def test_raw_data_handler(self):
        # Create a mock packet with Raw data
        raw_data = b'This is some raw data'
        raw_packet = IP(src='192.168.1.1', dst='192.168.1.2') / Raw(load=raw_data)
        self.packet_analyzer.analyze_packet(raw_packet)
        # Check logs or no exceptions

    def tearDown(self):
        self.event_dispatcher.events.clear()


if __name__ == '__main__':
    unittest.main()
