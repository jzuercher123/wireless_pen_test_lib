
import unittest
from scapy.packet import Packet
from wireless_pen_test_lib.packet_handler.packet_injector import PacketInjector


class EthernetHeader:
    pass


class IPHeader:
    pass


class UDPHeader:
    pass


class TestPacketInjector(unittest.TestCase):
    def test_inject_packet(self):
        # Create a packet
        packet = Packet()
        packet.add_header(EthernetHeader())
        packet.add_header(IPHeader())
        packet.add_header(UDPHeader())

        # Create a packet injector
        injector = PacketInjector()

        # Inject the packet
        injector.inject_packet(packet)

        # Check if the packet was injected
        self.assertEqual(injector.get_injected_packet(), packet)

if __name__ == '__main__':
    unittest.main()