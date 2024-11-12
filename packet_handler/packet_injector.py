import time

from scapy.all import *
import logging
import threading

class PacketInjector:
    def __init__(self, interface='wlan0mon'):
        self.interface = interface
        self.logger = logging.getLogger(self.__class__.__name__)
        self.injecting = False
        self.inject_thread = None

    def send_packet(self, packet, count=1, inter=0.1):
        """
        Sends a crafted packet.

        :param packet: Scapy packet to send.
        :param count: Number of times to send the packet.
        :param inter: Interval between packet sends.
        """
        self.logger.info(f"Sending packet: {packet.summary()} | Count: {count} | Interval: {inter}s")
        try:
            sendp(packet, iface=self.interface, count=count, inter=inter, verbose=False)
            self.logger.info("Packet sent successfully.")
        except Exception as e:
            self.logger.error(f"Failed to send packet: {e}")

    def send_continuous(self, packet, interval=0.1):
        """
        Continuously sends a crafted packet at specified intervals.

        :param packet: Scapy packet to send.
        :param interval: Time between sends in seconds.
        """
        self.injecting = True
        self.inject_thread = threading.Thread(target=self._inject_loop, args=(packet, interval))
        self.inject_thread.start()
        self.logger.info("Started continuous packet injection.")

    def _inject_loop(self, packet, interval):
        while self.injecting:
            try:
                sendp(packet, iface=self.interface, count=1, inter=0, verbose=False)
                self.logger.debug(f"Injected packet: {packet.summary()}")
                time.sleep(interval)
            except Exception as e:
                self.logger.error(f"Error during packet injection: {e}")

    def stop_continuous(self):
        """
        Stops continuous packet injection.
        """
        self.injecting = False
        if self.inject_thread and self.inject_thread.is_alive():
            self.inject_thread.join()
            self.logger.info("Stopped continuous packet injection.")
