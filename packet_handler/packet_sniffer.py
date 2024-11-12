from scapy.all import sniff
import logging
import threading

class PacketSniffer:
    def __init__(self, interface='wlan0mon', filter=None, prn=None):
        """
        Initializes the PacketSniffer.

        :param interface: Wireless interface in monitor mode.
        :param filter: BPF filter string.
        :param prn: Callback function to process each packet.
        """
        self.interface = interface
        self.filter = filter
        self.prn = prn
        self.logger = logging.getLogger(self.__class__.__name__)
        self.sniffing = False
        self.sniff_thread = None

    def start_sniffing(self):
        """
        Starts packet sniffing in a separate thread.
        """
        self.sniffing = True
        self.sniff_thread = threading.Thread(target=self._sniff)
        self.sniff_thread.start()
        self.logger.info("Started packet sniffing.")

    def _sniff(self):
        """
        Internal method to perform sniffing.
        """
        try:
            sniff(iface=self.interface, filter=self.filter, prn=self.prn, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            self.logger.error(f"Error during packet sniffing: {e}")

    def stop_sniffing(self):
        """
        Stops packet sniffing.
        """
        self.sniffing = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join()
            self.logger.info("Stopped packet sniffing.")
