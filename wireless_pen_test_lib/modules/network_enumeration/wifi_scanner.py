# modules/network_enumeration/wifi_scanner.py

import logging
from typing import Optional, List, Dict, Any
import pywifi
from pywifi import PyWiFi, const
from pywifi.iface import Interface

import time


class WifiScanner:
    """
    Class to handle Wi-Fi scanning operations.
    """

    def __init__(self, interface: Optional[str] = None, logger: Optional[logging.Logger] = None):
        """
        Initializes the WifiScanner.

        Args:
            interface (str, optional): Name of the network interface to use. Defaults to None.
            logger (logging.Logger, optional): Logger instance for logging messages. Defaults to None.
        """
        self.logger = logger or logging.getLogger(__name__)
        self.logger.debug("Initializing WifiScanner.")

        self.pywifi = PyWiFi()
        self.iface = self._get_interface(interface)

        # Start the interface
        self.iface.scan()
        self.logger.debug("WifiScanner initialized successfully.")

    def _get_interface(self, interface_name: Optional[str]) -> pywifi.iface.Interface:
        """
        Retrieves the specified Wi-Fi interface or the first available one.

        Args:
            interface_name (str, optional): Name of the Wi-Fi interface. Defaults to None.

        Returns:
            pywifi.interfaces.Interface: The Wi-Fi interface object.

        Raises:
            ValueError: If no Wi-Fi interfaces are found.
        """
        if interface_name:
            for iface in self.pywifi.interfaces():
                if iface.name() == interface_name:
                    self.logger.debug(f"Using specified interface: {interface_name}")
                    return iface
            self.logger.warning(f"Interface '{interface_name}' not found. Using the first available interface.")

        interfaces = self.pywifi.interfaces()
        if not interfaces:
            self.logger.error("No Wi-Fi interfaces found.")
            raise ValueError("No Wi-Fi interfaces found.")

        self.logger.debug(f"Using default interface: {interfaces[0].name()}")
        return interfaces[0]

    def scan_networks(self, scan_duration: int = 5) -> List[Dict[str, Any]]:
        """
        Scans for available Wi-Fi networks.

        Args:
            scan_duration (int, optional): Duration to wait for the scan to complete in seconds. Defaults to 5.

        Returns:
            List[Dict[str, Any]]: List of dictionaries containing SSID, BSSID, signal strength, channel, and security.
        """
        self.logger.info("Starting Wi-Fi network scan...")
        self.iface.scan()
        time.sleep(scan_duration)  # Wait for the scan to complete

        results = self.iface.scan_results()
        networks = []

        for network in results:
            security = self._get_security(network)
            networks.append({
                'ssid': network.ssid,
                'bssid': network.bssid,
                'signal': network.signal,
                'channel': self._get_channel(network.freq),
                'security': security
            })

        self.logger.info(f"Wi-Fi scan completed. {len(networks)} networks found.")
        return networks

    def _get_security(self, network) -> str:
        """
        Determines the security type of the Wi-Fi network.

        Args:
            network: PyWiFi network object.

        Returns:
            str: Security type (e.g., Open, WEP, WPA, WPA2).
        """
        akm = network.akm
        if not akm:
            return "Open"

        # Check available AKM types
        if const.AKM_TYPE_NONE in akm:
            return "Open"
        if const.AKM_TYPE_WPA2 in akm:
            return "WPA2"
        if const.AKM_TYPE_WPA in akm:
            return "WPA"

        # If AKM_TYPE_WEP exists, include it conditionally
        try:
            if const.AKM_TYPE_WEP in akm:
                return "WEP"
        except AttributeError:
            # AKM_TYPE_WEP does not exist in this pywifi version
            pass

        return "Unknown"

    def _get_channel(self, freq: int) -> int:
        """
        Converts frequency to Wi-Fi channel number.

        Args:
            freq (int): Frequency in MHz.

        Returns:
            int: Wi-Fi channel number.
        """
        if 2412 <= freq <= 2484:
            return (freq - 2407) // 5
        elif 5000 <= freq <= 5825:
            return (freq - 5000) // 5
        else:
            return 0  # Unknown channel

    def stop_scanning(self) -> None:
        """
        Stops any ongoing scanning operations.
        """
        self.logger.info("Stopping Wi-Fi network scan.")
        self.iface.stop()
