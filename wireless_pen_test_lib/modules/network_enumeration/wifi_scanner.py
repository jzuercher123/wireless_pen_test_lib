# wireless_pen_test_lib/modules/network_enumeration/wifi_scanner.py

import logging

# wireless_pen_test_lib/core/wifi_scanner.py

"""
WifiScanner Module

This module defines the WifiScanner class, responsible for scanning available Wi-Fi networks
using the pywifi library. It integrates with the CoreFramework to add discovered networks
to the universal pool.

**⚠️ Important Note:**
Ensure you have the necessary permissions to scan networks. Unauthorized scanning may be illegal
and unethical.
"""

import logging
import re
import socket
from typing import Optional, List, Dict, Any

import pywifi
from pywifi import PyWiFi, const
from pywifi.iface import Interface
import time


class WifiScanner:
    """
    WifiScanner Class

    Handles Wi-Fi scanning operations, retrieves network details, and integrates with the
    CoreFramework to manage discovered networks.
    """

    def __init__(
            self,
            interface: Optional[str] = None,
            logger: Optional[logging.Logger] = None,
            core_framework: Optional[Any] = None,
    ):
        """
        Initializes the WifiScanner.

        Args:
            interface (str, optional): Name of the network interface to use. Defaults to None.
                                        If None, the first available interface is used.
            logger (logging.Logger, optional): Logger instance for logging messages. Defaults to None.
            core_framework (CoreFramework, optional): Reference to the CoreFramework instance
                                                      for database operations. Defaults to None.
        """
        self.logger = logger or logging.getLogger(__name__)
        self.logger.debug("Initializing WifiScanner.")

        self.core = core_framework  # Reference to CoreFramework for database operations

        self.pywifi = PyWiFi()
        self.iface = self._get_interface(interface)

        if not self.iface:
            self.logger.error("No wireless interface found. WifiScanner initialization failed.")
            raise RuntimeError("No wireless interface found.")

        # Start the interface
        try:
            self.iface.scan()
            self.logger.debug("WifiScanner initialized successfully.")
        except Exception as e:
            self.logger.error(f"Failed to start scanning on interface {self.iface.name()}: {e}")
            raise e

    def _get_interface(self, interface_name: Optional[str] = None) -> Optional[Interface]:
        """
        Retrieves the specified network interface. If no interface name is provided,
        the first available interface is returned.

        Args:
            interface_name (str, optional): Name of the network interface to retrieve.

        Returns:
            Optional[Interface]: The pywifi Interface object if found, else None.
        """
        interfaces = self.pywifi.interfaces()
        self.logger.debug(f"Available interfaces: {[iface.name() for iface in interfaces]}")

        if interface_name:
            for iface in interfaces:
                if iface.name() == interface_name:
                    self.logger.debug(f"Using specified interface: {interface_name}")
                    return iface
            self.logger.warning(f"Interface '{interface_name}' not found. Using default interface.")

        if interfaces:
            default_iface = interfaces[0]
            self.logger.debug(f"Using default interface: {default_iface.name()}")
            return default_iface

        self.logger.error("No wireless interfaces available.")
        return None

    def _get_security(self, network) -> str:
        """
        Determines the security type of a Wi-Fi network.

        Args:
            network (pywifi.Profile): The Wi-Fi network profile.

        Returns:
            str: Security type (e.g., 'Open', 'WEP', 'WPA/WPA2').
        """
        auth = network.auth
        akm = network.akm
        cipher = network.cipher

        if auth == const.AUTH_ALG_OPEN:
            return "Open"
        elif auth == const.AKM_TYPE_NONE:
            return "WEP"
        elif auth in (const.AUTH_ALG_OPEN, const.AKM_TYPE_NONE):
            if akm:
                return "WPA/WPA2"
            else:
                return "WPA"
        else:
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
        elif 5170 <= freq <= 5825:
            return (freq - 5000) // 5
        else:
            return -1  # Unknown channel

    def _resolve_ip_hostname(self, mac: str) -> Dict[str, Optional[str]]:
        """
        Attempts to resolve IP and hostname from a MAC address.
        Note: This is a placeholder implementation. Actual resolution may require ARP tables
        or integration with network management tools.

        Args:
            mac (str): MAC address of the device.

        Returns:
            Dict[str, Optional[str]]: Dictionary containing 'ip' and 'hostname'.
        """
        # Placeholder implementation
        return {"ip": "N/A", "hostname": "N/A"}

    def scan_networks(self, scan_duration: int = 5) -> List[Dict[str, Any]]:
        """
        Scans for available Wi-Fi networks.

        Args:
            scan_duration (int, optional): Duration to wait for the scan to complete in seconds. Defaults to 5.

        Returns:
            List[Dict[str, Any]]: List of dictionaries containing SSID, BSSID, signal strength,
                                   channel, security, IP, MAC, and hostname.
        """
        self.logger.info("Starting Wi-Fi network scan...")
        try:
            self.iface.scan()
            time.sleep(scan_duration)  # Wait for the scan to complete
            results = self.iface.scan_results()
            self.logger.debug(f"Scan complete. {len(results)} networks found.")
        except Exception as e:
            self.logger.error(f"Failed to perform Wi-Fi scan: {e}")
            return []

        networks = []

        for network in results:
            security = self._get_security(network)
            channel = self._get_channel(network.freq)
            resolved = self._resolve_ip_hostname(network.bssid)

            network_info = {
                'ssid': network.ssid or "Hidden",
                'bssid': network.bssid,
                'ip': resolved.get('ip'),
                'mac': network.bssid,  # Assuming MAC is same as BSSID
                'hostname': resolved.get('hostname'),
                'signal': network.signal,
                'channel': channel,
                'security': security
            }
            networks.append(network_info)

            # Save the network to the universal pool
            if self.core:
                try:
                    self.core.add_target_to_pool(network_info)
                    self.logger.debug(f"Added network to pool: {network_info['ssid']} ({network_info['bssid']})")
                except Exception as e:
                    self.logger.error(f"Failed to add network to pool: {e}")

        self.logger.info(f"Wi-Fi scan completed. {len(networks)} networks found.")
        return networks
