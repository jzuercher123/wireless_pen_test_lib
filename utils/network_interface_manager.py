# wireless_pen_test_lib/utils/network_interface_manager.py

import subprocess
import logging

class NetworkInterfaceManager:
    def __init__(self, interface: str = "wlan0mon"):
        """
        Initialize the NetworkInterfaceManager with the specified interface.

        Args:
            interface (str): Name of the wireless interface.
        """
        if not self.is_valid_interface(interface):
            raise ValueError(f"Invalid network interface: {interface}")
        self.interface = interface
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info(f"NetworkInterfaceManager initialized for interface: {self.interface}")

    def is_valid_interface(self, interface: str) -> bool:
        available_interfaces = self.get_available_interfaces()
        return interface in available_interfaces

    def get_available_interfaces(self) -> list:
        # This should be replaced with actual system call to list interfaces
        return ['wlan0mon', 'eth0', 'lo']

    def get_interface_mac(self) -> str:
        """
        Retrieves the MAC address of the wireless interface.

        Returns:
            str: MAC address of the interface.
        """
        try:
            result = subprocess.check_output(["ifconfig", self.interface], stderr=subprocess.STDOUT).decode()
            mac_address = result.split("ether ")[1].split(" ")[0]
            return mac_address
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get MAC address: {e.output.decode()}")
            return "00:00:00:00:00:00"

    def set_monitor_mode(self):
        """
        Sets the wireless interface to monitor mode.
        """
        self.logger.info(f"Setting interface {self.interface} to monitor mode.")
        try:
            subprocess.run(["sudo", "ifconfig", self.interface, "down"], check=True)
            subprocess.run(["sudo", "iwconfig", self.interface, "mode", "monitor"], check=True)
            subprocess.run(["sudo", "ifconfig", self.interface, "up"], check=True)
            self.logger.info(f"Interface {self.interface} set to monitor mode successfully.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to set monitor mode: {e}")
            raise e

    def set_managed_mode(self):
        """
        Sets the wireless interface to managed mode.
        """
        self.logger.info(f"Setting interface {self.interface} to managed mode.")
        try:
            subprocess.run(["sudo", "ifconfig", self.interface, "down"], check=True)
            subprocess.run(["sudo", "iwconfig", self.interface, "mode", "managed"], check=True)
            subprocess.run(["sudo", "ifconfig", self.interface, "up"], check=True)
            self.logger.info(f"Interface {self.interface} set to managed mode successfully.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to set managed mode: {e}")
            raise e

    def get_interface_status(self) -> str:
        """
        Retrieves the current status of the wireless interface.

        Returns:
            str: Current mode of the interface (e.g., Monitor, Managed).
        """
        try:
            result = subprocess.check_output(["iwconfig", self.interface], stderr=subprocess.STDOUT).decode()
            if "Mode:Monitor" in result:
                return "Monitor Mode"
            elif "Mode:Managed" in result:
                return "Managed Mode"
            else:
                return "Unknown Mode"
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get interface status: {e.output.decode()}")
            return "Unknown Mode"