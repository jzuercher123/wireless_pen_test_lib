# scanners/local_scanner.py

import subprocess
import netifaces
import logging
import os
import platform
from typing import List, Optional, Dict, Any
import pandas as pd
import ipaddress
import socket
from scapy.all import srp, conf
from scapy.layers.l2 import ARP, Ether

class LocalScanner:
    def __init__(self, core_framework, interface: str):
        """
        Initialize the LocalScanner with the CoreFramework instance and network interface.

        Args:
            core_framework (CoreFramework): An instance of CoreFramework.
            interface (str): The network interface to scan.
        """
        self.core_framework = core_framework
        self.interface = interface
        self.logger = self.core_framework.logger.getChild(self.__class__.__name__)
        self.os_type = platform.system()
        self.logger.debug(f"Operating System detected: {self.os_type}")

    def is_wireless_interface(self) -> bool:
        """
        Determine if the interface is wireless.

        Returns:
            bool: True if wireless, False otherwise.
        """
        try:
            if self.os_type == "Linux":
                wireless_path = f"/sys/class/net/{self.interface}/wireless"
                is_wireless = os.path.exists(wireless_path)
                self.logger.debug(f"Wireless path {wireless_path} exists: {is_wireless}")
                return is_wireless
            elif self.os_type == "Darwin":  # macOS
                result = subprocess.run(
                    ["networksetup", "-listallhardwareports"],
                    capture_output=True, text=True, check=True
                )
                interfaces = result.stdout.split("\n\n")
                for iface in interfaces:
                    if f"Device: {self.interface}" in iface:
                        if "Wi-Fi" in iface or "AirPort" in iface:
                            self.logger.debug(f"Interface {self.interface} is wireless on macOS.")
                            return True
                self.logger.debug(f"Interface {self.interface} is not wireless on macOS.")
                return False
            elif self.os_type == "Windows":
                # WSL2 is running Linux; wireless interface detection not applicable
                self.logger.debug("Windows interface check called from WSL2; returning False.")
                return False
            else:
                self.logger.warning(f"Unsupported OS for wireless check: {self.os_type}")
                return False
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error checking wireless interface: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error in is_wireless_interface: {e}")
            return False

    def set_monitor_mode(self):
        """
        Set the interface to monitor mode if it's wireless.
        """
        if self.is_loopback_interface():
            self.logger.info("Loopback interface detected. Skipping monitor mode setup.")
            return

        if not self.is_wireless_interface():
            self.logger.info(f"Interface '{self.interface}' is not a wireless interface. Skipping monitor mode setup.")
            return

        try:
            if self.os_type == "Linux":
                self.logger.info(f"Setting interface {self.interface} to monitor mode on Linux.")
                subprocess.run(["sudo", "ifconfig", self.interface, "down"], check=True)
                subprocess.run(["sudo", "iwconfig", self.interface, "mode", "monitor"], check=True)
                subprocess.run(["sudo", "ifconfig", self.interface, "up"], check=True)
                self.logger.info(f"Interface {self.interface} set to monitor mode successfully on Linux.")
            elif self.os_type == "Darwin":
                self.logger.info(f"Setting interface {self.interface} to monitor mode on macOS.")
                # macOS uses different commands, such as `airport`
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                if not os.path.exists(airport_path):
                    self.logger.error("airport utility not found on macOS.")
                    return
                subprocess.run(["sudo", airport_path, "--disassociate"], check=True)
                subprocess.run(["sudo", "ifconfig", self.interface, "down"], check=True)
                subprocess.run(["sudo", "ifconfig", self.interface, "up"], check=True)
                # macOS does not support monitor mode in the same way as Linux
                self.logger.warning("Monitor mode setup on macOS might require additional steps.")
            else:
                self.logger.warning(f"Monitor mode setup not supported on OS: {self.os_type}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to set monitor mode: {e}")
            raise e
        except Exception as e:
            self.logger.error(f"Unexpected error in set_monitor_mode: {e}")
            raise e

    def bring_interface_up(self):
        """
        Bring the network interface up.
        """
        try:
            self.logger.info(f"Bringing interface {self.interface} up.")
            if self.os_type == "Windows":
                subprocess.run(["netsh", "interface", "set", "interface", self.interface, "enabled"], check=True)
            else:
                subprocess.run(["sudo", "ifconfig", self.interface, "up"], check=True)
            self.logger.info(f"Interface {self.interface} is up.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to bring interface up: {e}")
            raise e

    def bring_interface_down(self):
        """
        Bring the network interface down.
        """
        try:
            self.logger.info(f"Bringing interface {self.interface} down.")
            if self.os_type == "Windows":
                subprocess.run(["netsh", "interface", "set", "interface", self.interface, "disabled"], check=True)
            else:
                subprocess.run(["sudo", "ifconfig", self.interface, "down"], check=True)
            self.logger.info(f"Interface {self.interface} is down.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to bring interface down: {e}")
            raise e

    def get_interface_details(self) -> Optional[List[Dict[str, Any]]]:
        """
        Retrieve details about the network interface.

        Returns:
            Optional[List[Dict[str, Any]]]: List of interface details or None if an error occurs.
        """
        try:
            addrs = netifaces.ifaddresses(self.interface)
            details = []
            for family, addr_info_list in addrs.items():
                for addr_info in addr_info_list:
                    entry = {
                        'Family': netifaces.address_families.get(family, family),
                        'Address': addr_info.get('addr', '')
                    }
                    details.append(entry)
            # Append wireless status
            details.append({'Family': 'Wireless', 'Address': self.is_wireless_interface()})
            self.logger.debug(f"Interface details for {self.interface}: {details}")
            return details
        except ValueError:
            self.logger.error(f"Interface {self.interface} not found.")
            return None
        except Exception as e:
            self.logger.error(f"Error retrieving interface details: {e}")
            return None

    def is_loopback_interface(self) -> bool:
        """
        Determine if the interface is a loopback interface.

        Returns:
            bool: True if loopback, False otherwise.
        """
        try:
            details = netifaces.ifaddresses(self.interface)
            # Check for loopback by examining the addresses
            for family in (netifaces.AF_INET, netifaces.AF_INET6):
                if family in details:
                    for addr_info in details[family]:
                        if addr_info.get('addr') in ('127.0.0.1', '::1'):
                            self.logger.debug(f"Interface {self.interface} is a loopback interface.")
                            return True
            self.logger.debug(f"Interface {self.interface} is not a loopback interface.")
            return False
        except ValueError:
            self.logger.error(f"Interface {self.interface} not found.")
            return False
        except Exception as e:
            self.logger.error(f"Error determining if interface is loopback: {e}")
            return False

    @staticmethod
    def list_interfaces() -> List[str]:
        """
        List all available network interfaces.

        Returns:
            List[str]: List of interface names.
        """
        try:
            interfaces = netifaces.interfaces()
            logging.getLogger("LocalScanner").debug(f"Available interfaces: {interfaces}")
            return interfaces
        except Exception as e:
            logging.getLogger("LocalScanner").error(f"Error listing interfaces: {e}")
            return []

    def scan(self) -> Dict[str, Any]:
        """
        Scan the local network for devices.

        Returns:
            Dict[str, Any]: Dictionary containing the list of detected devices.
        """
        self.logger.info("Starting local network scan for devices...")

        # Determine network range
        try:
            addrs = netifaces.ifaddresses(self.interface)
            inet_info = addrs.get(netifaces.AF_INET)
            if not inet_info:
                self.logger.error(f"No IPv4 address found for interface {self.interface}.")
                return {"devices": []}

            ip_address = inet_info[0].get('addr')
            netmask = inet_info[0].get('netmask')
            if not ip_address or not netmask:
                self.logger.error(f"IP address or netmask not found for interface {self.interface}.")
                return {"devices": []}

            # Calculate network
            network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
            self.logger.debug(f"Calculated network range: {network}")
        except Exception as e:
            self.logger.error(f"Error determining network range: {e}")
            return {"devices": []}

        # Perform ARP scan using Scapy
        try:
            # Create ARP request
            arp = ARP(pdst=str(network))
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            self.logger.info(f"Sending ARP requests to {network}...")
            # Disable verbose in Scapy
            conf.verb = 0
            answered, unanswered = srp(packet, timeout=2, iface=self.interface, inter=0.1)

            devices = []
            for sent, received in answered:
                device = {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "hostname": self.get_hostname(received.psrc),
                    "ssid": self.get_ssid(),
                    "bssid": self.get_bssid()
                }
                devices.append(device)
                self.logger.debug(f"Discovered device: {device}")

            self.logger.info(f"ARP scan completed. {len(devices)} devices found.")
            return {"devices": devices}
        except PermissionError:
            self.logger.error("Permission denied: ARP scan requires elevated privileges.")
            return {"devices": []}
        except Exception as e:
            self.logger.error(f"Error during ARP scan: {e}")
            return {"devices": []}

    def get_hostname(self, ip: str) -> str:
        """
        Perform reverse DNS lookup to get the hostname of an IP address.

        Args:
            ip (str): The IP address.

        Returns:
            str: The hostname or "N/A" if not found.
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            self.logger.debug(f"Hostname for IP {ip}: {hostname}")
            return hostname
        except socket.herror:
            self.logger.debug(f"Hostname not found for IP {ip}.")
            return "N/A"
        except Exception as e:
            self.logger.error(f"Error performing reverse DNS for IP {ip}: {e}")
            return "N/A"

    def get_ssid(self) -> str:
        """
        Retrieve the SSID of the wireless network.

        Returns:
            str: The SSID or "N/A" if not applicable.
        """
        if not self.is_wireless_interface():
            return "N/A"

        try:
            if self.os_type == "Linux":
                result = subprocess.run(
                    ["iwgetid", "-r"],
                    capture_output=True, text=True, check=True
                )
                ssid = result.stdout.strip()
                self.logger.debug(f"Retrieved SSID on Linux: {ssid}")
                return ssid if ssid else "N/A"
            elif self.os_type == "Darwin":
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                if not os.path.exists(airport_path):
                    self.logger.error("airport utility not found on macOS.")
                    return "N/A"
                result = subprocess.run(
                    [airport_path, "-I"],
                    capture_output=True, text=True, check=True
                )
                for line in result.stdout.split("\n"):
                    if " SSID:" in line:
                        ssid = line.split("SSID:")[1].strip()
                        self.logger.debug(f"Retrieved SSID on macOS: {ssid}")
                        return ssid if ssid else "N/A"
                self.logger.debug("SSID not found in airport output on macOS.")
                return "N/A"
            else:
                self.logger.warning(f"SSID retrieval not supported on OS: {self.os_type}")
                return "N/A"
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error retrieving SSID: {e}")
            return "N/A"
        except Exception as e:
            self.logger.error(f"Unexpected error retrieving SSID: {e}")
            return "N/A"

    def get_bssid(self) -> str:
        """
        Retrieve the BSSID of the wireless network.

        Returns:
            str: The BSSID or "N/A" if not applicable.
        """
        if not self.is_wireless_interface():
            return "N/A"

        try:
            if self.os_type == "Linux":
                result = subprocess.run(
                    ["iwconfig", self.interface],
                    capture_output=True, text=True, check=True
                )
                for line in result.stdout.split("\n"):
                    if "Access Point:" in line:
                        bssid = line.split("Access Point:")[1].strip()
                        self.logger.debug(f"Retrieved BSSID on Linux: {bssid}")
                        return bssid if bssid else "N/A"
                self.logger.debug("BSSID not found in iwconfig output on Linux.")
                return "N/A"
            elif self.os_type == "Darwin":
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                if not os.path.exists(airport_path):
                    self.logger.error("airport utility not found on macOS.")
                    return "N/A"
                result = subprocess.run(
                    [airport_path, "-I"],
                    capture_output=True, text=True, check=True
                )
                for line in result.stdout.split("\n"):
                    if " BSSID:" in line:
                        bssid = line.split("BSSID:")[1].strip()
                        self.logger.debug(f"Retrieved BSSID on macOS: {bssid}")
                        return bssid if bssid else "N/A"
                self.logger.debug("BSSID not found in airport output on macOS.")
                return "N/A"
            else:
                self.logger.warning(f"BSSID retrieval not supported on OS: {self.os_type}")
                return "N/A"
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error retrieving BSSID: {e}")
            return "N/A"
        except Exception as e:
            self.logger.error(f"Unexpected error retrieving BSSID: {e}")
            return "N/A"




def main():
    # Configure logging
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s:%(message)s')
    logger = logging.getLogger("LocalScanner")

    # List available interfaces
    available_interfaces = LocalScanner.list_interfaces()

    if not available_interfaces:
        print("No network interfaces found.")
        return

    # Create a DataFrame for available interfaces
    interfaces_df = pd.DataFrame({
        'Index': range(1, len(available_interfaces) + 1),
        'Interface Name': available_interfaces
    })

    print("Available Network Interfaces:")
    print(interfaces_df.to_string(index=False))

    # Prompt the user to select an interface
    try:
        selected_idx = int(input(f"\nSelect an interface [1-{len(available_interfaces)}]: "))
        if not 1 <= selected_idx <= len(available_interfaces):
            raise ValueError
        selected_interface = available_interfaces[selected_idx - 1]
    except ValueError:
        print("Invalid selection. Please enter a valid number corresponding to the listed interfaces.")
        return

    # Initialize the LocalScanner with the selected interface
    scanner = LocalScanner(core_framework=None, interface=selected_interface)  # Replace 'None' with actual CoreFramework instance

    # Attempt to set monitor mode
    scanner.set_monitor_mode()

    # Retrieve and display interface details
    details = scanner.get_interface_details()
    if details is None:
        print("Failed to retrieve interface details.")
        return

    # Convert details to DataFrame
    details_df = pd.DataFrame(details)

    print("\nInterface Details:")
    print(details_df.to_string(index=False))


if __name__ == "__main__":
    main()
