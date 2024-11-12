#!/usr/bin/env python3
import subprocess
import re
from scapy.all import srp, conf
from scapy.layers.l2 import ARP, Ether
import netifaces
import sys
import logging
import argparse

# Configure logging
logger = logging.getLogger('NetworkScanner')

def setup_logging(level):
    """
    Sets up logging with the specified level.
    """
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        print(f"Invalid log level: {level}")
        sys.exit(1)
    logging.basicConfig(
        level=numeric_level,
        format='[%(asctime)s] %(levelname)s - %(name)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def scan_wireless_networks(interface='wlan0'):
    """
    Scans for wireless networks using iwlist.

    Args:
        interface (str): The wireless interface to scan.

    Returns:
        List[dict]: A list of dictionaries containing SSID, BSSID, Signal Level, and Channel.
    """
    logger.info(f"Scanning for wireless networks on interface: {interface}")
    try:
        # Execute iwlist scan command
        scan_output = subprocess.check_output(['iwlist', interface, 'scanning'], stderr=subprocess.STDOUT, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to execute iwlist: {e.output}")
        return []

    # Parse the output
    cells = scan_output.split('Cell ')
    networks = []

    for cell in cells[1:]:
        ssid_search = re.search(r'ESSID:"(.*)"', cell)
        ssid = ssid_search.group(1) if ssid_search else 'Hidden'

        bssid_search = re.search(r'Address: ([\w:]+)', cell)
        bssid = bssid_search.group(1) if bssid_search else 'Unknown'

        signal_search = re.search(r'Signal level=(-?\d+) dBm', cell)
        signal = signal_search.group(1) + ' dBm' if signal_search else 'N/A'

        channel_search = re.search(r'Channel:(\d+)', cell)
        channel = channel_search.group(1) if channel_search else 'N/A'

        networks.append({
            'SSID': ssid,
            'BSSID': bssid,
            'Signal': signal,
            'Channel': channel
        })

    logger.info(f"Found {len(networks)} wireless networks.")
    return networks

def get_default_gateway_ip():
    """
    Retrieves the default gateway IP address.

    Returns:
        str: The default gateway IP.
    """
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default')
    if default_gateway is None:
        logger.error("No default gateway found.")
        sys.exit(1)
    gateway_ip = default_gateway[netifaces.AF_INET][0]
    return gateway_ip

def get_network_prefix(interface):
    """
    Retrieves the network prefix (e.g., 192.168.1.0/24).

    Args:
        interface (str): The network interface.

    Returns:
        str: The network prefix.
    """
    addrs = netifaces.ifaddresses(interface)
    inet = addrs.get(netifaces.AF_INET)
    if not inet:
        logger.error(f"No IPv4 address found for interface {interface}.")
        sys.exit(1)
    ip_info = inet[0]
    ip_address = ip_info.get('addr')
    netmask = ip_info.get('netmask')
    if not ip_address or not netmask:
        logger.error(f"IP address or netmask not found for interface {interface}.")
        sys.exit(1)
    # Calculate CIDR notation
    cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
    network_prefix = f"{ip_address}/{cidr}"
    return network_prefix

def scan_local_network(interface='eth0'):
    """
    Scans the local network for active devices using ARP requests.

    Args:
        interface (str): The network interface to use for scanning.

    Returns:
        List[dict]: A list of dictionaries containing IP and MAC addresses.
    """
    logger.info(f"Scanning local network on interface: {interface}")
    network = get_network_prefix(interface)
    logger.debug(f"Network prefix: {network}")

    # Create ARP packet
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Disable verbose in scapy
    conf.verb = 0

    try:
        result = srp(packet, timeout=3, iface=interface, inter=0.1)[0]
    except Exception as e:
        logger.error(f"Error during ARP scan: {e}")
        return []

    devices = []
    for sent, received in result:
        devices.append({
            'IP': received.psrc,
            'MAC': received.hwsrc
        })

    logger.info(f"Found {len(devices)} devices on the local network.")
    return devices

def get_active_interfaces():
    """
    Retrieves active network interfaces.

    Returns:
        List[str]: A list of active network interface names.
    """
    interfaces = netifaces.interfaces()
    active_interfaces = []
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            active_interfaces.append(interface)
    return active_interfaces

def display_wireless_networks(networks):
    """
    Displays the list of wireless networks.

    Args:
        networks (List[dict]): List of wireless networks.
    """
    if not networks:
        logger.info("No wireless networks found.")
        return

    print("\n=== Wireless Networks ===")
    print(f"{'SSID':<30} {'BSSID':<20} {'Signal':<10} {'Channel':<8}")
    print("-" * 70)
    for net in networks:
        print(f"{net['SSID']:<30} {net['BSSID']:<20} {net['Signal']:<10} {net['Channel']:<8}")

def display_local_devices(devices):
    """
    Displays the list of devices on the local network.

    Args:
        devices (List[dict]): List of devices with IP and MAC addresses.
    """
    if not devices:
        logger.info("No devices found on the local network.")
        return

    print("\n=== Local Network Devices ===")
    print(f"{'IP Address':<20} {'MAC Address':<20}")
    print("-" * 40)
    for device in devices:
        print(f"{device['IP']:<20} {device['MAC']:<20}")

def parse_arguments():
    """
    Parses command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Network Devices Scanner Utility")
    parser.add_argument(
        '-w', '--wireless-interface',
        type=str,
        default=None,
        help="Specify the wireless interface to scan (e.g., wlan0). If not provided, the script will auto-detect."
    )
    parser.add_argument(
        '-e', '--ethernet-interface',
        type=str,
        default=None,
        help="Specify the Ethernet interface to scan (e.g., eth0). If not provided, the script will auto-detect."
    )
    parser.add_argument(
        '-l', '--log-level',
        type=str,
        default='INFO',
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Default is INFO."
    )
    return parser.parse_args()

def main():
    args = parse_arguments()
    setup_logging(args.log_level)

    # Determine active wireless interface
    active_interfaces = get_active_interfaces()
    wireless_interfaces = [iface for iface in active_interfaces if 'wlan' in iface]

    if args.wireless_interface:
        wireless_interface = args.wireless_interface
        if wireless_interface not in wireless_interfaces:
            logger.error(f"Specified wireless interface '{wireless_interface}' is not active or not found.")
            sys.exit(1)
    else:
        if not wireless_interfaces:
            logger.error("No wireless interfaces found. Ensure your wireless adapter is connected.")
            sys.exit(1)
        wireless_interface = wireless_interfaces[0]

    networks = scan_wireless_networks(interface=wireless_interface)
    display_wireless_networks(networks)

    # Determine active Ethernet interface for local network scan
    ethernet_interfaces = [iface for iface in active_interfaces if 'eth' in iface or 'enp' in iface or 'eno' in iface]
    if args.ethernet_interface:
        ethernet_interface = args.ethernet_interface
        if ethernet_interface not in ethernet_interfaces:
            logger.error(f"Specified Ethernet interface '{ethernet_interface}' is not active or not found.")
            sys.exit(1)
    else:
        if not ethernet_interfaces:
            logger.error("No Ethernet interfaces found. Ensure you are connected to a network.")
            sys.exit(1)
        ethernet_interface = ethernet_interfaces[0]

    devices = scan_local_network(interface=ethernet_interface)
    display_local_devices(devices)

if __name__ == "__main__":
    main()
