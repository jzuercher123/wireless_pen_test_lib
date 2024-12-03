from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import sys

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Beacon].network_stats().get("ssid", "Hidden")
        channel = int(ord(pkt[Dot11Elt:3].info))
        print(f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}")

def main():
    iface = "eth0"  # Replace with your monitor mode interface
    print(f"Scanning on interface {iface}...")
    sniff(iface=iface, prn=packet_handler, store=0)

if __name__ == "__main__":
    main()
