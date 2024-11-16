#!/bin/bash

# Extract environment variables
HOST_NAME=${HOST_NAME:-mock_host}
SSID=${SSID:-TestNetwork}
BSSID=${BSSID:-AA:BB:CC:DD:EE:FF}
PASSWORD=${PASSWORD:-password123}
ENCRYPTION=${ENCRYPTION:-WPA2}
MAC_ADDRESS=${MAC_ADDRESS:-AA:BB:CC:DD:EE:FF}

# Set hostname with alternative command to set-hostname
echo $HOST_NAME > /etc/hostname
hostname $HOST_NAME

# Set MAC address

# Configure network interfaces if needed
# For simplicity, we'll skip actual wireless configurations
# You can extend this script to simulate wireless behaviors
# by using iwconfig, ifconfig, etc.

# Set up the network
echo "Setting up network with SSID: $SSID, BSSID: $BSSID, Password: $PASSWORD, Encryption: $ENCRYPTION, MAC Address: $MAC_ADDRESS"

# Keep the container running
tail -f /dev/null
