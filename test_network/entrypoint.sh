# test_network/entrypoint.sh

#!/bin/bash

# Extract environment variables
HOST_NAME=${HOST_NAME:-mock_host}
SSID=${SSID:-TestNetwork}
BSSID=${BSSID:-AA:BB:CC:DD:EE:FF}
PASSWORD=${PASSWORD:-password123}
ENCRYPTION=${ENCRYPTION:-WPA2}
MAC_ADDRESS=${MAC_ADDRESS:-AA:BB:CC:DD:EE:FF}

# Set hostname
hostnamectl set-hostname $HOST_NAME

# Configure network interfaces if needed
# For simplicity, we'll skip actual wireless configurations
# You can extend this script to simulate wireless behaviors

# Keep the container running
tail -f /dev/null
