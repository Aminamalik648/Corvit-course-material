#!/bin/bash

# MAC Address Masking Tool for Kali Linux
# Author: Amina

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./macmasker.sh"
    exit 1
fi

# Check if interface is provided
if [ -z "$1" ]; then
    echo "Usage: sudo ./macmasker.sh <interface>"
    exit 1
fi

INTERFACE=$1

# Bring the interface down
ip link set $INTERFACE down

# Change MAC address randomly
macchanger -r $INTERFACE

# Bring the interface up
ip link set $INTERFACE up

# Show current MAC
echo "Current MAC for $INTERFACE:"
macchanger -s $INTERFACE

echo "Done! Your MAC has been masked."
