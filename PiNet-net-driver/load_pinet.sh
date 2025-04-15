#!/bin/bash

# Load the PiNet kernel module
echo "[+] Inserting PiNet kernel module..."
sudo insmod PiNet.ko

# Bring up the virtual interface
echo "[+] Setting interface pinet0 UP..."
sudo ip link set pinet0 up

# Assign IP address to the interface
echo "[+] Assigning IP 192.168.1.10/24 to pinet0..."
sudo ip addr add 192.168.1.10/24 dev pinet0

# Show interface info
echo "[+] Current interface status:"
ip addr show dev pinet0

echo "[✓] PiNet virtual network interface setup complete!"

