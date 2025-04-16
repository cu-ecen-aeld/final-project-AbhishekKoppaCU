#!/bin/bash

DEVICE_NAME="pinet"

# Load the PiNet kernel module
echo "[+] Inserting PiNet kernel module..."
sudo insmod PiNet.ko

# Wait briefly to ensure /dev creation logs are flushed
sleep 1

# Extract major number from dmesg
MAJOR=$(dmesg | grep "Char device /dev/${DEVICE_NAME}" | tail -n 1 | awk '{print $NF}')
MAJOR=${MAJOR:-$(grep ${DEVICE_NAME} /proc/devices | awk '{print $1}')}

if [[ -z "$MAJOR" ]]; then
    echo "[!] Failed to detect major number for /dev/${DEVICE_NAME}"
else
    # Create char device if not present
    if [[ ! -e /dev/${DEVICE_NAME} ]]; then
        echo "[+] Creating /dev/${DEVICE_NAME} with major $MAJOR..."
        sudo mknod /dev/${DEVICE_NAME} c $MAJOR 0
        sudo chmod 666 /dev/${DEVICE_NAME}
    else
        echo "[i] /dev/${DEVICE_NAME} already exists."
    fi
fi

# Bring up the virtual interface
echo "[+] Setting interface pinet0 UP..."
sudo ip link set pinet0 up

# Assign IP address to the interface
echo "[+] Assigning IP 192.168.1.10/24 to pinet0..."
sudo ip addr add 192.168.1.10/24 dev pinet0

# Show interface info
echo "[+] Current interface status:"
ip addr show dev pinet0

echo "[✓] PiNet virtual network + char driver setup complete!"

