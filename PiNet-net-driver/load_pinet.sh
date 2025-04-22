#!/bin/sh
set -e

module="PiNet"
device="pinet"
mode="666"
ip_addr="192.168.1.10/24"
iface="pinet0"

# Detect group: use staff if available, otherwise wheel
if grep -q '^staff:' /etc/group; then
    group="staff"
else
    group="wheel"
fi

# Load kernel module
if [ -e "${module}.ko" ]; then
    echo "[+] Inserting locally built ${module}.ko..."
    insmod "./${module}.ko"
else
    echo "[i] ${module}.ko not found locally, trying modprobe..."
    modprobe "${module}"
fi

# Wait for logs to flush
sleep 1

# Extract major number
major=$(dmesg | grep "Char device /dev/${device}" | tail -n 1 | awk '{print $NF}')
major=${major:-$(grep "${device}" /proc/devices | awk '{print $1}')}

if [ -z "$major" ]; then
    echo "[!] Failed to detect major number for /dev/${device}"
    exit 1
fi

# Create /dev entry
if [ ! -e "/dev/${device}" ]; then
    echo "[+] Creating /dev/${device} with major $major..."
    rm -f "/dev/${device}"
    mknod "/dev/${device}" c "$major" 0
    chgrp "$group" "/dev/${device}"
    chmod "$mode" "/dev/${device}"
else
    echo "[i] /dev/${device} already exists."
fi

# Setup network interface
echo "[+] Bringing up $iface..."
ip link set "$iface" up

echo "[+] Assigning IP $ip_addr to $iface..."
ip addr add "$ip_addr" dev "$iface"

echo "[✓] ${module} network + char device setup complete."

