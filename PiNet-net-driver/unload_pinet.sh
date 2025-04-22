#!/bin/sh
set -e

DEVICE_NAME="pinet"

echo "[–] Bringing down pinet0..."
ip link set pinet0 down 2>/dev/null || true

echo "[–] Flushing IP address from pinet0..."
ip addr flush dev pinet0 2>/dev/null || true

echo "[–] Removing /dev/${DEVICE_NAME} (if exists)..."
if [ -e /dev/${DEVICE_NAME} ]; then
    rm -f /dev/${DEVICE_NAME}
    echo "[✓] /dev/${DEVICE_NAME} removed."
else
    echo "[i] /dev/${DEVICE_NAME} does not exist."
fi

echo "[–] Removing PiNet kernel module..."
rmmod PiNet 2>/dev/null || true

# Optionally confirm removal
if lsmod | grep -q PiNet; then
    echo "[✗] Failed to remove PiNet module."
else
    echo "[✓] PiNet module removed successfully."
fi

exit 0

