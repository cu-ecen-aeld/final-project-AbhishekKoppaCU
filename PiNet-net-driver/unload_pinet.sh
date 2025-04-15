#!/bin/bash

# Gracefully unload the PiNet virtual driver

echo "[–] Bringing down pinet0..."
sudo ip link set pinet0 down 2>/dev/null

echo "[–] Flushing IP address from pinet0..."
sudo ip addr flush dev pinet0 2>/dev/null

echo "[–] Removing PiNet kernel module..."
sudo rmmod PiNet 2>/dev/null

if lsmod | grep -q PiNet; then
    echo "[✗] Failed to remove PiNet module."
else
    echo "[✓] PiNet module removed successfully."
fi

