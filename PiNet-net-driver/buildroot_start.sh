#!/bin/sh
choose_group()
{
    if grep -q '^staff:' /etc/group; then
        echo "staff"
    else
        echo "wheel"
    fi
}
load_pinet()
{
    local modName="$1"
    local modFile="$2"
    local devName="$3"
    local iface="$4"
    local ip_addr="$5"
    local foundMajor
    if ! modprobe "$modName" 2>/dev/null; then
        echo "modprobe $modName failed, trying insmod $modFile"
        insmod "$modFile" || exit 1
    fi
    sleep 1
    foundMajor=$(dmesg | grep "Char device /dev/${devName}" | tail -n 1 | awk '{print $NF}')
    foundMajor=${foundMajor:-$(awk '$2=="'"$devName"'" {print $1}' /proc/devices)}
    if [ -z "$foundMajor" ]; then
        echo "Failed to determine major number for /dev/${devName}"
        return 1
    fi
    echo "[+] Creating /dev/${devName} with major $foundMajor"
    rm -f /dev/"$devName"
    mknod /dev/"$devName" c "$foundMajor" 0
    chgrp "$MAIN_GROUP" /dev/"$devName"
    chmod 666 /dev/"$devName"
    echo "[+] Bringing up interface $iface"
    ip link set "$iface" up
    echo "[+] Assigning IP $ip_addr to $iface"
    ip addr add "$ip_addr" dev "$iface"
}
unload_pinet()
{
    local modName="$1"
    local devName="$2"
    local iface="$3"
    echo "[–] Bringing down interface $iface"
    ip addr flush dev "$iface" 2>/dev/null || true
    ip link set "$iface" down 2>/dev/null || true
    echo "[–] Removing /dev/${devName}"
    rm -f /dev/"$devName"
    echo "[–] Removing module $modName"
    if ! modprobe -r "$modName" 2>/dev/null; then
        echo "modprobe -r $modName failed, trying rmmod"
        rmmod "$modName" || exit 1
    fi
}
MAIN_GROUP=$(choose_group)
[ $# -eq 1 ] || {
    echo "Usage: $0 {start|stop}"
    exit 1
}
case "$1" in
    start)
        echo "[+] Starting PiNet driver setup..."
        load_pinet "PiNet" "/lib/modules/$(uname -r)/extra/PiNet.ko" "pinet" "pinet0" "192.168.1.10/24"
        ;;
    stop)
        echo "[–] Stopping PiNet driver..."
        unload_pinet "PiNet" "pinet" "pinet0"
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
exit 0
