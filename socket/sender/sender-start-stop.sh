#!/bin/sh

case "$1" in
  start)
    echo "Starting sender"
    /usr/bin/pinet_sender 172.20.10.4 wlan0 &
    ;;
  stop)
    echo "Stopping  daemon"
    killall pinet_sender
    ;;
  restart)
    $0 stop
    $0 start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
esac

exit 0
