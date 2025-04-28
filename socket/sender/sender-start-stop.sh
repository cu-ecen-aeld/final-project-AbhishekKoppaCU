#!/bin/sh

case "$1" in
  start)
    echo "Starting sender"
    /usr/bin/pinet_sender &
    ;;
  stop)
    echo "Stopping VNCL daemon"
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
