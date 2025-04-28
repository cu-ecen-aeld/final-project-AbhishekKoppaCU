#!/bin/sh

case "$1" in
  start)
    echo "Starting receiver"
    /usr/bin/pinet_receiver &
    ;;
  stop)
    echo "Stopping  daemon"
    killall pinet_receiver
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
