#!/bin/sh
# Stops and disables the service when the package goes away, but not on an
# upgrade: dpkg passes "remove", and rpm 0, then.
case "$1" in
  remove | 0)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now tsigoat.service >/dev/null 2>&1 || true
    fi
    ;;
esac
