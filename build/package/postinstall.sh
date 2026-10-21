#!/bin/sh
# Loads the unit, and restarts the service on an upgrade if it runs.
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl try-restart tsigoat.service >/dev/null 2>&1 || true
fi
