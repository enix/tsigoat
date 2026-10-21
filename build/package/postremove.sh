#!/bin/sh
# Forgets the unit once it is gone. The system user stays, as it may own
# files that the package did not install.
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
