#!/bin/sh
# Creates the system user of the service before the files land, so that
# /etc/tsigoat belongs to its group: with systemd-sysusers when the host runs
# systemd, with useradd otherwise.
set -e
if ! getent passwd tsigoat >/dev/null; then
  if command -v systemd-sysusers >/dev/null 2>&1; then
    echo 'u tsigoat - "tsigoat DNS update proxy" - -' |
      systemd-sysusers --replace=/usr/lib/sysusers.d/tsigoat.conf -
  else
    useradd --system --user-group --home-dir / --no-create-home \
      --shell /usr/sbin/nologin --comment "tsigoat DNS update proxy" tsigoat
  fi
fi
