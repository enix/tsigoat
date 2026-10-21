#!/usr/bin/env python3
"""A webhook endpoint for tsigoat: a starting point, to complete.

tsigoat checks the keys and the policy of the DNS updates, then posts each
update to this endpoint, as JSON (docs/webhook.md describes the format). The
endpoint authenticates the request, then calls one function per operation:
add_record, delete_record, delete_rrset and delete_name. Complete them for
your DNS provider, or set TSIGOAT_WEBHOOK_COMMAND to a command that does the
work, such as a script around the command line tool of the provider.

Settings, from the environment:

    TSIGOAT_WEBHOOK_LISTEN    address to listen on, 127.0.0.1:8053 by default
    TSIGOAT_WEBHOOK_SECRET    secret of the signature of the requests
    TSIGOAT_WEBHOOK_USERNAME  user name and password of basic authentication
    TSIGOAT_WEBHOOK_PASSWORD
    TSIGOAT_WEBHOOK_TOKEN     bearer token
    TSIGOAT_WEBHOOK_COMMAND   command run for every operation, with the
                              operation as arguments; without it, the
                              operations are only logged

Set at least one of the secret, the user name and the token, as in the
configuration of tsigoat; every one that is set must match. Prefer the
signature, which also protects the content of the requests. The endpoint
refuses a request that comes twice, a replay, by its identifier: it remembers
the identifiers of the requests that it accepted for as long as their
timestamp lets them in. It forgets them when it stops: it refuses the requests
signed before it started, which a previous run may have accepted.

This is a starting point, not a service to expose: it serves plain HTTP, one
request at a time, which keeps the updates of a zone in order even when
tsigoat gave up waiting for the previous one. Keep it on the loopback, next to
tsigoat, or behind a proxy that serves HTTPS and bounds the connections.

An update succeeds when every operation does. When one fails, the endpoint
answers 500 and tsigoat SERVFAIL, but the operations before it stay applied:
undo them if the provider allows, or keep the operations idempotent, so that
the update converges when the client sends it again.

Requires Python 3.9 or later, and its standard library alone.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import shlex
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

LISTEN = os.environ.get("TSIGOAT_WEBHOOK_LISTEN", "127.0.0.1:8053")
SECRET = os.environ.get("TSIGOAT_WEBHOOK_SECRET", "")
USERNAME = os.environ.get("TSIGOAT_WEBHOOK_USERNAME", "")
PASSWORD = os.environ.get("TSIGOAT_WEBHOOK_PASSWORD", "")
TOKEN = os.environ.get("TSIGOAT_WEBHOOK_TOKEN", "")
COMMAND = shlex.split(os.environ.get("TSIGOAT_WEBHOOK_COMMAND", ""))

# A request signed more than this many seconds away from now is a replay, or
# comes from a host whose clock is off.
MAX_CLOCK_SKEW = 300
MAX_BODY_SIZE = 1 << 20
COMMAND_TIMEOUT = 30
# Bounds the wait for each read of a request, so that a client that stalls
# holds the endpoint for that long at most.
SOCKET_TIMEOUT = 10
# Bounds the identifiers that the endpoint remembers: beyond, it refuses the
# requests until the oldest identifiers expire.
MAX_RECENT_IDS = 10000

log = logging.getLogger("webhook")

# The second at which the endpoint started: a request signed before may have
# been accepted by a previous run, whose identifiers the endpoint forgot.
STARTED = int(time.time())


# The operations. Each one gets the zone and the canonical owner name, such as
# "_acme-challenge.www.example.com.", the record type, such as "TXT", and the
# RDATA in presentation format, such as '"value"' for a TXT record:
# txt_strings() decodes it. Raise an exception to fail the update.


def add_record(zone, name, rtype, ttl, rdata):
    """Adds a record; adding a record that exists changes nothing."""
    run("add", zone, name, rtype, str(ttl), rdata)


def delete_record(zone, name, rtype, rdata):
    """Deletes a record; deleting a missing record changes nothing."""
    run("delete-record", zone, name, rtype, rdata)


def delete_rrset(zone, name, rtype):
    """Deletes every record of a type at a name."""
    run("delete-rrset", zone, name, rtype)


def delete_name(zone, name):
    """Deletes every record of a name."""
    run("delete-name", zone, name)


def run(*args):
    """Runs TSIGOAT_WEBHOOK_COMMAND with the arguments, or logs them."""
    if not COMMAND:
        log.info("operation: %s", shlex.join(args))
        return
    subprocess.run([*COMMAND, *args], check=True, timeout=COMMAND_TIMEOUT)


def txt_strings(rdata):
    """Decodes the RDATA of a TXT record into its strings."""
    strings, current, quoted, i = [], None, False, 0
    while i < len(rdata):
        c = rdata[i]
        if c == "\\":
            if rdata[i + 1 : i + 4].isdigit():
                current = (current or "") + chr(int(rdata[i + 1 : i + 4]))
                i += 4
                continue
            current = (current or "") + rdata[i + 1]
            i += 2
            continue
        if c == '"':
            if quoted:
                strings.append(current or "")
                current = None
            quoted = not quoted
        elif quoted:
            current = (current or "") + c
        elif not c.isspace():
            current = (current or "") + c
        elif current is not None:
            strings.append(current)
            current = None
        i += 1
    if current is not None:
        strings.append(current)
    return strings


def apply(update):
    """Applies the operations of an update, in order."""
    zone = update["zone"]
    log.info("update %s of %s by key %r: %d operations", update["id"], zone, update["key"], len(update["operations"]))
    for op in update["operations"]:
        name, rtype = op["name"], op.get("type")
        if op["op"] == "add":
            add_record(zone, name, rtype, op["ttl"], op["rdata"])
        elif rtype is None:
            delete_name(zone, name)
        elif "rdata" in op:
            delete_record(zone, name, rtype, op["rdata"])
        else:
            delete_rrset(zone, name, rtype)


class RecentIDs:
    """The identifiers of the requests accepted lately, each one until its
    timestamp lets the request in no more: a request whose identifier comes
    again meanwhile is a replay."""

    def __init__(self, limit):
        self.limit = limit
        self.expiries = {}

    def admit(self, request_id, expiry):
        """Records an identifier until expiry, in seconds since the epoch.
        Returns the status that refuses the request: 409 for a replay, 429
        when the endpoint remembers too many identifiers; None to go on. Both
        are 4xx: the endpoint applies nothing."""
        now = time.time()
        self.expiries = {i: t for i, t in self.expiries.items() if t > now}
        if request_id in self.expiries:
            return 409
        if len(self.expiries) >= self.limit:
            return 429
        self.expiries[request_id] = expiry
        return None


RECENT_IDS = RecentIDs(MAX_RECENT_IDS)


class Handler(BaseHTTPRequestHandler):
    """Authenticates the updates of tsigoat, and applies them."""

    # The socket of a request waits that long for each read at most.
    timeout = SOCKET_TIMEOUT

    def do_POST(self):
        declared = self.headers.get("Content-Length")
        if declared is None:
            self.reply(411)
            return
        if not (declared.isascii() and declared.isdigit()):
            self.reply(400)
            return
        length = int(declared)
        if length > MAX_BODY_SIZE:
            self.reply(413)
            return
        body = self.rfile.read(length)
        if len(body) < length:
            # The client went away.
            return
        if not self.authenticated(body):
            self.reply(401)
            return
        try:
            update = json.loads(body)
        except ValueError:
            self.reply(400)
            return
        if not isinstance(update, dict) or update.get("version") != 1 or not valid_id(update.get("id")):
            log.warning("malformed update from %s", self.address_string())
            self.reply(400)
            return
        if self.signed_before_start():
            log.warning("update %s from %s refused: signed before the endpoint started", update["id"], self.address_string())
            self.reply(409)
            return
        refused = RECENT_IDS.admit(update["id"], self.expiry())
        if refused:
            reason = "replay" if refused == 409 else "too many recent requests"
            log.warning("update %s from %s refused: %s", update["id"], self.address_string(), reason)
            self.reply(refused)
            return
        try:
            apply(update)
        except Exception:  # every failure fails the update
            log.exception("the update %s failed", update["id"])
            self.reply(500)
            return
        self.reply(204)

    def expiry(self):
        """Returns when a replay of the request would fail the check of its
        timestamp: the end of the window of the timestamp of a signed request,
        of the current time otherwise."""
        now = time.time()
        timestamp = self.headers.get("X-Tsigoat-Timestamp", "")
        if SECRET and timestamp.isascii() and timestamp.isdigit():
            return max(int(timestamp), now) + MAX_CLOCK_SKEW
        return now + MAX_CLOCK_SKEW

    def signed_before_start(self):
        """Tells whether the request was signed before the endpoint started."""
        timestamp = self.headers.get("X-Tsigoat-Timestamp", "")
        return bool(SECRET) and int(timestamp) < STARTED

    def authenticated(self, body):
        """Checks every authentication that the settings ask for."""
        if SECRET and not self.signed(body):
            log.warning("bad signature from %s", self.address_string())
            return False
        if USERNAME and not equal(self.headers.get("Authorization", ""), basic_authorization()):
            log.warning("bad credentials from %s", self.address_string())
            return False
        if TOKEN and not equal(self.headers.get("Authorization", ""), "Bearer " + TOKEN):
            log.warning("bad token from %s", self.address_string())
            return False
        return True

    def signed(self, body):
        """Checks the signature: HMAC-SHA256 of the timestamp, ".", the body."""
        timestamp = self.headers.get("X-Tsigoat-Timestamp", "")
        if not (timestamp.isascii() and timestamp.isdigit()) or abs(time.time() - int(timestamp)) > MAX_CLOCK_SKEW:
            return False
        mac = hmac.new(SECRET.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
        return equal(self.headers.get("X-Tsigoat-Signature", ""), "sha256=" + mac.hexdigest())

    def reply(self, code):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002, the name of the base class
        log.info("%s %s", self.address_string(), format % args)


def basic_authorization():
    credentials = f"{USERNAME}:{PASSWORD}".encode()
    return "Basic " + base64.b64encode(credentials).decode()


def equal(a, b):
    """Compares secrets in constant time."""
    return hmac.compare_digest(a.encode(), b.encode())


def valid_id(value):
    """Tells whether a value is the identifier of a request: 32 hexadecimal
    digits."""
    return isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not (SECRET or USERNAME or TOKEN):
        sys.exit("set TSIGOAT_WEBHOOK_SECRET, TSIGOAT_WEBHOOK_USERNAME or TSIGOAT_WEBHOOK_TOKEN")
    if USERNAME and TOKEN:
        sys.exit("set TSIGOAT_WEBHOOK_USERNAME or TSIGOAT_WEBHOOK_TOKEN, not both")
    host, _, port = LISTEN.rpartition(":")
    host = host.strip("[]")

    class Server(HTTPServer):
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET

    server = Server((host, int(port)), Handler)
    log.info("listening on %s", LISTEN)
    if host not in ("127.0.0.1", "::1", "localhost"):
        log.warning(
            "%s is beyond the loopback: this example serves plain HTTP, one request at a time; "
            "put it behind a proxy that serves HTTPS and bounds the connections",
            LISTEN,
        )
    server.serve_forever()


if __name__ == "__main__":
    main()
