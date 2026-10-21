# Webhooks

When tsigoat has no backend for a DNS provider, a webhook fills the gap.
tsigoat authenticates the clients, checks the policy of every update, then
posts the update to an HTTP endpoint of yours, which applies it with whatever
the provider offers, such as its command line tool.
[examples/webhook/webhook.py](../examples/webhook/webhook.py) is a starting
point, in Python.

```yaml
backends:
  - name: provider
    type: webhook
    webhook:
      url: https://hooks.example.com/tsigoat
      signature:
        secretFile: /run/secrets/tsigoat/webhook
zones:
  - name: example.com.
    backend: provider
    policy:
      - key: cert-manager.
        acme: ["example.com.", "**.example.com."]
```

[Configuration](configuration.md#backends) lists every setting.

## Requests

tsigoat posts each update as one JSON request:

```json
{
  "version": 1,
  "id": "6f0d9ab4c2e1f8a35b7c0d1e2f3a4b5c",
  "zone": "example.com.",
  "key": "cert-manager.",
  "operations": [
    {"op": "add", "name": "_acme-challenge.www.example.com.", "type": "TXT", "ttl": 60, "rdata": "\"value\""},
    {"op": "delete", "name": "_acme-challenge.www.example.com.", "type": "TXT", "rdata": "\"value\""},
    {"op": "delete", "name": "_acme-challenge.www.example.com.", "type": "TXT"},
    {"op": "delete", "name": "old.example.com."}
  ]
}
```

| Field | Content |
| --- | --- |
| `version` | `1`, the version of this format |
| `id` | 128 random bits in hexadecimal, unique to each request: an endpoint recognizes a request that comes twice, a replay, and names the request in its logs |
| `zone` | The zone of the update |
| `key` | The key that signed the update; empty for an unsigned update |
| `operations` | The operations, to apply in order |

| Operation | Meaning |
| --- | --- |
| `add`, with `type`, `ttl` and `rdata` | Adds a record; adding a record that exists changes nothing |
| `delete`, with `type` and `rdata` | Deletes one record |
| `delete`, with `type` | Deletes every record of the type at the name |
| `delete` alone | Deletes every record of the name |

Names are fully qualified and in lower case. Types are mnemonics, such as
`TXT`, or `TYPE65534` for the types that tsigoat does not know. `rdata` is the
RDATA in presentation format, as zone files write it: the strings of a TXT
record come in double quotes.

## Responses

The status of the response is the answer of the endpoint: tsigoat does not
wait for the body of a success.

| Status | Means | The client gets |
| --- | --- | --- |
| 2xx | The update applied whole | NOERROR |
| 4xx | The endpoint applied nothing, such as for a request that it refuses | SERVFAIL |
| 5xx | The update may have applied in part, or whole, or not at all | SERVFAIL, and an unknown outcome |

The client gets SERVFAIL too when the endpoint does not answer within the
`timeout` of the backend, from the connection to the end of the response, or
when the connection or TLS fails. The log entry of the update gives the status
and the beginning of the body, and the
[TsigoatBackendErrors](operations.md#tsigoatbackenderrors) alert fires when
the failures last.

A request may fail after it reached the endpoint: the response does not come
in time, the connection breaks, the endpoint fails after it applied part of
the update, or a gateway answers 502 or 504 for an endpoint that broke off or
took too long. The endpoint may have applied the update then, or may apply it
still: the update log tells that the outcome is unknown, and the
[TsigoatUncertainUpdates](operations.md#tsigoatuncertainupdates) alert fires.
A client that sends its update again brings it to its end, when the endpoint
keeps its operations idempotent. An endpoint answers 4xx only when it applied
nothing, and 5xx otherwise.

## Contract

The endpoint:

- applies the operations of a request in order, all or nothing when it can;
  otherwise, it keeps them idempotent, so that an update converges when the
  client sends it again;
- applies the updates of a zone one at a time, in the order they arrive;
- answers within the timeout of the backend, five seconds by default;
- accepts a request without operations, without changing anything:
  `tsigoat check-config --backends` and the start of tsigoat send one per
  zone, to check that the endpoint answers and accepts their authentication;
- authenticates the requests, and refuses their replays, see below.

tsigoat, for its part:

- sends the updates of a zone one at a time, while the endpoint answers
  within the timeout. After a timeout, tsigoat sends the next update of the
  zone, though the endpoint may still apply the previous one, and several
  instances of tsigoat send theirs side by side: only the endpoint can keep
  the updates of a zone apart, as the example does, which handles one
  request at a time;
- refuses the updates with prerequisites, with REFUSED: their evaluation needs
  the content of the zone, which tsigoat does not read;
- leaves out the deletions that RFC 2136 ignores whatever the state of the
  zone, of the SOA and of the NS records of the apex, and refuses the
  deletion of every record of the apex, which spares the SOA and the NS
  records;
- answers the SOA queries of the zones with an SOA of its own, with serial 1:
  clients only use it to find the zone of a name.

The rest of RFC 2136, which depends on the content of the zone, is the job of
the endpoint and of the provider: a CNAME alone at its name, a SOA serial that
only grows, the last NS record of the apex kept. ACME challenges, which add
and delete TXT records, need none of it.

## Authentication

The endpoint should accept the requests of tsigoat alone. `signature` signs
them; `basicAuth` or `bearer` adds credentials, which may come on top of the
signature; `headers` adds any header, such as an API key that a gateway
expects.

With `signature`, every request carries two headers:

| Header | Content |
| --- | --- |
| `X-Tsigoat-Timestamp` | The time of the request, in seconds since the Unix epoch |
| `X-Tsigoat-Signature` | `sha256=` and the hexadecimal HMAC-SHA256, with the secret, of the timestamp, a period and the body |

The endpoint computes the same HMAC, compares it in constant time, and refuses
the timestamps more than five minutes away from its clock. In Python:

```python
mac = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256)
valid = hmac.compare_digest(signature, "sha256=" + mac.hexdigest())
valid = valid and abs(time.time() - int(timestamp)) <= 300
```

The timestamp bounds the age of a replay, but does not stop one: within the
five minutes, a request that someone captured and sends again, after a later
update that undid it, passes the signature and the timestamp. The endpoint
refuses replays by their `id`, which the signature covers: it remembers the
identifiers of the requests that it accepted for as long as their timestamp
lets them in, and refuses a request whose identifier it knows, as the example
does, with 409. It must remember them across its restarts: a request signed
by a clock ahead of its own stays valid for up to ten minutes. The example
keeps them in a file, `TSIGOAT_WEBHOOK_STATE`, which it writes before it
applies a request.

The secret never travels: the signature keeps someone in the middle from
forging or changing a request, even over plain HTTP, or with
`insecureSkipVerify`, which accepts any certificate. It does not authenticate
the response, though: such an intermediary can still drop a request and
answer 2xx, so that tsigoat reports an update that never applied. Across a
network, serve the endpoint over HTTPS with a certificate that tsigoat
verifies, or keep it on the loopback, next to tsigoat. Credentials travel in
each request, and draw a warning over plain HTTP or with `insecureSkipVerify`.

tsigoat refuses the redirects of the endpoint, unless `followRedirects` lets
it follow the 307 and 308 redirects to the same scheme and host, which keep
the request whole. The other redirects would turn the request into a GET
without a body, or send it, with its headers and credentials, to another
server, or in plain HTTP.

## The example

[examples/webhook/webhook.py](../examples/webhook/webhook.py) needs Python 3.9
or later, and its standard library alone. It reads its settings from the
environment, checks the signature, the basic credentials or the token,
refuses the replays, and calls one function per operation. Complete these
functions for your provider, or set `TSIGOAT_WEBHOOK_COMMAND` to a command,
which receives every operation as arguments:

| Operation | Arguments |
| --- | --- |
| Add a record | `add <zone> <name> <type> <ttl> <rdata>` |
| Delete a record | `delete-record <zone> <name> <type> <rdata>` |
| Delete the records of a type | `delete-rrset <zone> <name> <type>` |
| Delete every record of a name | `delete-name <zone> <name>` |

```sh
TSIGOAT_WEBHOOK_SECRET="$(cat /run/secrets/tsigoat/webhook)" \
TSIGOAT_WEBHOOK_COMMAND=/usr/local/bin/my-dns-update \
  python3 webhook.py
```

The example is a starting point, not a service to expose. It serves plain
HTTP on `127.0.0.1:8053`, one request at a time, which keeps the updates of a
zone in order; a client has ten seconds to send its request whole, so that
one that stalls, or sends its bytes one by one, holds the example ten seconds
at most. Keep it on the loopback, next to tsigoat, or behind a proxy that
serves HTTPS and bounds the connections. Keep its state file on a volume that
outlives it, one file per endpoint: `tsigoat-webhook-8053.json` in its working
directory by default. A test runs it behind tsigoat with each authentication,
and nsupdate as the client, and checks that it refuses the replays, after a
restart too, and the slow clients.
