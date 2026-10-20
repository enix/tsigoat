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

A 2xx response applies the update, and the client gets NOERROR. Any other
response fails it, and the client gets SERVFAIL, as when the endpoint does not
answer within the `timeout` of the backend, from the connection to the end of
the response, or when the connection or TLS fails. The log entry of the update
gives the status and the beginning of the body, and the
[TsigoatBackendErrors](operations.md#tsigoatbackenderrors) alert fires when
the failures last.

## Contract

The endpoint:

- applies the operations of a request in order, all or nothing when it can;
  otherwise, it keeps them idempotent, so that an update converges when the
  client sends it again;
- answers within the timeout of the backend, five seconds by default;
- accepts a request without operations, without changing anything:
  `tsigoat check-config --backends` and the start of tsigoat send one per
  zone, to check that the endpoint answers and accepts their authentication;
- authenticates the requests, see below.

tsigoat, for its part:

- sends the updates of a zone one at a time, so that a simple script never
  applies two at once; tsigoat runs as a single instance;
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
the timestamps more than five minutes away from its clock, which stops
replays. In Python:

```python
mac = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256)
valid = hmac.compare_digest(signature, "sha256=" + mac.hexdigest())
valid = valid and abs(time.time() - int(timestamp)) <= 300
```

The secret never travels, so that the signature also protects the requests
when TLS cannot: over plain HTTP, or with `insecureSkipVerify`, which accepts
any certificate. Credentials travel in each request, and draw a warning in
these cases.

tsigoat refuses the redirects of the endpoint, unless `followRedirects` lets
it follow the 307 and 308 redirects, which keep the request whole; the other
redirects would turn it into a GET without a body.

## The example

[examples/webhook/webhook.py](../examples/webhook/webhook.py) needs Python 3.9
or later, and its standard library alone. It reads its settings from the
environment, checks the signature, the basic credentials or the token, and
calls one function per operation. Complete these functions for your
provider, or set `TSIGOAT_WEBHOOK_COMMAND` to a command, which receives every
operation as arguments:

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

The example serves plain HTTP on `127.0.0.1:8053`: keep it on the loopback,
next to tsigoat, or behind a proxy that serves HTTPS. A test runs it behind
tsigoat with each authentication, and nsupdate as the client.
