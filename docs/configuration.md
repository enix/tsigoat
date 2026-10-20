# Configuration

tsigoat reads one YAML file, `/etc/tsigoat/config.yaml` unless `--config`
names another. [examples/config.yaml](../examples/config.yaml) shows every
setting with comments.

The file is strict: an unknown setting is an error, and every error names its
place, such as `zones[0].policy[1].names[0]`. `tsigoat check-config` validates
a file without starting anything, prints the warnings about risky settings,
and exits with code 1 when the file is invalid; `--backends` also reads every
zone through its backend.

## A minimal configuration

One key for cert-manager, restricted to the ACME challenges of one zone:

```yaml
keys:
  - name: cert-manager.
    secretFile: /run/secrets/tsigoat/cert-manager
backends:
  - name: pdns
    type: powerdns
    powerdns:
      url: http://pdns:8081
      apiKeyFile: /run/secrets/tsigoat/powerdns-api-key
zones:
  - name: example.com.
    policy:
      - key: cert-manager.
        names: ["_acme-challenge.example.com.", "_acme-challenge.**.example.com."]
        types: [TXT]
```

## Listen addresses

| Setting | Meaning |
| --- | --- |
| `listen` | Addresses for DNS, each served over both UDP and TCP; `["[::]:5353"]` by default |
| `admin.listen` | Address of the administration HTTP server, which serves the health checks and the metrics; disabled when absent |

An address is `host:port`. The administration server cannot take the TCP
address of a DNS listener. `serve --listen` and `serve --admin-listen` replace
these settings.

## Keys

| Setting | Meaning |
| --- | --- |
| `name` | The key name, as clients send it in their TSIG record |
| `algorithm` | `hmac-sha256` by default; also `hmac-sha224`, `hmac-sha384`, `hmac-sha512`, and the legacy `hmac-sha1` and `hmac-md5` |
| `secret`, `secretFile`, `secretEnv` | The secret, base64-encoded: inline, in a file, or in an environment variable; exactly one of them |

Names are case-insensitive and fully qualified: `Cert-Manager` and
`cert-manager.` are the same key. A key has one algorithm: a request signed
with another one gets BADKEY, even with the right secret. `hmac-sha1` and
`hmac-md5` draw a warning, since RFC 8945 recommends against the first and
forbids the second; keep them for the clients that cannot change, see
[Security](security.md#legacy-algorithms).

A secret is random bytes, base64-encoded. A secret shorter than the output of
its algorithm, 32 bytes for HMAC-SHA256, draws a warning. Either command makes
one:

```sh
openssl rand -base64 32
tsig-keygen -a hmac-sha256 cert-manager.
```

Files and environment variables keep the secrets out of the configuration, so
that it can live in a ConfigMap or a repository. Surrounding whitespace is
ignored.

## Backends

| Setting | Meaning |
| --- | --- |
| `name` | Name of the backend, which zones refer to |
| `type` | `powerdns`, the only type so far |
| `powerdns.url` | Base URL of the PowerDNS HTTP API, such as `http://pdns:8081` |
| `powerdns.serverId` | Server of the API; `localhost` by default |
| `powerdns.apiKey`, `apiKeyFile`, `apiKeyEnv` | The API key: inline, in a file, or in an environment variable; exactly one of them |
| `powerdns.timeout` | Timeout of every API call, up to one minute; `5s` by default |
| `powerdns.caFile` | PEM bundle trusted for the certificate of the API, on top of the system roots |

[PowerDNS](powerdns.md) tells what tsigoat needs from PowerDNS.

## Zones

| Setting | Meaning |
| --- | --- |
| `name` | The zone, which must exist in its backend |
| `backend` | Name of the backend of the zone; optional when there is only one |
| `keys` | Keys allowed to update every record of the zone, but the SOA |
| `policy` | Rules that grant narrower rights to other keys |
| `allowUnauthenticated` | Accept unsigned updates of every record but the SOA, from anyone who reaches tsigoat; draws a warning |

A zone must allow something: list keys, write rules, or accept unsigned
updates. tsigoat applies an update to the zone named by its zone section; a
record that belongs to another zone that tsigoat serves, such as a child zone,
gets NOTZONE.

## Policy rules

A rule grants a key some names and some record types:

```yaml
policy:
  - key: cert-manager.
    names: ["_acme-challenge.example.com.", "_acme-challenge.**.example.com."]
    types: [TXT]
  - key: dhcp.
    names: ["*.dhcp.example.com."]
    types: [A, AAAA, ANY]
```

- **Names** are patterns inside the zone. A `*` label matches exactly one
  label, a `**` label matches one or more:
  `_acme-challenge.**.example.com.` matches
  `_acme-challenge.www.example.com.` and `_acme-challenge.a.b.example.com.`,
  but not `_acme-challenge.example.com.`, which the rule above lists on its
  own.
- **Types** restrict the record types; a rule without types allows every type
  but SOA. `ANY` allows deleting every RRset of a name at once.
- **The SOA** belongs to the backend, which maintains its serial: no key may
  update it unless a rule names the `SOA` type.
- **A request is refused as a whole**, with REFUSED, when one of its records
  breaks the policy.
- **Prerequisites** may only test names that the key may update, so that a
  narrow key cannot probe the rest of the zone.

A key listed in `keys` cannot have rules in the same zone: it already holds
every right but the SOA.
