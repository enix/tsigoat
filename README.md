# tsigoat

The RFC 2136 to anything proxy.

tsigoat receives DNS UPDATE messages ([RFC 2136][rfc2136]), authenticates them
with TSIG ([RFC 8945][rfc8945]) and applies the changes through the API of a
DNS provider. ACME DNS-01 clients such as cert-manager, lego or certbot can then
solve their challenges without ever holding the provider credentials, even when
the provider does not speak RFC 2136.

```text
cert-manager, lego,     DNS UPDATE              HTTP API
certbot, nsupdate...  ─── + TSIG ──► tsigoat ───────────► PowerDNS
```

> [!WARNING]
> tsigoat has no release yet. PowerDNS is the only backend, and tsigoat runs
> as a single instance.

## Features

- **RFC 2136 updates**, prerequisites included, applied atomically: tsigoat
  computes the whole update before it calls the backend once, so that a
  failure leaves the zone untouched. The rules of the RFC hold: CNAME
  exclusivity, SOA serial ordering, protection of the apex SOA and NS.
- **TSIG**: one algorithm per key, HMAC-SHA256 by default, HMAC-SHA224,
  SHA384 and SHA512 too, and the legacy HMAC-SHA1 and HMAC-MD5 for the keys
  that opt into them. Responses are signed; signature failures get the BADKEY,
  BADSIG and BADTIME errors of RFC 8945.
- **Policy per zone**: keys that may update the whole zone, and rules that
  restrict other keys to some names and record types, such as the
  `_acme-challenge` TXT records.
- **SOA queries** for the zones that tsigoat serves, which lego, certbot and
  nsupdate send to find the zone of a name.
- **Operations**: one structured log entry per update, Prometheus metrics,
  health checks, a strict configuration file with `check-config`, static
  binaries and multi-architecture images.

## Getting started

Write a configuration (see [Configuration](#configuration)), check it, and
run tsigoat:

```sh
tsigoat check-config --config config.yaml
tsigoat serve --config config.yaml
```

The container images run `serve` with `/etc/tsigoat/config.yaml`, listen on
port 5353 over UDP and TCP, and serve the administration endpoints on 9153 when
the configuration enables them:

```sh
docker run --rm -p 53:5353/udp -p 53:5353/tcp \
  -v "$PWD/config.yaml:/etc/tsigoat/config.yaml:ro" ghcr.io/enix/tsigoat
```

[examples/kubernetes](examples/kubernetes) deploys tsigoat for cert-manager.

TSIG secrets are random bytes, base64-encoded:

```sh
openssl rand -base64 32
tsig-keygen -a hmac-sha256 cert-manager.   # the same, as a BIND key block
```

## Configuration

[examples/config.yaml](examples/config.yaml) shows every setting, with
comments. A minimal configuration for cert-manager:

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

| Setting | Meaning |
| --- | --- |
| `listen` | DNS addresses, for UDP and TCP; `["[::]:5353"]` by default |
| `admin.listen` | Address of the administration HTTP server; disabled by default |
| `keys[].name` | Key name, as clients send it; a trailing dot is implied |
| `keys[].algorithm` | `hmac-sha256` (default), `hmac-sha224`, `hmac-sha384`, `hmac-sha512`, or the legacy `hmac-sha1` and `hmac-md5` |
| `keys[].secret`, `secretFile`, `secretEnv` | The base64 secret, inline, in a file, or in an environment variable: exactly one |
| `backends[].type` | `powerdns` |
| `backends[].powerdns.url` | Base URL of the PowerDNS HTTP API |
| `backends[].powerdns.serverId` | Server of the API; `localhost` by default |
| `backends[].powerdns.apiKey`, `apiKeyFile`, `apiKeyEnv` | The API key: exactly one |
| `backends[].powerdns.timeout` | Timeout of every API call; `5s` by default |
| `backends[].powerdns.caFile` | PEM bundle trusted for the API, on top of the system roots |
| `zones[].name` | The zone, which must exist in its backend |
| `zones[].backend` | Backend of the zone; optional with a single backend |
| `zones[].keys` | Keys allowed to update every record of the zone but the SOA |
| `zones[].policy[]` | Rules: a `key`, name patterns in `names`, record `types` |
| `zones[].allowUnauthenticated` | Accept unsigned updates from anyone; draws a warning |

Policy rules match names with patterns where `*` stands for exactly one label
and `**` for one or more: `_acme-challenge.**.example.com.` matches
`_acme-challenge.www.example.com.` but not `_acme-challenge.example.com.`.
Without `types`, a rule allows every type but SOA; `ANY` allows deleting every
record of a name, and SOA updates need a rule that lists `SOA`, since the
backend maintains the serial. A request is refused as a whole when one of its
records breaks the policy, and its prerequisites may only test names that the
key may update.

The configuration is strict: unknown settings are errors, and every error
names its place, such as `zones[0].policy[1].names[0]`.

## Command line

| Command | Purpose |
| --- | --- |
| `tsigoat serve` | Serve DNS updates until SIGINT or SIGTERM, then finish the updates in progress |
| `tsigoat check-config` | Validate the configuration and print its warnings; exit code 1 when invalid |
| `tsigoat version` | Print the version; `--short` for the number only |

`serve` and `check-config` read `--config`, `/etc/tsigoat/config.yaml` by
default. `serve` also takes `--listen` (repeatable) and `--admin-listen`,
which replace the addresses of the configuration, `--log-format` (`text` or
`json`), `--log-level` (`debug`, `info`, `warn` or `error`), and
`--auto-gomemlimit`, on by default, which sets the Go memory limit from the
cgroup.

## Clients

Clients send their updates to tsigoat, and check the propagation of their
records on the public DNS, as usual.

### cert-manager

```yaml
solvers:
  - dns01:
      rfc2136:
        nameserver: tsigoat.tsigoat.svc.cluster.local:53
        tsigKeyName: cert-manager.
        tsigAlgorithm: HMACSHA256
        tsigSecretSecretRef:
          name: tsigoat-tsig-key
          key: secret
```

Set `tsigAlgorithm`: cert-manager defaults to `HMACMD5`, which tsigoat only
accepts on a key declared with `algorithm: hmac-md5`.
[examples/kubernetes/cert-manager-issuer.yaml](examples/kubernetes/cert-manager-issuer.yaml)
holds a complete ClusterIssuer.

### lego and Traefik

```sh
RFC2136_NAMESERVER=tsigoat.example.com:53 \
RFC2136_TSIG_KEY=lego. \
RFC2136_TSIG_ALGORITHM=hmac-sha256. \
RFC2136_TSIG_SECRET=... \
lego --dns rfc2136 --domains www.example.com --email admin@example.com run
```

lego, and Traefik which builds on it, default to `hmac-sha1.`: set
`RFC2136_TSIG_ALGORITHM`.

### certbot

```ini
# certbot certonly --dns-rfc2136 --dns-rfc2136-credentials tsigoat.ini
dns_rfc2136_server = 192.0.2.53
dns_rfc2136_port = 53
dns_rfc2136_name = certbot.
dns_rfc2136_secret = ...
dns_rfc2136_algorithm = HMAC-SHA256
```

The server must be an IP address.

### nsupdate

```sh
nsupdate -y "hmac-sha256:admin.:$SECRET" <<EOF
server tsigoat.example.com 53
update add www.example.com. 300 A 192.0.2.1
send
EOF
```

## PowerDNS

tsigoat is tested with PowerDNS Authoritative 4.9 and 5.0. It needs the HTTP
API (`api=yes`, `api-key`, and the webserver reachable from tsigoat), and the
zones must exist. tsigoat leaves the SOA serial to PowerDNS: the zones created
through the API bump it on every change (`SOA-EDIT-API` set to `DEFAULT`);
set that metadata on the other zones.

An update becomes a single PATCH request, which PowerDNS applies in one
transaction. tsigoat reads the records of PowerDNS-specific types, such as
ALIAS and LUA, but never writes them. Disabled records are invisible to
tsigoat, and an update that rewrites their RRset drops them.

## Monitoring

With `admin.listen` set, tsigoat serves `/healthz`, `/readyz` (200 while it
serves DNS, 503 once it shuts down) and `/metrics`:

| Metric | Labels |
| --- | --- |
| `tsigoat_dns_responses_total` | `opcode`, `rcode`, `zone`, `key`, `algorithm` |
| `tsigoat_dns_response_duration_seconds` | `opcode` |
| `tsigoat_tsig_failures_total` | `error`: BADKEY, BADSIG or BADTIME |
| `tsigoat_backend_calls_total` | `backend`, `operation` (lookup or apply), `result` |
| `tsigoat_backend_call_duration_seconds` | `backend`, `operation` |
| `tsigoat_build_info` | `version`, `revision`, `goversion` |

The `zone` and `key` labels only take configured names, empty otherwise, so
that clients cannot grow the series. `algorithm` tracks the remaining use of
HMAC-MD5 and HMAC-SHA1.

Every update ends with one log entry, `msg=update`, with the key, the zone,
the rcode, the reason of a rejection or the error of a failure, and the
changes applied.

## Security

- TSIG authenticates the requests; it does not encrypt them. RFC 8945 forbids
  HMAC-MD5 and recommends against HMAC-SHA1: tsigoat accepts them only on the
  keys that name them, logs a warning at startup, and counts their use. Move
  their clients to `hmac-sha256`, then the keys.
- Give each client its own key, restricted by policy rules to what it updates.
- An unsigned update gets REFUSED both for the zones that tsigoat does not
  serve and for those that require a key. tsigoat answers SOA queries for the
  zones it serves, signed or not, since lego and certbot send them unsigned:
  whoever reaches tsigoat can tell which zones it serves.
- `allowUnauthenticated` lets anyone who reaches tsigoat change the zone:
  keep such zones on private networks.
- tsigoat serializes the updates of a zone within its process: run a single
  instance. Other writers of the same zones, through the PowerDNS API, race
  with it.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Development

With [Nix][nix] and [direnv][direnv], `direnv allow` provides every tool.
Otherwise install Go, [Task][task] and Docker (or Podman) for [Dagger][dagger].

```sh
task dev        # PowerDNS with the example.test. zone, on localhost
task dev:run    # tsigoat on 127.0.0.1:10053, prints the TSIG key to use
```

Then, from another terminal:

```sh
nsupdate -y "hmac-sha256:dev.:<key printed by task dev:run>" <<EOF
server 127.0.0.1 10053
zone example.test.
update add hello.example.test. 60 TXT "world"
send
EOF
dig +tcp @127.0.0.1 -p 5300 hello.example.test. TXT
```

`task --list` shows every task; [CONTRIBUTING.md](CONTRIBUTING.md) explains
the toolchain and the conventions.

## License

MIT, see [LICENSE](LICENSE).

[rfc2136]: https://www.rfc-editor.org/rfc/rfc2136
[rfc8945]: https://www.rfc-editor.org/rfc/rfc8945
[nix]: https://nixos.org/
[direnv]: https://direnv.net/
[task]: https://taskfile.dev/
[dagger]: https://dagger.io/
