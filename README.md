# tsigoat

The RFC 2136 to anything proxy.

tsigoat receives DNS UPDATE messages ([RFC 2136][rfc2136]), authenticates them
with TSIG ([RFC 8945][rfc8945]) and applies the changes through the API of a
DNS provider. ACME DNS-01 clients such as cert-manager, lego or certbot can then
solve their challenges without ever holding the provider credentials, even when
the provider does not speak RFC 2136. In front of a name server that does,
such as BIND, tsigoat relays the updates with its own key, and brings the keys
and the policy.

```text
cert-manager, lego,     DNS UPDATE              HTTP API
certbot, nsupdate...  ─── + TSIG ──► tsigoat ───────────► PowerDNS
                                             DNS UPDATE
                                     tsigoat ───────────► BIND, Knot DNS...
                                             + its TSIG
```

> [!WARNING]
> tsigoat has no release yet. Its backends are PowerDNS and the name servers
> that implement RFC 2136; tsigoat runs as a single instance, but in front of
> name servers alone.

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
  restrict other keys to some names and record types, with bounds on the TTL
  and the number of the records. An `acme` rule lets a key write the values of
  the DNS-01 challenges of its certificates, and nothing else.
- **Relay to RFC 2136 servers**: in front of BIND or another name server,
  tsigoat checks the keys and the policy, then relays the updates signed with
  its own key, and the server applies them.
- **SOA queries** for the zones that tsigoat serves, which lego, certbot and
  nsupdate send to find the zone of a name.
- **Operations**: one structured log entry per update, Prometheus metrics,
  health checks, a strict configuration file with `check-config`, static
  binaries and multi-architecture images.

## Getting started

Make a TSIG secret, and write a configuration that lets one key write the ACME
challenges of a zone held by PowerDNS:

```sh
openssl rand -base64 32 > cert-manager.key
```

```yaml
keys:
  - name: cert-manager.
    secretFile: cert-manager.key
backends:
  - name: pdns
    type: powerdns
    powerdns:
      url: http://pdns:8081
      apiKeyEnv: PDNS_API_KEY
zones:
  - name: example.com.
    policy:
      - key: cert-manager.
        acme: ["example.com.", "**.example.com."]
```

Check it, then serve it, here on port 5353 over UDP and TCP:

```sh
tsigoat check-config --config config.yaml --backends
tsigoat serve --config config.yaml
```

The container images run `serve` with `/etc/tsigoat/config.yaml`, and [the
Helm chart](chart/README.md) deploys tsigoat in Kubernetes, next to
cert-manager or for clients out of the cluster.

## Documentation

| Document | For |
| --- | --- |
| [Configuration](docs/configuration.md) | Every setting of the configuration file, and the update policy |
| [Clients](docs/clients.md) | Setting up cert-manager, lego and Traefik, certbot and nsupdate |
| [PowerDNS](docs/powerdns.md) | What tsigoat needs from PowerDNS, and how it writes to it |
| [RFC 2136 servers](docs/rfc2136.md) | Relaying the updates to BIND or another name server, with the keys and the policy of tsigoat |
| [Operations](docs/operations.md) | Command line, images, Kubernetes, logs, metrics and alerts |
| [Helm chart](chart/README.md) | Installing tsigoat in Kubernetes, and the values of the chart |
| [Security](docs/security.md) | What tsigoat protects, its limits, and how to harden a deployment |
| [Architecture](docs/architecture.md) | How a request flows through tsigoat, and how it is tested |

To report a vulnerability, see [SECURITY.md](SECURITY.md).

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
