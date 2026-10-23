<!-- markdownlint-disable-next-line MD041 -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/enix/tsigoat/raw/main/docs/assets/logo-dark.svg">
    <img alt="tsigoat" src="https://github.com/enix/tsigoat/raw/main/docs/assets/logo-light.svg" width="400">
  </picture>
</p>

<p align="center">The RFC 2136 to anything proxy.</p>

tsigoat receives DNS UPDATE messages ([RFC 2136][rfc2136]), authenticates them
with TSIG ([RFC 8945][rfc8945]) and applies the changes through the API of a
DNS provider: PowerDNS, Cloudflare, OVHcloud or Scaleway. ACME DNS-01 clients
such as cert-manager, lego or certbot can then solve their challenges without
ever holding the provider credentials, even when the provider does not speak
RFC 2136. In front of a name server that does, such as BIND, tsigoat relays
the updates with its own key, and brings the keys and the policy. For any
other provider, a webhook of yours applies them.

```text
cert-manager, lego,     DNS UPDATE              HTTP API
certbot, nsupdate...  ─── + TSIG ──► tsigoat ───────────► PowerDNS, Cloudflare,
                                                          OVHcloud, Scaleway
                                             DNS UPDATE
                                     tsigoat ───────────► BIND, Knot DNS...
                                             + its TSIG
                                             HTTP POST
                                     tsigoat ───────────► your webhook
```

## Features

- **RFC 2136 updates**, prerequisites included, applied whole: tsigoat
  computes the whole update before it calls the backend once, so that a
  failure leaves the zone untouched, or is reported as an unknown outcome
  when the provider cannot tell. The rules of the RFC hold: CNAME
  exclusivity, SOA serial ordering, protection of the apex SOA and NS.
- **TSIG**: one algorithm per key, HMAC-SHA256 by default, HMAC-SHA224,
  SHA384 and SHA512 too, and the legacy HMAC-SHA1 and HMAC-MD5 for the keys
  that opt into them. Responses are signed; signature failures get the BADKEY,
  BADSIG, BADTIME and BADTRUNC errors of RFC 8945.
- **Policy per zone**: keys that may update the whole zone, and rules that
  restrict other keys to some names and record types, with bounds on the TTL
  and the number of the records. An `acme` rule lets a key write the values of
  the DNS-01 challenges of its certificates, and nothing else.
- **Hosted DNS providers**: Cloudflare, OVHcloud and Scaleway, through their
  APIs, with credentials that tsigoat narrows down to names and types. An
  update applies whole, in one request where the API allows; tsigoat turns
  down what a provider would not keep intact, rather than writing it
  approximately.
- **Relay to RFC 2136 servers**: in front of BIND or another name server,
  tsigoat checks the keys and the policy, then relays the updates signed with
  its own key, and the server applies them.
- **Webhooks** for the other providers: tsigoat posts every update, as JSON,
  to an HTTP endpoint of yours, signed; a Python example is the starting
  point.
- **SOA queries** for the zones that tsigoat serves, which lego, certbot and
  nsupdate send to find the zone of a name.
- **Several instances**, such as the replicas of the chart: the records that
  an update adds and removes apply to the records as they stand, so that
  the instances keep each other's records, on the hosted providers and on
  PowerDNS since 4.9.12 and 5.0.2, with the limits that
  [operations.md](docs/operations.md#several-instances) tells.
- **Operations**: one structured log entry per update, Prometheus metrics,
  health checks, a strict configuration file with `check-config`, static
  binaries, deb and rpm packages with a hardened systemd unit, and
  multi-architecture images.

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
| [Hosted DNS providers](docs/providers.md) | How tsigoat writes to the APIs of hosted providers, and what it turns down |
| [Cloudflare](docs/cloudflare.md), [OVHcloud](docs/ovh.md), [Scaleway](docs/scaleway.md) | The credentials to create for each provider, and what it does its own way |
| [RFC 2136 servers](docs/rfc2136.md) | Relaying the updates to BIND or another name server, with the keys and the policy of tsigoat |
| [Webhooks](docs/webhook.md) | Applying the updates with a script of yours, for the providers that tsigoat does not support |
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
