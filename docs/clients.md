# Clients

Clients send their updates to tsigoat, as to any RFC 2136 server, then check
the propagation of their records on the public DNS, as usual. Give each client
its own key, restricted by a [policy rule](configuration.md#policy-rules) to
the records it manages.

Most clients default to a legacy algorithm, which tsigoat refuses unless the
key declares it: set the algorithm explicitly.

| Client | Default algorithm | Setting |
| --- | --- | --- |
| cert-manager | HMAC-MD5 | `tsigAlgorithm: HMACSHA256` |
| lego, Traefik | HMAC-SHA1 | `RFC2136_TSIG_ALGORITHM=hmac-sha256.` |
| certbot | HMAC-MD5 | `dns_rfc2136_algorithm = HMAC-SHA256` |
| nsupdate `-y` | HMAC-MD5 | `-y hmac-sha256:name:secret` |

Before an update, lego, certbot and nsupdate find the zone of a name with SOA
queries to tsigoat, which answers them for the zones it serves, signed or not.

## cert-manager

A solver of an Issuer or a ClusterIssuer:

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

The Secret holds the base64 TSIG secret, as tsigoat reads it.
[examples/helm/cert-manager-issuer.yaml](../examples/helm/cert-manager-issuer.yaml)
holds a complete ClusterIssuer, for tsigoat installed with [the Helm
chart](../chart/README.md). cert-manager supports `HMACMD5`, `HMACSHA1`,
`HMACSHA256` and `HMACSHA512`.

## lego and Traefik

```sh
RFC2136_NAMESERVER=tsigoat.example.com:53 \
RFC2136_TSIG_KEY=lego. \
RFC2136_TSIG_ALGORITHM=hmac-sha256. \
RFC2136_TSIG_SECRET=... \
lego --dns rfc2136 --domains www.example.com --email admin@example.com run
```

Traefik builds on lego: give its process the same variables, and set
`dnsChallenge.provider` to `rfc2136`.

## certbot

```ini
# certbot certonly --dns-rfc2136 --dns-rfc2136-credentials tsigoat.ini
dns_rfc2136_server = 192.0.2.53
dns_rfc2136_port = 53
dns_rfc2136_name = certbot.
dns_rfc2136_secret = ...
dns_rfc2136_algorithm = HMAC-SHA256
```

The server must be an IP address.

## nsupdate

```sh
nsupdate -y "hmac-sha256:admin.:$SECRET" <<EOF
server tsigoat.example.com 53
update add www.example.com. 300 A 192.0.2.1
send
EOF
```

Without a `zone` line, nsupdate finds the zone with a SOA query. `-k` reads the
key from a file that `tsig-keygen` wrote, which keeps the secret out of the
command line.
