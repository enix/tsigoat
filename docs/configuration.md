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
        acme: ["example.com.", "**.example.com."]
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
that it can live in a ConfigMap or a repository, for every secret of the
configuration. Surrounding whitespace is ignored, and a file or a variable
that holds nothing else is an error: a missing secret must not turn off the
authentication that it configures.

## Backends

| Setting | Meaning |
| --- | --- |
| `name` | Name of the backend, which zones refer to |
| `type` | `powerdns`; `cloudflare`, `ovh` or `scaleway` for a hosted provider; `rfc2136` for a name server that tsigoat relays the updates to; `webhook` for an HTTP endpoint that applies them; the settings of the type follow |

A `powerdns` backend writes to the HTTP API of PowerDNS, see
[PowerDNS](powerdns.md):

| Setting | Meaning |
| --- | --- |
| `powerdns.url` | Base URL of the PowerDNS HTTP API, such as `http://pdns:8081` |
| `powerdns.serverId` | Server of the API; `localhost` by default |
| `powerdns.apiKey`, `apiKeyFile`, `apiKeyEnv` | The API key: inline, in a file, or in an environment variable; exactly one of them |
| `powerdns.timeout` | Timeout of every API call, up to one minute; `5s` by default |
| `powerdns.caFile` | PEM bundle trusted for the certificate of the API, on top of the system roots |

A `cloudflare` backend writes to the API of Cloudflare, see
[Cloudflare](cloudflare.md):

| Setting | Meaning |
| --- | --- |
| `cloudflare.apiToken`, `apiTokenFile`, `apiTokenEnv` | The API token |
| `cloudflare.zoneIds` | Identifiers of zones, by name, for a token that cannot find them by name |
| `cloudflare.timeout` | Timeout of every API call, up to one minute; `5s` by default |

An `ovh` backend writes to the API of OVHcloud, see [OVHcloud](ovh.md):

| Setting | Meaning |
| --- | --- |
| `ovh.endpoint` | `ovh-eu`, `ovh-ca`, `ovh-us`, or the `https` URL of the API |
| `ovh.applicationKey` | The application key, with the two settings below |
| `ovh.applicationSecret`, `applicationSecretFile`, `applicationSecretEnv` | The secret of the application |
| `ovh.consumerKey`, `consumerKeyFile`, `consumerKeyEnv` | The consumer key, which holds the rights |
| `ovh.oauth2.clientId` | In place of an application key: the identifier of an OAuth2 service account, with the setting below |
| `ovh.oauth2.clientSecret`, `clientSecretFile`, `clientSecretEnv` | The secret of the service account |
| `ovh.timeout` | Timeout of every API call, up to one minute; `5s` by default |

A `scaleway` backend writes to the Domains and DNS API of Scaleway, see
[Scaleway](scaleway.md):

| Setting | Meaning |
| --- | --- |
| `scaleway.secretKey`, `secretKeyFile`, `secretKeyEnv` | The secret key of the API key |
| `scaleway.timeout` | Timeout of every API call, up to one minute; `5s` by default |

The [hosted providers](providers.md) hold no TTL below 60 seconds: tsigoat
raises lower TTLs, and turns down what a provider would not keep intact.

An `rfc2136` backend relays the updates to a name server that implements RFC
2136 itself, such as BIND, which applies them, see [RFC 2136
servers](rfc2136.md):

| Setting | Meaning |
| --- | --- |
| `rfc2136.server` | Address of the name server, as `host:port` |
| `rfc2136.key` | The TSIG key that tsigoat signs with, which the server accepts: `name`, `algorithm` and the secret, as a key of `keys` |
| `rfc2136.timeout` | Timeout of every exchange with the server, up to one minute; `5s` by default |

A `webhook` backend posts the updates to an HTTP endpoint, as JSON, which
applies them; see [Webhooks](webhook.md):

| Setting | Meaning |
| --- | --- |
| `webhook.url` | Address of the endpoint, `http(s)://host[:port][/path]` |
| `webhook.signature.secret`, `secretFile`, `secretEnv` | Secret that signs every request with HMAC-SHA256 |
| `webhook.basicAuth.username`, and `password`, `passwordFile` or `passwordEnv` | Credentials of HTTP basic authentication |
| `webhook.bearer.token`, `tokenFile`, `tokenEnv` | Bearer token |
| `webhook.headers` | Headers of every request: a `name`, and `value`, `valueFile` or `valueEnv` |
| `webhook.timeout` | Timeout of every request, from the connection to the end of the response, up to one minute; `5s` by default |
| `webhook.caFile` | PEM bundle trusted for the certificate of the endpoint, on top of the system roots |
| `webhook.insecureSkipVerify` | Accept any certificate of the endpoint; draws a warning |
| `webhook.followRedirects` | Follow the 307 and 308 redirects of the endpoint to the same scheme and host, which keep the request whole; tsigoat follows none by default |

`basicAuth` and `bearer` exclude each other, since both take the
`Authorization` header; `signature` goes with either. A webhook without any of
them draws a warning, as do credentials sent over plain HTTP. Headers may not
take the place of those that tsigoat sets.

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

A rule grants a key some names and some record types, and may constrain the
records that an update adds:

```yaml
policy:
  - key: dhcp.
    names: ["*.dhcp.example.com."]
    types: [A, AAAA, ANY]
    maxTTL: 3600
```

| Setting | Meaning |
| --- | --- |
| `key` | The key that the rule grants rights to |
| `names` | Name patterns inside the zone |
| `types` | Record types; every type but SOA when absent |
| `maxTTL` | Highest TTL of the records that an update adds, in seconds |
| `content` | `acme` allows only the values of ACME challenges, in TXT records |
| `maxRecords` | Most records that one update adds under the rule |

- **Names** are patterns inside the zone. A `*` label matches exactly one
  label, a `**` label matches one or more: `*.dhcp.example.com.` matches
  `host.dhcp.example.com.`, `_acme-challenge.**.example.com.` matches
  `_acme-challenge.www.example.com.` and `_acme-challenge.a.b.example.com.`,
  but not `_acme-challenge.example.com.`.
- **Types** restrict the record types. `ANY` allows deleting every RRset of a
  name at once.
- **The constraints** apply to the records that an update adds, not to the
  deletions. An update adds a record under the first rule of the key that
  allows it, constraints included.
- **The SOA** belongs to the backend, which maintains its serial: no key may
  update it unless a rule names the `SOA` type.
- **A request is refused as a whole**, with REFUSED, when one of its records
  breaks the policy.
- **Prerequisites** may only test names that the key may update, so that a
  narrow key cannot probe the rest of the zone.

A key listed in `keys` cannot have rules in the same zone: it already holds
every right but the SOA.

### ACME challenges

An `acme` rule lists the names of the certificates whose DNS-01 challenges a
key may answer, and allows nothing else:

```yaml
policy:
  - key: cert-manager.
    acme: ["example.com.", "*.example.com.", "**.example.com."]
```

| Certificate name | Challenge record |
| --- | --- |
| `example.com.` | `_acme-challenge.example.com.` |
| `*.example.com.`, a wildcard certificate | `_acme-challenge.example.com.`, the same |
| `**.example.com.`, every name below `example.com.` | `_acme-challenge.**.example.com.` |

The rule allows TXT records with `content: acme`, `maxTTL: 300` and
`maxRecords: 10`; `maxTTL` and `maxRecords` may change these bounds.

The value of a DNS-01 challenge, which the client publishes in the TXT record,
is one string: the base64url encoding of the SHA-256 digest of the key
authorization, the token of the certificate authority joined to the
thumbprint of the account key (RFC 8555 8.4). `content: acme` checks this
form, so that the key cannot write other TXT records; tsigoat knows neither
the token nor the account key, so that it cannot tell a value of a pending
challenge from another one.

The rule allows the deletion of any TXT record of its names, since some
clients delete the TXT RRset of a challenge before adding their value.

When the challenges are delegated with CNAME records to another zone that
tsigoat serves, a rule with `names`, `types: [TXT]` and `content: acme`
allows the challenge values at the targets.
