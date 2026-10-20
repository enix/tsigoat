# OVHcloud

tsigoat applies the updates through the API of OVHcloud, with an application
key or an OAuth2 service account. [Hosted DNS providers](providers.md) tells
what the backends of the hosted providers have in common.

```yaml
backends:
  - name: ovh
    type: ovh
    ovh:
      endpoint: ovh-eu
      applicationKey: 7kbG7Bk7S9Nt7ZSV
      applicationSecretFile: /run/secrets/tsigoat/ovh-application-secret
      consumerKeyFile: /run/secrets/tsigoat/ovh-consumer-key
zones:
  - name: example.com.
    backend: ovh
    policy:
      - key: cert-manager.
        acme: ["example.com.", "**.example.com."]
```

`endpoint` is `ovh-eu`, `ovh-ca` or `ovh-us`, or the URL of the API.

## Credentials

### An application key

An application key and its secret identify tsigoat; a consumer key holds its
rights. Create the three of them on the `createToken` page of the endpoint, such
as <https://eu.api.ovh.com/createToken/>, with an unlimited validity, the
addresses of tsigoat, and these rights for each zone `Z` that tsigoat
serves, and nothing else:

| Method | Path |
| --- | --- |
| GET | `/domain/zone/Z/record` |
| GET | `/domain/zone/Z/record/*` |
| POST | `/domain/zone/Z/record` |
| PUT | `/domain/zone/Z/record/*` |
| DELETE | `/domain/zone/Z/record/*` |
| POST | `/domain/zone/Z/refresh` |
| GET | `/domain/zone/Z/soa` |

The rights of OVHcloud stop at the zone: tsigoat and its policy narrow them
down to names and types.

tsigoat signs every request with the time of the API, which it reads at the
first request and every hour since: the API turns down the requests signed
more than two minutes away from its own time.

### An OAuth2 service account

```yaml
    ovh:
      endpoint: ovh-eu
      oauth2:
        clientId: EU.0123456789abcdef
        clientSecretFile: /run/secrets/tsigoat/ovh-client-secret
```

Create a service account, with the `CLIENT_CREDENTIALS` flow, and an IAM policy
that grants it these actions on the zones that tsigoat serves, such as
`urn:v1:eu:resource:dnsZone:example.com`:

- `dnsZone:apiovh:record/get`, `record/create`, `record/edit` and
  `record/delete`;
- `dnsZone:apiovh:refresh`, without which the name servers never serve the
  changes;
- `dnsZone:apiovh:soa/get`.

Service accounts need one of the endpoints `ovh-eu`, `ovh-ca` and `ovh-us`.

## How tsigoat writes

- **One refresh per update**: the name servers of OVHcloud serve a zone as it
  stood at its last refresh. tsigoat applies the records of an update one
  request at a time, the deletions, the changes of TTL, then the creations,
  and refreshes the zone once, so that the name servers see the update whole.
- **No transaction**: a request that fails may have applied anyway, before
  its response was lost. When a request fails, or the refresh fails three
  times, tsigoat reads the records of the update again, brings them back to
  their content before the update, whatever the requests did, checks them,
  and refreshes the zone; the update gets SERVFAIL. When that fails too, the
  outcome is unknown: the zone may hold part of the update, which the next
  refresh, by tsigoat or by anyone, publishes; the update log tells so, and
  the [TsigoatUncertainUpdates](operations.md#tsigoatuncertainupdates) alert
  fires. A refresh by another writer, such as the control panel, publishes
  what an update of tsigoat is writing too, if it comes in between.
- **Lookups**: one request lists the records of a name, then one request
  reads each of them.

## Records

| Types | |
| --- | --- |
| A, AAAA, CAA, CNAME, DNAME, HTTPS, LOC, MX, NAPTR, NS, PTR, RP, SRV, SSHFP, SVCB, TLSA, TXT | Held |
| Every other type, such as DS, URI or HINFO | REFUSED |

- **TXT**: OVHcloud trims the spaces at the ends of the strings, and mangles
  their quotes and backslashes: tsigoat turns down the TXT strings that hold
  any, the empty ones, and those that hold bytes outside printable ASCII. The
  SPF, DKIM and DMARC records of the control panel read as the TXT records
  that the name servers serve.
- **TTL**: from 60 seconds to one day. A TTL of 0, the default TTL of the
  zone at OVHcloud, reads as that default TTL, which tsigoat reads from the
  SOA of the zone.
- **The apex**: tsigoat shows the SOA of the zone, and its NS records, and
  turns down their changes.
