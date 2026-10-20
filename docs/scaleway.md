# Scaleway

tsigoat applies the updates through the Domains and DNS API of Scaleway, with
the secret key of an API key. [Hosted DNS providers](providers.md) tells what
the backends of the hosted providers have in common.

```yaml
backends:
  - name: scaleway
    type: scaleway
    scaleway:
      secretKeyFile: /run/secrets/tsigoat/scaleway
zones:
  - name: example.com.
    backend: scaleway
    policy:
      - key: cert-manager.
        acme: ["example.com.", "**.example.com."]
```

## The API key

The permissions of Scaleway stop at the Project, which holds zones and
domains: keep the zones that tsigoat serves in a Project of their own.

1. Create an IAM application for tsigoat, and an API key for the application;
   tsigoat needs its secret key alone.
2. Create a policy for the application, with one rule: the Project of the
   zones, and the permission set `DomainsDNSFullAccess`. A condition of the
   rule may restrict it to the addresses of tsigoat.

The permission set lets the key change every zone of the Project, and the
domains registered in it: do not share the Project with a registered domain.
A new key or policy may take two minutes to apply.

## How tsigoat writes

- **One PATCH request per update**: the deletions, the changes of TTL, then
  the creations, which Scaleway applies in order, as one version of the zone.
- **No new zone**: tsigoat forbids Scaleway to create a zone for the names of
  an update, which would hide every name below them.
- **Zones by name**: a sub-zone of Scaleway, such as `acme.example.com`, holds
  the names below it, whatever the parent zone holds: serve it as a zone of
  its own.

## Records

| Types | |
| --- | --- |
| A, AAAA, CAA, CNAME, DNAME, HTTPS, MX, NAPTR, NS, SRV, SSHFP, SVCB, TLSA, TXT | Held |
| DS, HINFO, LOC, PTR, RP, URI | REFUSED, until a live test shows that Scaleway keeps them intact |

- **TXT**: Scaleway stores a TXT record as a single string, which it serves
  in strings of 255 bytes, trims its spaces at its ends, and mangles its
  quotes and backslashes. tsigoat writes the strings of a record joined, and
  turns down the records whose strings would move: all but the last string
  must be 255 bytes long. It turns down the empty records too, and those
  whose strings hold quotes, backslashes or bytes outside printable ASCII.
- **SVCB and HTTPS**: Scaleway takes the values of their parameters
  unquoted: tsigoat turns down the values with spaces or quotes.
- **NS**: Scaleway gives the NS records a TTL of 1800 seconds at least:
  tsigoat turns down lower TTLs for them.
- **TTL**: from 60 seconds to 30 days.
- **Dynamic records**: the records that answer according to the location or
  the network of the client, to weights or to health checks hold their
  default answer alone. tsigoat shows it, but turns down the updates that
  would change their RRset, which would turn them into static records.
- **ALIAS records**, a type of Scaleway, are invisible to tsigoat.
- **The apex**: tsigoat shows an SOA of its own, and the NS records of the
  zone, and turns down their changes.

## Limits

- **Rate**: 50 requests per second.
- **Propagation**: the name servers of Scaleway serve a change within a few
  seconds.
