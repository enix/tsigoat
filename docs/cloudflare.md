# Cloudflare

tsigoat applies the updates through the API of Cloudflare, with an API token.
[Hosted DNS providers](providers.md) tells what the backends of the hosted
providers have in common.

```yaml
backends:
  - name: cloudflare
    type: cloudflare
    cloudflare:
      apiTokenFile: /run/secrets/tsigoat/cloudflare
zones:
  - name: example.com.
    backend: cloudflare
    policy:
      - key: cert-manager.
        acme: ["example.com.", "**.example.com."]
```

## The API token

Create a user API token, under _My Profile_, _API Tokens_, or an account API
token, under _Manage Account_, _Account API Tokens_, which survives the user,
with:

- the permission _Zone_, _DNS_, _Edit_;
- the zone resources _Include_, _Specific zone_: the zones that tsigoat
  serves;
- optionally, a client IP address filter: the addresses of tsigoat.

tsigoat finds a zone by its name. Should the token not see the zone that way,
give tsigoat its identifier, shown on the _Overview_ page of the zone:

```yaml
    cloudflare:
      apiTokenFile: /run/secrets/tsigoat/cloudflare
      zoneIds:
        example.com.: 023e105f4ecef8ad9ca31a8372d0c353
```

tsigoat takes no other credential: the Global API Key opens the whole account.

## How tsigoat writes

- **One batch request per update**: the deletions, the changes of TTL, then
  the creations, which Cloudflare applies in one transaction. A batch holds
  200 operations at most on the Free plan: tsigoat turns down a larger update
  rather than split it.
- **A zone that changed** since tsigoat read it makes the batch fail on a
  record that exists already: tsigoat reads the zone again, and sends another
  batch, once.
- **The records with fields**, such as SRV, CAA or TLSA, go as their fields,
  as the API wants them; the others as their content.

## Records

| Types | |
| --- | --- |
| A, AAAA, CAA, CNAME, DS, HTTPS, LOC, MX, NAPTR, NS, OPENPGPKEY, PTR, SMIMEA, SRV, SSHFP, SVCB, TLSA, TXT, URI | Held |
| Every other type, such as HINFO, RP or DNAME | REFUSED |

- **TXT**: tsigoat writes the strings in quotes, with their escapes, which
  Cloudflare keeps. Empty TXT records, which Cloudflare neither stores nor
  serves, and bytes outside printable ASCII get REFUSED.
- **TTL**: from 60 seconds to one day. The automatic TTL of Cloudflare reads
  as 300 seconds, the TTL that its name servers serve.
- **Proxied records**: Cloudflare serves its own addresses for the A, AAAA
  and CNAME records that it proxies. tsigoat shows them with their own content,
  but turns down the updates that would change their RRset, or add addresses
  or a CNAME beside them, which Cloudflare would proxy too. Records that
  another product of Cloudflare manages, such as Email Routing, are left
  alone the same way.
- **The apex**: tsigoat shows an SOA of its own, and the NS records of the
  name servers that Cloudflare assigned to the zone, when the token may read
  the zone.
- **CNAME records at the apex**, which Cloudflare flattens into addresses, do
  not come from tsigoat: RFC 2136 forbids a CNAME beside the SOA.

## Limits

- **Rate**: 1,200 requests per 5 minutes per token, across the API and the
  dashboard for a user token. An update costs two requests per name that it
  touches, and its batch.
- **Propagation**: the name servers of Cloudflare serve a change within five
  minutes, usually much less.
