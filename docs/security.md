# Security

tsigoat holds the credentials of a DNS provider, which can change whole zones,
the TSIG key of a name server or the secrets of a webhook that it relays the
updates to, and hands out TSIG keys that can only change what their policy
allows. Its
security rests on the secrecy of those keys, on the policy, and on the
exposure of the DNS and administration ports.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## TSIG

TSIG authenticates a request and protects it against changes in transit; it
does not encrypt it, so that the records of an update are visible on the
network. tsigoat checks the signature, then the time of the request against
the margin that the client chose, five minutes for most clients.

- An unknown key, or a known key with another algorithm than its own, gets
  NOTAUTH with BADKEY; a wrong signature, BADSIG. These answers are unsigned,
  as RFC 8945 requires.
- A request signed too long ago or ahead gets BADTIME, signed, with the time
  of the server, which shows the clock offset to the client.
- The answers to signed requests are signed with the same key.

## Legacy algorithms

RFC 8945 forbids HMAC-MD5 and recommends against HMAC-SHA1. Some clients still
use them by default, cert-manager and certbot MD5, lego SHA1, so that tsigoat
supports them on the keys that declare them, with a warning at startup. A key
has a single algorithm: a request signed with another one gets BADKEY, so
that a legacy algorithm never applies to a key that did not opt in.

To move a client off a legacy algorithm:

1. Create a new key with `hmac-sha256`, and give it the rights of the old one.
2. Configure the client with the new key and its algorithm.
3. Check with `tsigoat_dns_responses_total{algorithm=~"hmac-md5|hmac-sha1"}`
   that the old key is no longer used, then remove it.

## Policy

- Give each client its own key, restricted to the records it manages: an
  `acme` rule for an ACME client, which then writes the values of the
  challenges of its certificates alone, with a short TTL, and cannot touch the
  other TXT records, such as SPF, DKIM or DMARC.
- Keep `keys`, which grants a whole zone, for the clients that need it.
- The SOA can only change through a rule that names it.
- A request is refused as a whole when one of its records breaks the policy,
  and its prerequisites may only test names that the key may update.

## Unsigned requests

- An unsigned update of a zone that does not accept them gets REFUSED, as
  does one of a zone that tsigoat does not serve.
- `allowUnauthenticated` lets anyone who reaches tsigoat change the zone: keep
  such zones on private networks, if at all.
- tsigoat answers the SOA queries of the zones it serves, signed or not, since
  lego and certbot send them unsigned to find the zone of a name: whoever
  reaches tsigoat can tell which zones it serves. These answers reuse the SOA
  of a zone for 30 seconds, so that they do not reach the backend each time.

## Known limits

- **Replays**: tsigoat does not detect a request sent again within the time
  margin of its signature. Updates are mostly idempotent, and clients resend
  the very same message when a UDP answer is lost, which a replay check would
  refuse.
- **Rate**: tsigoat does not limit the rate of requests. Each signed update
  costs a few backend calls, each unsigned one none, but for the zones that
  accept unsigned updates.
- **Single instance**: tsigoat serializes the updates of a zone within its
  process, see [PowerDNS](powerdns.md#concurrency).

## Hardening a deployment

- Expose the DNS port to the clients that need it, not to the internet as a
  whole when they live elsewhere.
- Keep the administration server, which has no authentication, on a private
  network.
- Read the secrets from files or environment variables, not from the
  configuration file itself.
- Run the `scratch` image as its unprivileged user, on a read-only root
  filesystem, without capabilities, as the [Helm chart](../chart/README.md)
  does.
- Restrict the PowerDNS API to tsigoat, and serve it over HTTPS when it
  crosses a network.
- Let a name server behind an `rfc2136` backend grant the key of tsigoat only
  what its clients need, and keep the server out of reach of the clients. TSIG
  authenticates the relayed updates without encrypting them.
- Sign the requests to a `webhook` backend, have the endpoint check the
  signature and the timestamp, and serve it over HTTPS, or on the loopback.
- Verify the signature of the images before deploying them, see
  [SECURITY.md](../SECURITY.md#verifying-releases).
