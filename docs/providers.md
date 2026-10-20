# Hosted DNS providers

tsigoat applies the updates through the APIs of [Cloudflare](cloudflare.md),
[OVHcloud](ovh.md) and [Scaleway](scaleway.md). Their backends share what
this page describes; the page of each provider tells which credentials to
create, and what the provider does its own way.

## How tsigoat writes

These providers store records one by one, each with an identifier, where RFC
2136 thinks in RRsets. For every update, tsigoat reads the records of the
names that the update touches, computes the result of the update, then turns
each RRset that changes into records to delete, to create, or whose TTL
changes. A record that stays keeps its identifier, and what tsigoat does not
see of it, such as a comment.

| Provider | An update is | Whole or not at all |
| --- | --- | --- |
| Cloudflare | One batch request | Yes, in the API: one transaction; the name servers may serve its records a few seconds apart |
| Scaleway | One PATCH request | Yes, in the API: one version of the zone |
| OVHcloud | One request per record, then a refresh of the zone | The name servers see the update whole, at the refresh; after a failure, tsigoat brings the records back as they were |

Whole does not mean certain: when a request times out, or gets a server
error, the update may have applied or not. tsigoat then reads the records
again, and answers NOERROR when they show the update. Otherwise the update
gets SERVFAIL, and its outcome is unknown, since the request may still apply:
the update log tells so, the metrics count the call as `indeterminate`, and the
[TsigoatUncertainUpdates](operations.md#tsigoatuncertainupdates) alert fires.
A client that sends the update again brings its RRsets to the wanted content
anyway. A request turned down for its rate goes again after the delay that the
provider asks for, when the deadline of the update leaves time for it.

## What tsigoat turns down

tsigoat never writes a record approximately. What a provider would store
otherwise, or not at all, gets REFUSED before anything changes, with the
reason in the [update log](operations.md#logs):

- **the SOA and the NS records of the apex**, which the provider manages;
- **the record types that the provider does not hold**, and those that tsigoat
  did not verify that it keeps intact: each page lists them;
- **the contents that the provider would alter**: TXT strings outside
  printable ASCII, and, depending on the provider, quotes, backslashes, spaces
  at the ends of TXT strings, or empty ones;
- **names other than host names**: letters, digits, hyphens and underscores,
  with a leading wildcard;
- **the RRsets of the records that the provider serves otherwise than their
  data**, the proxied records of Cloudflare and the dynamic records of
  Scaleway: tsigoat shows them, for prerequisites, but changes nothing in
  their RRset;
- **TTLs** above the maximum of the provider.

A record that the provider refuses for another reason fails the update, with
SERVFAIL and the message of the provider in the log: tsigoat counts it as an
error of the backend, which the
[TsigoatBackendErrors](operations.md#tsigoatbackenderrors) alert watches.

## TTLs

The providers hold no TTL below 60 seconds, and some read 0 as the default TTL
of the zone. tsigoat raises the lower TTLs of an update to 60 seconds, which
the update log reports in `ttl_raised`. ACME clients ask for 60 seconds or
more.

These providers let the records of an RRset have different TTLs. Such an RRset
reads with the lowest of them, the one that resolvers keep, and an update that
keeps its records gives them all its TTL.

## The SOA

tsigoat answers the SOA queries of the zones that it serves, which clients
send to find the zone of a name. OVHcloud tells the SOA of a zone; for
Cloudflare and Scaleway, which do not, tsigoat makes one up, with the first
name server of the zone as primary, and a serial of 1.

## Concurrency

tsigoat serializes the updates of a zone within its process. Other writers of
the same zones, through the API, the control panel or another tsigoat, race
with it: an update reads, then writes, and could undo a change made in
between. Run a single instance of tsigoat, and keep other writers away from
the records that it manages, such as the `_acme-challenge` records.

## Testing

The unit tests run each backend against a simulation of the API of its
provider, with the behaviors that the documentation of the provider and the
reports of its users tell: the conformance suite of the backends, and every
scenario of `test/scenario`, whose divergences on each provider are listed
with their reason. The live tests run the conformance suite and the challenges
of a certificate against the providers themselves, with the zones and the
credentials of a developer: see [CONTRIBUTING.md](../CONTRIBUTING.md#live-tests).
