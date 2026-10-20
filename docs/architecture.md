# Architecture

This document is for contributors: how a request flows through tsigoat, and
how the code is tested. [CONTRIBUTING.md](../CONTRIBUTING.md) covers the
development workflow.

## Packages

| Package | Role |
| --- | --- |
| `cmd/tsigoat` | Command line: `serve`, `check-config`, `version` |
| `internal/config` | Strict YAML decoding, canonical names, path-anchored validation errors |
| `internal/app` | Assembly: configuration → keyring, backends, policies, DNS server, administration server |
| `internal/dnsserver` | UDP and TCP listeners, request handling, response signing, shutdown |
| `internal/auth` | TSIG keyring, one algorithm per key; update policy |
| `internal/update` | The RFC 2136 engine: parsing, prerequisites, update section |
| `internal/zone` | Working view of a zone: lazy reads, changes in memory, diff |
| `internal/backend` | Backend and relay contracts; `memory` for the tests, `powerdns` for production, `rfc2136` to relay to a name server, `webhook` to an HTTP endpoint; `httpclient` for the HTTP clients; `backendtest`, the conformance suite of the backends |
| `internal/backend/hosted` | What the backends of hosted providers share: RRsets from records, records from RRset changes, the limits of a provider, the HTTP client of the APIs; `hostedtest` for their simulations |
| `internal/backend/cloudflare`, `ovh`, `scaleway` | The backends of the hosted providers; `cloudflaretest`, `ovhtest` and `scalewaytest` simulate their APIs |
| `internal/metrics`, `internal/admin` | Prometheus collectors; `/healthz`, `/readyz` and `/metrics` |
| `internal/logging` | `log/slog` setup |

miekg/dns, the DNS library, stays within the DNS-facing packages, and the
engine performs no I/O but the reads of its view: golangci-lint checks both
with depguard rules.

## Life of an update

1. **TSIG.** miekg/dns reads the message and verifies its signature with the
   keyring. A failure gets NOTAUTH with BADKEY, BADSIG, BADTIME, or BADTRUNC
   for a truncated MAC. A TSIG or OPT record out of place, or a MAC size out
   of the bounds of RFC 8945, gets FORMERR, an EDNS version other than 0
   BADVERS.
2. **Zone section**: exactly one entry, of type SOA, of a data class, or
   FORMERR.
3. **Admission**: the zone must be served, and the key, or the absence of
   one, admitted to it. A signed request for an unknown zone gets NOTAUTH;
   anything else REFUSED, so that unsigned requests cannot tell an unknown
   zone from a forbidden one.
4. **Structure**: the prerequisite section and the prescan of the update
   section (RFC 2136 3.2, 3.4.1): FORMERR or NOTZONE, or REFUSED beyond 256
   records. A record added, or tested by value, without the RDATA that its
   type requires gets FORMERR.
5. **Policy**: every record of the update section must be allowed, those
   that it adds within the bounds of their rule (TTL, content, number), and
   every name of the prerequisite section updatable by the key, or REFUSED.
   The update of a zone on an `rfc2136` backend then goes to its relay, which
   returns the answer of the name server: the steps below are the job of that
   server, see [RFC 2136 servers](rfc2136.md).
6. **Lock** of the zone, which honours the deadline of the request: the
   updates of a zone run one at a time.
7. **Prerequisites**, evaluated on a view of the zone: NXDOMAIN, YXDOMAIN,
   NXRRSET or YXRRSET when one fails.
8. **Update section**, applied to the view by the rules of RFC 2136 3.4.2:
   CNAME exclusivity, SOA serial ordering, apex SOA and NS protection, one TTL
   per RRset.
9. **One call to the backend** with the RRset changes of the view; a failure
   gets SERVFAIL, and nothing is applied, unless the backend tells that the
   outcome is unknown, see [the backend contract](#the-backend-contract).
10. **Response**, signed with the key of the request; one log entry; metrics.

## The engine and the view

`zone.View` reads the RRsets of a name from the backend the first time the
update touches it, and keeps every change in memory. Records are compared in
their wire form, since miekg/dns may hold the same RDATA differently when
parsed from text. `View.Changes` returns RRset-level changes: deletions first,
then replacements, for the backends that check each change against the state
left by the previous ones.

`update` holds the RFC 2136 logic on top of the view, and returns an
`*update.Error` with the rcode and the reason of a rejection, which the server
logs.

## The backend contract

```go
type Backend interface {
    // Lookup returns every RRset of the zone owned by the canonical name.
    Lookup(ctx context.Context, zone, name string) ([]RRset, error)
    // Apply applies the changes to the zone, all or nothing.
    Apply(ctx context.Context, zone string, changes []Change) error
}
```

A change replaces a whole RRset, or deletes one. A backend must apply the
changes of a call atomically, or not at all; `ErrZoneNotFound` reports a
missing zone. A `*backend.RejectionError` turns the update down before
anything changes, such as a record that the provider cannot hold: the client
gets its rcode, and the metrics count no backend error. Atomicity does not
make the outcome certain: a write that times out, or whose connection breaks,
may have committed. A backend that cannot establish the outcome, by reading the
records back or by undoing what it wrote, returns a
`*backend.IndeterminateError`: the client gets SERVFAIL, the metrics count the
call as `indeterminate`, and the TsigoatUncertainUpdates alert fires. Any
other error means that nothing changed. A backend whose
provider holds no TTL below a minimum implements `backend.TTLFloor`: it turns
lower TTLs down, and the server raises the TTLs of an update to the minimum,
which the update log reports. The PowerDNS backend sends one PATCH request,
which PowerDNS applies in one transaction, as the Cloudflare and Scaleway
backends send one batch, or PATCH, request; when the request left whole but
its answer did not come back, the PowerDNS backend reads the RRsets again, as
the backends of the hosted providers do. The API of OVHcloud has no
transaction: its backend writes one record at a time and publishes the zone
once, at the end; when a request fails, it reads the records again and brings
them back to their content before the update, whatever the failed request
did.

The backends of the hosted providers share `internal/backend/hosted`. They read
the records of a name, with their identifiers, and group them into RRsets; to
apply a change, they read the records of its RRset again, then `hosted.Diff`
tells which records to delete, to create, or whose TTL changes, so that the
records that stay keep their identifier. `hosted.Limits` turns down, before any
request, what a provider cannot hold intact. When a write fails without telling
whether it applied, as after a timeout, the backend reads the records again and
reports a success if they show the update. These recoveries go on past the
deadline of the update, within `backend.RecoveryBudget`, which the server
waits for at shutdown.

```go
type Relay interface {
    // Update relays an update of the zone, signed by key, and returns the
    // rcode that the client gets.
    Update(ctx context.Context, zone, key string, prerequisites, updates []dns.RR) (int, error)
    // SOA returns the SOA record of the zone.
    SOA(ctx context.Context, zone string) (dns.RR, error)
    // Check checks that the relay reaches the zone, without changing it.
    Check(ctx context.Context, zone string) error
}
```

A relay evaluates the updates itself: the `rfc2136` backend sends them to a
name server, the `webhook` backend to an HTTP endpoint, which apply them. A
`*backend.RejectionError` turns an update down, such as the prerequisites
that a webhook cannot evaluate. A `*backend.IndeterminateError` tells that
the server or the endpoint may have applied an update whose exchange failed
once it was sent, as on a timeout. Other errors are those of the server or of
the configuration, which the client gets as SERVFAIL. The server takes no lock
for the zones of a relay; the webhook backend sends the updates of a zone one
at a time itself, while the endpoint answers within its timeout.

## Queries

Clients find the zone of a name with SOA queries. tsigoat answers those of the
zones it serves, signed or not: the SOA in the answer section at the apex, in
the authority section below it. The answers reuse the SOA of a zone for 30
seconds, a failure to read it for 5, from the end of the read, so that
queries, which anyone may send, do not reach the backend each time; one read
at a time, which the other queries wait for until their deadline. Other
queries and opcodes get NOTIMP, and those of other zones REFUSED.

Over UDP, a response fits in 512 octets, or in the payload size that the
client advertises with EDNS, up to 1232: compressed if need be, then cut down
to its question and its OPT and TSIG records, with TC set, for the client to
retry over TCP. Only the SOA of a zone with long names takes that much room.

## Testing

| Layer | What it checks | Where |
| --- | --- | --- |
| Unit tests | Every package, with `-race` and a shuffled order; coverage floors on `update`, `zone` and `auth` | `go test ./...`, `task test:unit` |
| Fuzzing | Configuration, engine, whole request handling, name patterns | `Fuzz*` targets, `task test:fuzz`; ten minutes each, nightly |
| Backend conformance | The contract of a backend: RRsets replaced and deleted whole, the others left alone, TXT contents and every record type kept intact, atomicity, and what the backend cannot hold turned down without any change | `internal/backend/backendtest`, on the in-memory backend, PowerDNS and the simulated APIs of the hosted providers |
| Scenarios in process | Each scenario of `test/scenario/scenarios` against tsigoat on the in-memory backend | `internal/app` |
| Scenarios on the providers | The same scenarios on the simulated APIs of Cloudflare, OVHcloud and Scaleway, with the divergences of each provider listed with their reason | `internal/app` |
| Live tests | The conformance suite and the challenges of a certificate against the providers themselves, with the test zones and credentials of a developer | `test/live`, `task test:live` |
| Scenarios end to end | The same scenarios against a tsigoat binary and PowerDNS 4.9 and 5.0; faults injected with toxiproxy | `test/e2e`, `task test:e2e` |
| Scenarios relayed | The same scenarios through a tsigoat that relays the updates to another tsigoat on the in-memory backend, and through a webhook that applies them with the engine, but those with prerequisites | `internal/app` |
| Webhook example | nsupdate through tsigoat to `examples/webhook/webhook.py`, with each authentication; the refusal of a replay | `task test:webhook` |
| Differential | The same scenarios against BIND 9, the reference implementation, with the intended divergences listed with their reason; and through tsigoat relaying to BIND, where every scenario passes | `test/differential`, `task test:differential` |
| Real clients | nsupdate; lego and certbot getting certificates from Pebble | `task test:clients`, `task test:acme` |
| Helm chart | The chart rendered with every example and fixture: the configuration valid in the pod, ports, probes, mounts and selectors in agreement, invalid values refused, the alerts unit-tested with promtool, the objects valid for kubeconform | `test/chart`, `task test:helm` |
| Acceptance | tsigoat installed with its chart in a k3s cluster, under the restricted Pod Security profile; cert-manager gets certificates through it, with explicit, legacy and unsigned setups | `task test:acceptance`, nightly |
| Mutation | Mutants of `update`, `zone` and `auth` that the tests miss | `task test:mutation`, nightly |

A scenario describes a zone, requests in the syntax of nsupdate, and the
expected outcome. [CONTRIBUTING.md](../CONTRIBUTING.md#test-scenarios) shows
how to write one.
