# Response to the project audit of 2026-10-21

**Response by Claude Opus 5.5 (effort Max).**

This document answers [the project audit of 2026-10-21](2026-10-21-project-audit.md),
which reviewed revision `9afbd4c`. Every finding was checked against the
source before any change, and every one of them held. The fixes are commits
on `main` after the audited revision; each message names the finding that it
addresses. A finding or a recommendation left without action, in
whole or in part, says why, and the decisions that belong to the maintainer
close the document.

## Outcome at a glance

| ID | Verdict | Outcome | Commits |
| --- | --- | --- | --- |
| F01 | Confirmed | Fixed: OVHcloud takes back what the answers of its requests tell, or reports an unknown outcome, and never takes back the records of another writer | `7cf32f8`, `da85857`, `abf3cba`, `66ff754` |
| F02 | Confirmed | Fixed: each conversion boundary decodes once; the CAA and URI strings of a request keep their backslashes at every backend | `8b10a2c`, `dd1b337` |
| F03 | Confirmed | Fixed: Scaleway refuses empty TXT strings | `8b10a2c` |
| F04 | Confirmed | Fixed: one recovery budget, which shutdown and the chart allow for | `7cf32f8` |
| F05 | Confirmed | Fixed: honest ordering contract, request identifiers, unknown outcomes, outcome told by the status | `461f643`, `04dedc2` |
| F06 | Confirmed | Fixed: replays refused by the example across its restarts, honest transport claims, warnings, same-origin redirects | `461f643`, `a1e331d`, `0d8651b` |
| F07 | Confirmed | Fixed in the example: a request has ten seconds to come whole | `461f643`, `0d8651b` |
| F08 | Confirmed | Fixed: blank secrets refused | `4ff3c4b` |
| F09 | Confirmed | Fixed: every inline header value refused | `47e3798` |
| F10 | Confirmed | Fixed: UDP responses fit the budget of the client, with TC, but those whose question and signature alone exceed it | `8033dc8`, `80e8cb7` |
| F11 | Confirmed | Fixed: failure expiry from the end of the read, cancellable wait | `0635b3c` |
| F12 | Confirmed | Fixed: RFC 8945 length rules, BADTRUNC under a full-MAC policy | `53aed06` |
| F13 | Confirmed | Fixed: additions without the RDATA of their type get FORMERR | `6741fcb`, `06fc528` |
| F14 | Confirmed | Several replicas, whose writes keep each other's records, TTL floor included; what holds within one alone, and with session affinity, documented | `ca07db7`, `42c3a70`, `3d8a915`, `0f8637d`, `ce778cf`, `3141e26`, `099be7c` |
| F15 | Confirmed | Fixed: one toolchain for tests, scans and releases, checked in CI; scanner pinned | `5cb039a`, `6aa5d63` |
| F16 | Confirmed | Fixed: second YAML document refused, and the names that a request would spell otherwise | `8372c29`, `06fc528`, `5865d6c` |
| F17 | Confirmed | Fixed in the code: no loss on PowerDNS 4.9 | `299e338` |
| F18 | Confirmed | Fixed | `d7d8ad6` |
| F19 | Confirmed | Fixed | `c753373` |
| A01 | Agreed | Unknown outcomes in the backend contract, for every remote backend and relay, tested after timeouts and cancellations | `da85857`, `5922410`, `461f643`, `a6e29ec`, `fb6052e`, `06fc528`, `abf3cba`, `04dedc2`, `05da985`, `7778db6`, `91ec6ab`, `32a1ac3` |
| A02 | Partly agreed | Hidden OVHcloud state removed; PowerDNS preservation state kept | `7cf32f8` |
| A03 | Partly agreed | Duplicate canonicalization removed; record model unchanged | `89cb154` |
| A04 | Deferred | No change | — |
| A05 | Partly done | Unknown outcomes measured, and alerted on from their time; benchmarks and admission control deferred | `da85857`, `1d4d91b` |
| A06 | Partly done | Faults after commit, writes that land after their timeout, codec round trips, injected retry waits, wire fixtures, isolated fuzzing | several, below |
| A07 | Mostly done | Pipeline status, path filters, stale text, toolchain; artifact export deferred | `b0d0f28`, `a2d06a6`, `fc3dc51`, `3fa5a3d` |

Three defects outside the audit came up on the way, and are fixed:
`tsigoat_tsig_failures_total` never counted anything (`129439e`), the
PowerDNS backend reported a PATCH request that lost its answer as a failure
that changed nothing (`a6e29ec`), and the `Recreate` strategy of the chart
rendered beside the `rollingUpdate` of the defaults, which Kubernetes refuses
(`ce778cf`).

## Findings

### F01 — OVH partial publication

**Confirmed.** The compensation undid the steps before the failed one, and
took an error for a request that applied nothing.

**Action.** The OVHcloud backend no longer compensates step by step from its
plan. Its requests write what their answers tell in a journal: the records
that they created, by the identifiers that OVHcloud returns, and those that
they deleted or retimed. When a request or the refresh fails, the backend
takes back what the journal holds, and that alone: it deletes the records
created, by identifier, creates again those deleted, gives back their TTL to
those retimed, reads the result back to check it, then refreshes the zone, so
that the name servers serve nothing of the update. A request that fails
without telling whether it applied, such as one that times out or answers a
server error, may have applied, or apply after the recovery, and nothing
tells its effect apart from what another writer does, such as another
instance of tsigoat that adds the same value meanwhile: its outcome stays
unknown, and the recovery leaves the records of its data alone rather than
delete the record of another writer (`abf3cba`, `66ff754`). When taking back
or checking fails, or when publishing the records taken back fails after a
refresh that may have published part of the update, the error is a
`*backend.IndeterminateError` too (see A01): the update log tells so, the
metrics count the call as `indeterminate`, and the new
`TsigoatUncertainUpdates` alert fires. The private flag of the zones to
refresh, which relied on a later non-empty Apply, is gone (A02).

**Tests.** The OVHcloud simulation can apply a request and then fail it
(`ovhtest.Failure{AfterCommit: true}`), or hold it until its client gives up,
then apply it (`ovhtest.Failure{Late: true}`). `TestRecovery` covers a
rejected creation and TTL change, taken back; a committed creation, addition,
removal, deletion and TTL change; a committed refresh; a refresh that fails
again after taking back; a failed take-back; and a creation and an addition
that apply after their timeout, or after the cancellation of their update.
`TestRecoveryBesideAnotherWriter` runs the case of two writers: the request
of a first instance lands after its timeout, while a second one adds the same
value; the first one keeps the record of the second, and reports an unknown
outcome.

**Left.** OVHcloud has no transaction: another writer that refreshes the zone
during an update publishes part of it. `docs/ovh.md` says so.

### F02 — Cloudflare conversions

**Confirmed**, for NAPTR and for SVCB/HTTPS, and wider for CAA and URI:
miekg/dns decodes the value of a CAA record and the target of a URI record
from the wire as raw bytes, but parses, encodes and writes them in escaped
form, so that a backslash in a request went at every backend that wrote the
record again, not at Cloudflare alone.

**Action.** miekg/dns holds the character-strings of NAPTR records, and SVCB
parameter values, in escaped presentation form, and tsigoat gives CAA values
and URI targets that form as soon as it parses a request, and in
`backend.Canonical` (`dd1b337`). The Cloudflare backend unescapes them once
into the raw strings of the API, and writes SVCB values with the escapes of
miekg/dns alone, quoted once (`8b10a2c`). The simulation renders API content
in presentation format with the escaping of the provider rather than with Go
quoting. Strings that hold bytes outside
printable ASCII are refused before writing, since their preservation is not
established. OVHcloud and Scaleway refuse NAPTR and CAA strings with quotes or
backslashes, as they do for TXT strings, until a live test shows that they
keep them.

**Tests.** `TestRoundTrip` round-trips backslashes, quotes, escaped separators
and `alpn="h2;foo"`, from records as a request carries them. Two scenarios
send a CAA and a URI record with a backslash, over the wire, to every
backend, through the relays, and to BIND; the scenarios compare canonical
forms, since a right value and a mangled one wrote alike as text. The
conformance suite takes the records as a request carries them, and gains a
NAPTR record with a backreference; it runs on every backend: memory,
PowerDNS, the three simulations, and the live providers.

**Left.** The simulation is ours (see A06): only `task test:live` checks what
Cloudflare stores.

### F03 — Scaleway trailing empty TXT string

**Confirmed.** **Action:** Scaleway refuses a TXT record with an empty string,
before writing. **Tests:** `TestTXTStrings` covers 254 and 255 octets, 256
octets in two strings, two and three full strings, a short first string, an
empty last string, an empty string, and a trailing space.

### F04 — Recovery without an overall deadline

**Confirmed.**

**Action.** `backend.RecoveryBudget`, 15 seconds, and `backend.RecoveryContext`:
the recoveries and checks that go on past the deadline of an update (OVHcloud
restore, read-back at Cloudflare, Scaleway and PowerDNS) share one budget,
detached from the cancellation of the client but bounded. When it runs out,
the outcome is unknown and reported as such, never taken for "nothing
applied". The server waits at shutdown for the request timeout plus that
budget, 26 seconds, which the 30 seconds of the chart's
`terminationGracePeriodSeconds` cover; `docs/operations.md` says so.

**Left.** The zone lock stays held during a recovery, on purpose: another
update of the zone must not interleave with a restore. It is bounded at 25
seconds.

### F05 — Webhook ordering after a timeout

**Confirmed.**

**Action.** `docs/webhook.md` no longer claims that the endpoint never applies
two updates of a zone at once: the relay keeps them apart only while the
endpoint answers within the timeout, and the endpoint must apply the updates
of a zone one at a time, as the example does. The status of an answer tells
the outcome: 2xx, the update applied; 4xx, nothing applied; 5xx, maybe in
part, as the example answers 500 once it applied part of an update
(`04dedc2`). A request that fails once it may have left whole, on a timeout
or a broken connection, and a 5xx, return an `IndeterminateError`. Every request
carries an `id`, 128
random bits that the signature covers, for endpoints that want idempotency.
The status of the answer decides a success: the relay no longer waits for
the body, whose read errors it used to ignore (the P3 part of the finding).

**Left.** A status or reconciliation API, for stronger guarantees, is a
decision (below).

### F06 — Webhook replay and transport claims

**Confirmed.**

**Action.** The `id` above; the example remembers the identifiers that it
accepted while their timestamp lets them in, and answers a replay 409. It
keeps them in a state file, written before it applies a request and read
back when it starts, so that a restart forgets none: a request signed by a
clock up to five minutes ahead stays valid that long after a restart
(`0d8651b`).
`docs/webhook.md` and `docs/security.md` now say that the timestamp bounds the
age of a replay without stopping one, and that the signature authenticates
the requests but not the answers, so that verified HTTPS is needed across a
network. `check-config` warns of plain HTTP beyond the loopback even with a
signature, and of the answers that `insecureSkipVerify` lets an intermediary
fake. `followRedirects` follows 307 and 308 to the same scheme and host
alone.

**Tests.** The example test sends a replay, then restarts the example and
replays requests again, one of them signed two minutes ahead, and checks
their 409; the redirect tests of `httpclient` and `webhook` cover another
origin and plain HTTP.

### F07 — Webhook example blocked before authentication

**Confirmed**, for the example alone.

**Action.** The example checks the declared length (missing, malformed, too
large) before reading the body, gives a request ten seconds to come whole,
read after read, so that a client that stalls or sends its bytes one by one
holds it ten seconds at most (`0d8651b`), and presents itself as a starting
point for the loopback, not a service to expose. It stays single-threaded on
purpose: that keeps the updates of a zone in order (F05).

**Tests.** The example test sends a request without length, and a client that
sends a byte a second.

### F08 — Empty resolved secrets

**Confirmed.** **Action:** a secret read from a file or an environment
variable that holds nothing but whitespace is an error naming the setting,
for every secret of the configuration. **Tests:** fixtures for a blank
signature secret file and a blank bearer token variable.

### F09 — Inline webhook headers in the ConfigMap

**Confirmed.** **Action:** the chart refuses every inline
`webhook.headers[].value`, since no list of names can tell a secret header
from another; values come from the chart's Secret through `valueFile`.
**Tests:** an invalid chart fixture, and the valid webhook fixture moved to
`valueFile`.

### F10 — UDP responses beyond the client's budget

**Confirmed.**

**Action.** A response that does not travel over TCP now fits in 512 octets
without EDNS, or in the payload size that the client advertises, between 512
and the 1232 octets that tsigoat advertises. Room for the TSIG record, with
its full MAC, is reserved first. A response that does not fit is compressed,
then cut down to its question and its OPT and TSIG records, with TC set, as
RFC 8945 5.3 truncates a signed response. A response that does not fit even
so, whose question and TSIG record take the room alone, as for a request
about as large with long names, goes out larger, with TC set, which the
architecture guide says (`80e8cb7`). TCP responses stay whole.

**Tests.** An SOA with two 255-octet names, truncated without EDNS and with
EDNS 512, whole with 1232, signed responses that still verify, TCP whole; a
response that fits only compressed; a 512/513-octet boundary that catches an
off-by-one in the TSIG reservation. `FuzzServeDNS` checks the size of every
response.

### F11 — Slow SOA failures and the cache wait

**Confirmed.** **Action:** the expiry of a cached SOA, or of a failure to read
it, counts from the end of the read; the cache is taken through a channel, so
that a waiting query gives up at its deadline. **Tests:** a failing backend
slower than the failure time gives one read for two queries; a waiter with a
50 ms deadline returns while another read hangs.

### F12 — Truncated TSIG MACs

**Confirmed.**

**Action.** The keyring applies RFC 8945 5.2.2.1: a MAC longer than the output
of the algorithm, or shorter than the larger of 10 octets and half that
output, makes the request corrupt, which gets FORMERR without TSIG record; a
truncated MAC within the bounds verifies on its prefix, in constant time.
tsigoat keeps requiring full MACs, as RFC 8945 lets a local policy do: a
truncated MAC that verifies gets BADTRUNC, signed with the truncated request
MAC, once the time verified, in the order of RFC 8945 5.2.

**Tests.** Six algorithms in `internal/auth`, and real signed requests: 16
octets get BADTRUNC, 15 FORMERR, a wrong 16-octet MAC BADSIG, an hour-old one
BADTIME.

**Left.** Accepting truncated MACs, per key, is a decision (below).

### F13 — Additions without RDATA

**Confirmed.** **Action:** an addition or a value-dependent prerequisite that
comes with an empty RDATA, for a type that requires some, gets FORMERR. The
check compares the record with the empty record of its type rather than
encoding it, since empty MX or SRV records encode back into some octets; NULL,
APL, EID, NIMLOC and unknown types may be empty. **Tests:** messages built
octet by octet (`internal/update/rdata_test.go`), a table of types, and a
server test where a signed empty A record gets FORMERR and applies nothing.

### F14 — Recreate is not fencing

**Confirmed.** Recreate holds during a rollout alone (`ca07db7` corrected the
claim); and nothing fences a stale writer: neither a single-replica
StatefulSet nor a lease, as the audit notes. A lease would also put the
Kubernetes API in the path of every update, in proportion to the traffic,
and stop the updates during the maintenances of the control plane.

**Action.** The maintainer chose availability over fencing: rather than keep
a single writer, tsigoat makes concurrent instances safe for the updates
that matter. The engine sends the records that an update adds and removes,
which the backends apply to the records as they stand (EXTEND and PRUNE at
PowerDNS), so that concurrent instances keep each other's records
(`42c3a70`); the chart runs two replicas, with a rolling update and a
PodDisruptionBudget (`3d8a915`). The server raises the TTLs below the minimum
of a provider before it tells an addition from a replacement, so that a
record added at 30 seconds to an RRset that the provider holds at 60 stays an
addition (`0f8637d`). This holds on the hosted providers, and on PowerDNS
since 4.9.12 and 5.0.2, which take EXTEND and PRUNE: the documentation now
says so, and tells to run a single instance in front of an older PowerDNS.
What holds within one instance alone, a change of TTL, prerequisites and
CNAME transitions, is documented as an assumed choice, which accepts the
risk of overlapping writers for those changes. A single replica, with the
`Recreate` strategy, avoids it during rollouts alone: a pod deleted by hand or
evicted gets its replacement at once, while it finishes its updates in
progress, for 26 seconds at most, which the documentation tells again
(`099be7c`). Session affinity keeps those guarantees between the updates of
one client alone, such as the concurrent challenges of one cert-manager, not
between clients (`3141e26`). The `Recreate`
strategy, as the documentation told to set it, rendered beside the
`rollingUpdate` of the defaults, which Kubernetes refuses: the chart now
leaves it out (`ce778cf`).

**Tests.** Two instances add, then remove, sixteen challenges of one name at
once, in process on every backend at a TTL below the minimum of the
providers, and end to end on PowerDNS 4.9 and 5.0: no addition is lost, and
no removed value stays; without `0f8637d`, each simulation of a provider
loses values within a few runs. The acceptance test runs cert-manager through two replicas; the
chart tests check that no rendered Deployment holds a `Recreate` strategy
beside `rollingUpdate`.

### F15 — Different Go toolchains

**Confirmed.** **Action:** `go.mod` names the toolchain, `go1.27.3`, which
`setup-go` and `GOTOOLCHAIN=auto` select for releases, CodeQL and the Dagger
pipelines alike; `task check:toolchain`, part of the drift checks, fails when
the golang image of `dagger/base.go` names another version, and the lint
workflow runs it (`6aa5d63`). govulncheck is pinned, and Renovate moves it.

### F16 — Configuration acceptance gaps

**Confirmed.** **Action:** a second YAML document is an error (`8372c29`). A
name is valid only when a request spells it alike: once encoded and decoded
by miekg/dns, it reads the same, without escapes. Escapes such as
`\101xample.test.`, characters that the presentation format escapes, such as
`@`, and bytes outside ASCII are refused in zone names, key names and policy
patterns, rather than normalized: no real zone or key needs them, and one
spelling serves the configuration and the wire (`5865d6c`). **Tests:**
invalid fixtures for a second document, an escaped name, a name with `@`, and
a key name outside ASCII.

### F17 — Disabled records on PowerDNS 4.9

**Confirmed.** **Action:** fixed in the code rather than in the documentation.
The backend reads the version of the server once, and on PowerDNS 4 reads the
whole zone instead of filtering by `rrset_name`, which leaves the disabled
records out there; Apply then keeps them as it does on PowerDNS 5. The
known-defect marker is gone: `TestDisabledRecordsSurvive` passes against
PowerDNS 4.9.17 and 5.0.

**Cost.** A lookup reads the whole zone on PowerDNS 4.9, which
`docs/powerdns.md` states for large zones.

### F18 — Live ACME residue

**Confirmed.** **Action:** the ACME flow of `test/live` deletes the TXT RRset
of its challenge name before its first update, and once it is over, with a
bounded context of its own, reporting a failed cleanup. golangci-lint did not
build the live tests, whose build tag it lacked; it does now.

### F19 — Retry-After shortened

**Confirmed.** **Action:** the five-second cap bounds the backoff that tsigoat
chooses alone; a delay that the provider asks for holds whole, or the request
fails at once when the deadline of the update leaves no time for it.
`Retry-After` is read as seconds or as an HTTP date; a past date asks for no
delay; a delay beyond a minute fails at once. **Tests:** `TestRetryAfter` and
`TestRetryDelays`, with an injected wait.

## Architectural recommendations

### A01 — Honest guarantees per mutation path

**Agreed, and done.** The backend contract now tells three outcomes apart: a
`*backend.RejectionError` turns an update down before any write; a
`*backend.IndeterminateError` reports an outcome that tsigoat could not
establish; any other error means that nothing changed. Every remote backend
follows it:

- PowerDNS, Cloudflare and Scaleway read the records back after a write that
  left whole and lost its answer, or got a server error (a 502 or 504 from a
  gateway, for PowerDNS), and succeed when the records show the update
  (`a6e29ec`, `7cf32f8`);
- OVHcloud takes back what the answers of its requests tell, or reports an
  unknown outcome, as for a request that may still apply (F01);
- the RFC 2136 relay tells apart an exchange that failed before the update
  left, from one that failed after (`5922410`), and the webhook relay does the
  same (`461f643`); an answer of a name server that does not prove that the
  server sent it, unsigned, with a signature that does not verify, NOTAUTH or
  a TSIG error, which miekg/dns leaves unverified, and a 5xx of a webhook
  endpoint, which answers 4xx only when it applied nothing, leave the outcome
  unknown too (`04dedc2`, `7778db6`);
- a request that never left whole is a plain failure at every provider
  (`fb6052e`), so that an outage does not read as an unknown outcome; one
  canceled while it is written may have left whole, since over HTTP/2 the
  transport gives up on it without waiting for the end of its write: its
  outcome is unknown, at PowerDNS, at the providers and at a webhook
  endpoint alike (`91ec6ab`).

Every remote backend and relay has a test of a write that is still running
when tsigoat gives up on it, after its timeout and after the cancellation of
its update once the write reached the server whole: the simulations and the
PowerDNS fake hold the write, then apply it once tsigoat answered, and
tsigoat must have reported an unknown outcome (`abf3cba`, `05da985`,
`32a1ac3`).

The metrics count unknown outcomes apart, the `TsigoatUncertainUpdates` alert
and its runbook tell an operator what to check, `docs/architecture.md` states
the contract, and `docs/providers.md` distinguishes a commit in the API from
the publication by the name servers.

**Not done:** capability flags in the interfaces (prerequisites, atomicity,
recovery). The split between a backend and a relay already carries the
prerequisites; atomicity and recovery are documented per backend, and no code
would consume such flags today.

### A02 — State coupling between Lookup and Apply

**Partly agreed.** OVHcloud no longer keeps any pending state between calls
(F01). The PowerDNS backend keeps the disabled records that a lookup found
for the next Apply: every Apply follows the lookups of its own update, under
the lock of its zone, so that the state comes from the reads of the same
update; a read inside Apply would cost one more request per update, a whole
zone on PowerDNS 4.9 (F17), and would not stop other writers either.
The coupling is documented where it lives, and is worth revisiting if the
backend is ever wrapped or shared.

### A03 — Single sources of truth for records

**Partly agreed.** The wire round trip of the zone view now uses
`backend.Canonical`. The Cloudflare conversion says, at each boundary,
whether a string is presentation data or a raw API value (F02). The record
model, with an owner, a type and a TTL on both an RRset and its records, is
unchanged: changing it touches the engine and every backend, for no defect
found, and the zone view sets the owner and the TTL of the records that it
reads from their RRset, in one place.

### A04 — Provider composition

**Deferred.** Seven types of backend, three of them hosted providers, keep
the lists manageable, and the lagging list behind F09 is gone, since the chart now
refuses every inline header value. Centralizing provider metadata is worth
doing with the next provider, when its cost is paid anyway.

### A05 — Resource bounds and overload

**Partly done.** Unknown outcomes and failed recoveries are now measured
(`indeterminate`). The series of every backend exist at zero from the start,
and the `TsigoatUncertainUpdates` alert fires on the time of the last unknown
outcome, `tsigoat_backend_last_indeterminate_timestamp_seconds`, so that the
first incident counts, even before the first scrape of its series
(`1d4d91b`). Benchmarks, an admission budget, queue-wait and
rate-limit metrics are deferred: the request bound, the per-zone lock with
its deadline and the ten-second request timeout bound the work of a request,
ACME traffic is small, and the audit itself asks for measurements before
optimizations. How much exposure to plan for is a decision (below).

### A06 — Diverse oracles and failures after commit

**Partly done.** Added: failures after commit in the OVHcloud simulation, for
every step and the refresh, and two writers of one value (F01); updates at a
TTL below the minimum of the providers, through two instances at once (F14); lost answers and gateway errors after a
committed or uncommitted PATCH in the PowerDNS fake (`a6e29ec`); round trips
of escaped strings and a NAPTR backreference in the conformance suite (F02);
TXT string boundaries (F03); retries with an injected wait (F19); requests
built octet by octet (F13); truncated MACs on real signed requests (F12);
response sizes over UDP (F10); writes that apply after their timeout, or
after the cancellation of their update, at every remote backend and relay
(F01, A01); records as a request carries them in the conformance suite
and the scenarios (F02); replays across a restart of the webhook example
(F06); alert series that start with their incident (A05). `FuzzServeDNS` now
gives every input a new
server and backend, so that a failure reproduces from its input alone, and
can sign an input at the time of the test, so that it explores the policy and
the engine of the secured zone rather than failing the signature
(`184d512`).

**Deferred:** recorded responses of the real provider APIs, which need the
live tests to run first; and retries interleaved with later updates.

### A07 — CI evidence and pipeline selection

**Mostly done.** The mutation task keeps the exit status of gremlins
(`b0d0f28`); the path filters of the workflows include `dagger.json`, the
Dagger action and the test workflow itself (`a2d06a6`); the CLI help names
every backend (`fc3dc51`) and `CLAUDE.md` tells the current state
(`3fa5a3d`); toolchain alignment is F15.

**Deferred:** exporting JUnit, coverage, mutation and fuzz artifacts from
Dagger to the workflow runs. It is an evolution of the CI rather than a
defect, which needs the Dagger functions to return their reports and the
workflows to upload them.

## Found along the way

- `tsigoat_tsig_failures_total` never increased: miekg/dns takes the TSIG
  record out of a response as it signs it, before the metrics read it, so
  that the `TsigoatSignatureFailures` alert could never fire. The server now
  keeps the TSIG error itself, and a test counts a BADKEY (`129439e`).
- The PowerDNS backend reported a PATCH that left whole and lost its answer
  as an error that changed nothing, which the new contract forbids
  (`a6e29ec`, A01).
- The hosted providers took any failure without an HTTP status for an
  ambiguous one, a refused connection included (`fb6052e`, A01).
- `__pycache__` of the webhook example was tracked (`945552c`).
- The `Recreate` strategy of the chart, which the documentation told to set
  for a single replica, rendered beside the `rollingUpdate` of the defaults:
  Kubernetes refuses such a Deployment, which kubeconform does not check
  (`ce778cf`, F14).
- govulncheck reports GO-2026-6809, in the `crypto/x509` of Go 1.27.2, which
  trusts compromised intermediate certificates, as tsigoat does for the HTTPS
  APIs of its backends: the toolchain moved to Go 1.27.3 (`c850b83`).

## Decisions for the maintainer

1. **Stronger webhook guarantees (F05).** Endpoints get an `id` and an
   ordering requirement; a status or reconciliation API would let tsigoat
   settle unknown outcomes, at the cost of a larger protocol.
2. **Truncated TSIG MACs (F12).** A per-key opt-in would be small, since
   verification already accepts them within the bounds of RFC 8945. lego,
   certbot, cert-manager and nsupdate send full MACs by default, as far as we
   know; the recommendation is to wait for a client that needs it. Related:
   a MAC size out of bounds gets FORMERR without TSIG error, and is counted
   in `tsigoat_dns_responses_total` but not in `tsigoat_tsig_failures_total`.
3. **Capacity (A05).** Whether an admission budget and overload metrics are
   needed depends on how exposed the deployments are; benchmarks first.
4. **CI artifacts (A07).** Whether to export test, coverage, mutation and fuzz
   reports from the workflows.

## Verification

Through Task and Dagger, on the fixed source:

| Check | Result |
| --- | --- |
| `task check`, on `c850b83` | Passed: drift checks, the toolchain included; every linter, Go with 0 issues; 1,298 unit tests with 42 documented skips, under the race detector in shuffled order; Helm tests; PowerDNS 5.0 end-to-end, 163 tests and 2 skips; nsupdate; lego and certbot against Pebble; the webhook example; the BIND differential, 210 tests and 12 intended skips; Gitleaks, govulncheck and Trivy. |
| `task test:e2e PDNS_VERSION=4.9`, on `c850b83` | Passed: 163 tests and 2 skips, against 3 skips at the audit: the disabled records survive (F17). |
| `task test:acceptance`, on `c850b83` | Passed: cert-manager, through the two replicas of the chart in k3s, got its three certificates through tsigoat: with an HMAC-SHA256 key, an HMAC-MD5 key, and unsigned updates. |
| This document | Passed the Markdown lint. |
| Fuzzing | `FuzzServeDNS`, isolated, for two minutes: 24 million inputs, no failure. It found at once an input that miekg/dns signs but cannot read back, which the harness now skips. |
| Regression tests | The new tests fail with their fix reverted: checked for F10, F11, the TSIG metric, the unknown outcomes of PowerDNS, the failures that never left at the hosted providers, the two writers at OVHcloud (F01), the TTL floor before an addition (F14), the unverified answers of an RFC 2136 server (A01), and the `Recreate` strategy of the chart. |
| Not run | The live provider tests, for want of credentials; mutation testing; long fuzzing. |
