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
| F01 | Confirmed | Fixed: OVHcloud restores the state before the update, or reports an unknown outcome | `7cf32f8`, `da85857` |
| F02 | Confirmed | Fixed: each conversion boundary decodes once; escaped strings round-trip | `8b10a2c` |
| F03 | Confirmed | Fixed: Scaleway refuses empty TXT strings | `8b10a2c` |
| F04 | Confirmed | Fixed: one recovery budget, which shutdown and the chart allow for | `7cf32f8` |
| F05 | Confirmed | Fixed: honest ordering contract, request identifiers, unknown outcomes, success at the status | `461f643` |
| F06 | Confirmed | Fixed: replays refused by the example, honest transport claims, warnings, same-origin redirects | `461f643`, `a1e331d`, `c46df95` |
| F07 | Confirmed | Fixed in the example | `461f643` |
| F08 | Confirmed | Fixed: blank secrets refused | `4ff3c4b` |
| F09 | Confirmed | Fixed: every inline header value refused | `47e3798` |
| F10 | Confirmed | Fixed: UDP responses fit the budget of the client, with TC | `8033dc8` |
| F11 | Confirmed | Fixed: failure expiry from the end of the read, cancellable wait | `0635b3c` |
| F12 | Confirmed | Fixed: RFC 8945 length rules, BADTRUNC under a full-MAC policy | `53aed06` |
| F13 | Confirmed | Fixed: additions without the RDATA of their type get FORMERR | `6741fcb`, `06fc528` |
| F14 | Confirmed | Guarantee corrected; then several replicas whose writes keep each other's records | `ca07db7`, `42c3a70`, `3d8a915` |
| F15 | Confirmed | Fixed: one toolchain for tests, scans and releases; scanner pinned | `5cb039a` |
| F16 | Confirmed | Fixed: second YAML document and escaped names refused | `8372c29`, `06fc528` |
| F17 | Confirmed | Fixed in the code: no loss on PowerDNS 4.9 | `299e338` |
| F18 | Confirmed | Fixed | `d7d8ad6` |
| F19 | Confirmed | Fixed | `c753373` |
| A01 | Agreed | Unknown outcomes in the backend contract, for every remote backend | `da85857`, `5922410`, `461f643`, `a6e29ec`, `fb6052e`, `06fc528` |
| A02 | Partly agreed | Hidden OVHcloud state removed; PowerDNS preservation state kept | `7cf32f8` |
| A03 | Partly agreed | Duplicate canonicalization removed; record model unchanged | `89cb154` |
| A04 | Deferred | No change | — |
| A05 | Partly done | Unknown outcomes measured; benchmarks and admission control deferred | `da85857` |
| A06 | Partly done | Faults after commit, codec round trips, injected retry waits, wire fixtures, isolated fuzzing | several, below |
| A07 | Mostly done | Pipeline status, path filters, stale text, toolchain; artifact export deferred | `b0d0f28`, `a2d06a6`, `fc3dc51`, `3fa5a3d` |

Two defects outside the audit came up on the way, and are fixed:
`tsigoat_tsig_failures_total` never counted anything (`129439e`), and the
PowerDNS backend reported a PATCH request that lost its answer as a failure
that changed nothing (`a6e29ec`).

## Findings

### F01 — OVH partial publication

**Confirmed.** The compensation undid the steps before the failed one, and
took an error for a request that applied nothing.

**Action.** The OVHcloud backend no longer compensates step by step. It reads
the records of the update before writing. When a request or the refresh
fails, it reads them again and brings every RRset of the update back to its
content before the update, TTLs included, whatever the failed request did
(`hosted.Restore`); it reads the result back to check it, then refreshes the
zone, so that the name servers serve nothing of the update. When restoring
or checking fails, or when publishing the restored records fails after a
refresh that may have published part of the update, the error is a
`*backend.IndeterminateError` (see A01): the update log tells so, the metrics
count the call as `indeterminate`, and the new `TsigoatUncertainUpdates` alert
fires. The private flag of the zones to refresh, which relied on a later
non-empty Apply, is gone (A02).

**Tests.** The OVHcloud simulation can apply a request and then fail it
(`ovhtest.Failure{AfterCommit: true}`). `TestRecovery` covers a committed
creation, deletion and TTL change, a committed refresh, a refresh that fails
again after restoring, and a failed restore.

**Left.** OVHcloud has no transaction: another writer that refreshes the zone
during an update publishes part of it. `docs/ovh.md` says so.

### F02 — Cloudflare conversions

**Confirmed**, for NAPTR and for SVCB/HTTPS.

**Action.** miekg/dns holds the character-strings of NAPTR, CAA and URI
records, and SVCB parameter values, in escaped presentation form. The
Cloudflare backend now unescapes them once into the raw strings of the API,
and writes SVCB values with the escapes of miekg/dns alone, quoted once. The
simulation renders API content in presentation format with the escaping of
the provider rather than with Go quoting. Strings that hold bytes outside
printable ASCII are refused before writing, since their preservation is not
established. OVHcloud and Scaleway refuse NAPTR and CAA strings with quotes or
backslashes, as they do for TXT strings, until a live test shows that they
keep them.

**Tests.** `TestRoundTrip` round-trips backslashes, quotes, escaped separators
and `alpn="h2;foo"`. The conformance suite gains a NAPTR record with a
backreference, which runs on every backend: memory, PowerDNS, the three
simulations, and the live providers.

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
of a zone one at a time, as the example does. A request that fails once it
left whole, on a timeout or a broken connection, and the 502 and 504 of a
gateway, return an `IndeterminateError`. Every request carries an `id`, 128
random bits that the signature covers, for endpoints that want idempotency.
The status of the answer decides a success: the relay no longer waits for
the body, whose read errors it used to ignore (the P3 part of the finding).

**Left.** A status or reconciliation API, for stronger guarantees, is a
decision (below).

### F06 — Webhook replay and transport claims

**Confirmed.**

**Action.** The `id` above; the example remembers the identifiers that it
accepted while their timestamp lets them in, and answers a replay 409. Since
it forgets them when it stops, it refuses the requests signed before it
started, which a previous run may have accepted (`c46df95`).
`docs/webhook.md` and `docs/security.md` now say that the timestamp bounds the
age of a replay without stopping one, and that the signature authenticates
the requests but not the answers, so that verified HTTPS is needed across a
network. `check-config` warns of plain HTTP beyond the loopback even with a
signature, and of the answers that `insecureSkipVerify` lets an intermediary
fake. `followRedirects` follows 307 and 308 to the same scheme and host
alone.

**Tests.** The example test sends a replay, and a request signed before the
example started, and checks their 409; the redirect tests of `httpclient` and
`webhook` cover another origin and plain HTTP.

### F07 — Webhook example blocked before authentication

**Confirmed**, for the example alone.

**Action.** The example checks the declared length (missing, malformed, too
large) before reading the body, bounds each read with a ten-second socket
timeout, and presents itself as a starting point for the loopback, not a
service to expose. It stays single-threaded on purpose: that keeps the
updates of a zone in order (F05).

**Tests.** The example test sends a request without length.

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
RFC 8945 5.3 truncates a signed response. TCP responses stay whole.

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

**Confirmed.** **Action:** the chart, `docs/operations.md` and
`docs/security.md` say that Recreate holds during a rollout alone: a pod
deleted by hand or evicted gets its replacement at once, while it finishes
its updates in progress, for 26 seconds at most; they advise against deleting
the pod while updates run.

**Left.** Fencing is a decision (below): neither a single-replica StatefulSet
nor a lease removes every stale writer, as the audit notes, and both cost
availability or complexity.

**Follow-up, the same day.** The maintainer chose availability over fencing,
and no lease: a lock on the Kubernetes API would load it in proportion to the
traffic, and fail during the maintenances of the control plane. The engine
now sends the records that an update adds and removes, which the backends
apply to the records as they stand (EXTEND and PRUNE at PowerDNS), so that
concurrent instances keep each other's records (`42c3a70`); the chart runs
two replicas, with a rolling update and a PodDisruptionBudget (`3d8a915`).
What holds within one instance alone, a change of TTL, prerequisites and
CNAME transitions, is documented as an assumed choice, with the ways to keep
it: a single replica, or the affinity of a client to one pod.

### F15 — Different Go toolchains

**Confirmed.** **Action:** `go.mod` names the toolchain, `go1.27.2`, which
`setup-go` and `GOTOOLCHAIN=auto` select for releases, CodeQL and the Dagger
pipelines alike; `task check:toolchain`, part of the drift checks, fails when
the golang image of `dagger/base.go` names another version. govulncheck is
pinned, and Renovate moves it.

### F16 — Configuration acceptance gaps

**Confirmed.** **Action:** a second YAML document is an error. Names written
with escapes, such as `\101xample.test.`, are refused in zone names, key names
and policy patterns, rather than normalized: no real zone or key needs them,
and refusing keeps one spelling for the configuration and the wire. **Tests:**
invalid fixtures for both.

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
- OVHcloud restores the records, or reports an unknown outcome (F01);
- the RFC 2136 relay tells apart an exchange that failed before the update
  left, from one that failed after (`5922410`), and the webhook relay does the
  same (`461f643`);
- a request that never left whole is a plain failure at every provider
  (`fb6052e`), so that an outage does not read as an unknown outcome.

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
(`indeterminate`). Benchmarks, an admission budget, queue-wait and
rate-limit metrics are deferred: the request bound, the per-zone lock with
its deadline and the ten-second request timeout bound the work of a request,
ACME traffic is small, and the audit itself asks for measurements before
optimizations. How much exposure to plan for is a decision (below).

### A06 — Diverse oracles and failures after commit

**Partly done.** Added: failures after commit in the OVHcloud simulation, for
every step and the refresh (F01); lost answers and gateway errors after a
committed or uncommitted PATCH in the PowerDNS fake (`a6e29ec`); round trips
of escaped strings and a NAPTR backreference in the conformance suite (F02);
TXT string boundaries (F03); retries with an injected wait (F19); requests
built octet by octet (F13); truncated MACs on real signed requests (F12);
response sizes over UDP (F10). `FuzzServeDNS` now gives every input a new
server and backend, so that a failure reproduces from its input alone, and
can sign an input at the time of the test, so that it explores the policy and
the engine of the secured zone rather than failing the signature
(`184d512`).

**Deferred:** recorded responses of the real provider APIs, which need the
live tests to run first; and a wider fault matrix (cancellation by the client,
retries interleaved with later updates).

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

## Decisions for the maintainer

1. **Fencing (F14).** Keep the documented limitation of one Deployment with
   Recreate, or move to a single-replica StatefulSet, or add a lease with the
   handling of a lost lease. None of them stops every stale writer. Decided
   after this response: several replicas whose writes keep each other's
   records, see F14.
2. **Stronger webhook guarantees (F05).** Endpoints get an `id` and an
   ordering requirement; a status or reconciliation API would let tsigoat
   settle unknown outcomes, at the cost of a larger protocol.
3. **Truncated TSIG MACs (F12).** A per-key opt-in would be small, since
   verification already accepts them within the bounds of RFC 8945. lego,
   certbot, cert-manager and nsupdate send full MACs by default, as far as we
   know; the recommendation is to wait for a client that needs it. Related: a MAC size out of bounds gets FORMERR without TSIG
   error, and is counted in `tsigoat_dns_responses_total` but not in
   `tsigoat_tsig_failures_total`.
4. **Capacity (A05).** Whether an admission budget and overload metrics are
   needed depends on how exposed the deployments are; benchmarks first.
5. **CI artifacts (A07).** Whether to export test, coverage, mutation and fuzz
   reports from the workflows.

## Verification

Through Task and Dagger, on the fixed source:

| Check | Result |
| --- | --- |
| `task check`, on `184d512` | Passed: drift checks, the toolchain included; every linter, Go with 0 issues; 1,224 unit tests with 38 documented skips, under the race detector in shuffled order; Helm tests; PowerDNS 5.0 end-to-end, 155 tests and 2 skips; nsupdate; lego and certbot against Pebble; the webhook example; the BIND differential, 206 tests and 12 intended skips; Gitleaks, govulncheck and Trivy. |
| `task test:e2e PDNS_VERSION=4.9`, on `184d512` | Passed: 155 tests and 2 skips, against 3 skips at the audit: the disabled records survive (F17). |
| `task test:acceptance`, on `c46df95` | Passed: cert-manager, through the chart in k3s, got both its certificates through tsigoat. |
| Later commits | `c46df95` passed `task test:webhook`; the documentation commits passed the Markdown lint. |
| Fuzzing | `FuzzServeDNS`, isolated, for two minutes: 24 million inputs, no failure. It found at once an input that miekg/dns signs but cannot read back, which the harness now skips. |
| Regression tests | The new tests fail with their fix reverted: checked for F10, F11, the TSIG metric, the unknown outcomes of PowerDNS, and the failures that never left at the hosted providers. |
| Not run | The live provider tests, for want of credentials; mutation testing; long fuzzing. |
