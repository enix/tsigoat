# Project audit — 2026-10-21

**Audit performed by GPT-6 Astra (effort Ultra).**

Audited revision: `9afbd4cc1e994e41660976566faf70ec5676450c` (`main`).
Date: 21 October 2026, Europe/Paris. The working tree was clean at the start.
This report follows the repository's English documentation convention.

## Overall assessment

The project has a sound foundation: a small command layer, explicit policy
checks before provider access, a staged update engine, constrained provider
adapters, and unusually broad tests for a project of this size. A rewrite would
discard useful work. The separation between DNS transport, authorization,
update evaluation, and provider integration should be preserved.

The main weakness is the gap between the guarantees expressed by the interfaces
and the guarantees actually available from remote systems. A provider-side
transaction, a sequence of compensating HTTP calls, and an arbitrary webhook
are materially different. Treating them as equivalent makes uncertain outcomes,
timeouts, recovery, and concurrent writers difficult to reason about. Several
reproduced defects arise precisely at those boundaries. Good statement coverage
and passing scenarios do not establish those distributed-system guarantees.

Before broad production use, prioritize OVH recovery, exact record preservation,
webhook security and ordering, and the claim that Kubernetes always runs at most
one writer. The ACME-only use case reduces exposure to some record-conversion
defects, but does not remove the recovery, replay, or concurrency problems.

## Scope and method

The review covered application wiring and CLI, configuration and secret loading,
TSIG and policy, DNS transport, RFC 2136 evaluation, zone state, every backend,
metrics and administration, Helm, containers, Dagger, GitHub workflows, release
configuration, documentation, and the test architecture. Three parallel reviews
examined the DNS core, hosted providers, and other backends; findings were
consolidated against the source and targeted reproductions.

This is a source and local integration audit, not a penetration test of deployed
infrastructure or a certification of RFC compliance. Live provider credentials,
production DNS zones, registry publication, and repository protection settings
were not exercised. No push, release, or production mutation was performed.

Evidence labels used below:

- **Reproduced:** a bounded local probe demonstrated the behavior. Provider
  simulations and in-memory backends are identified explicitly.
- **Source-confirmed:** the control flow establishes the issue, but its full
  operational consequences were not reproduced against a deployed system.
- **Known limitation:** already documented or deliberately excluded by a test.
- **Design recommendation:** an architectural improvement, not a newly proven bug.

P1 means address before relying on the affected behavior in production. P2 means
an important correctness, security, compatibility, or reliability issue. P3 means
a narrower robustness or maintainability problem. These are engineering
priorities, not CVSS scores.

## Findings at a glance

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| F01 | P1 | OVH compensation omits the failed operation even when it committed | Reproduced, simulated API |
| F02 | P2 | Cloudflare encoding does not preserve some NAPTR and HTTPS data | Reproduced, simulator and codecs |
| F03 | P2 | Scaleway accepts a TXT representation it changes | Reproduced, codecs |
| F04 | P2 | Recovery can outlive the request and shutdown budgets | Source-confirmed |
| F05 | P2 | Webhook client serialization does not guarantee remote ordering | Reproduced, local endpoint |
| F06 | P2 | Webhook replay and transport-security claims are too strong | Reproduced, example handler |
| F07 | P2 | One unauthenticated slow connection can stall the webhook example | Reproduced, example HTTP server |
| F08 | P2 | Empty resolved secrets can disable configured webhook authentication | Reproduced, CLI; source-confirmed send path |
| F09 | P2 | Helm allows inline authentication headers into the ConfigMap | Reproduced, Helm render |
| F10 | P2 | Large SOA replies ignore the client's UDP response budget | Reproduced, real UDP |
| F11 | P2 | Slow SOA failures defeat the negative cache | Reproduced, timed backend |
| F12 | P2 | Valid truncated TSIG MACs are classified as bad signatures | Reproduced, signed DNS request |
| F13 | P2 | Missing type-specific RDATA reaches the update engine | Reproduced, memory backend |
| F14 | P2 | Recreate does not establish the chart's single-writer guarantee | Source and Kubernetes documentation |
| F15 | P2 | CI and release select different Go toolchains | Source-confirmed and observed CI container |
| F16 | P3 | Configuration validation has silent acceptance gaps | Reproduced |
| F17 | P2 | PowerDNS 4.9 can lose disabled records during replacement | Known limitation |
| F18 | P3 | Failed live ACME tests leave records that break subsequent runs | Source-confirmed |
| F19 | P2 | Hosted HTTP retries shorten the provider's Retry-After delay | Source-confirmed |

## Detailed findings

### F01 — OVH can publish a partial update after apparently successful compensation

**P1; reproduced with the simulated OVH API.**

In [OVH Apply](../../internal/backend/ovh/apply.go), lines 50–52, a failed
`s.do(ctx)` triggers compensation of `steps[:i]`. This excludes the failing
operation. An HTTP error does not prove that the provider did not commit that
operation. The creation path at lines 138–144 returns immediately on error,
before obtaining the new record identifier.

The reproduction began with TXT `old` and requested replacement with TXT `new`.
Deleting `old` succeeded. Creating `new` committed in the simulated API, which
then returned HTTP 500. Compensation recreated `old` and refreshed the zone.
Both `old` and `new` remained, while Apply returned an error saying that the
previous steps had been undone. This is an actual partial result, not merely an
inaccurate log message.

Reconcile the uncertain operation against a recorded before-state before
deciding what to undo or publish. Simply adding the failed operation to the
compensation slice is insufficient: a failed deletion may or may not have
happened, and blind recreation can itself duplicate data. Record and expose an
unresolved outcome when reconciliation is inconclusive. Add failure injection
after server-side commit for creation, deletion, TTL changes, and refresh.

### F02 — Cloudflare conversions mix DNS presentation strings and API strings

**P2; NAPTR reproduced through the simulated API; HTTPS reproduced at the codec boundary.**

[Cloudflare conversion](../../internal/backend/cloudflare/convert.go), lines
296–300, copies `dns.NAPTR` string fields directly into API JSON fields. Some of
those strings already contain DNS presentation escaping. The simulator renders
the API fields back into DNS presentation text, adding escaping around the
backslashes already present in the copied values. A canonical NAPTR regular expression containing
a backreference survived Apply with success but read back with extra backslashes;
the input and output were not DNS-equivalent.

The same representation problem appears in `svcbOf`, lines 317–326: quoting an
already presentation-escaped parameter value can double its escaping. A canonical
HTTPS record with `alpn="h2;foo"` did not survive the local round trip through
ToAPI, reconstructed API Content, and FromAPI. This proves a codec inconsistency;
it does not establish whether the live
API would reject or store that particular payload.

Define each conversion boundary in terms of raw bytes, DNS presentation text,
or JSON text, and decode exactly once. Add round-trip properties covering
backslashes, quotes, escaped separators, and octets. When exact preservation is
not established, reject the value explicitly before writing. The provider's
[DNS record schema](https://developers.cloudflare.com/api/resources/dns/subresources/records/)
is the external contract; an HTTP success alone is not a preservation test.

### F03 — Scaleway silently removes a trailing empty TXT character-string

**P2; reproduced with Limits.Check, ToAPI, and FromAPI.**

[Scaleway `txtContent`](../../internal/backend/scaleway/convert.go), lines
96–109, checks that every nonfinal string has 255 bytes and that the joined
content is nonempty. It accepts a TXT record containing 255 printable bytes
followed by an empty character-string. ToAPI joins those strings; the round trip
returns one string instead of two.

TXT character-string boundaries are part of RDATA. This violates the backend's
stated exact-preservation policy even if an application concatenates TXT chunks.
Reject this representation, or preserve it if the provider supports doing so.
Test lengths 254, 255, and 256, empty final chunks, and multiple full chunks.

### F04 — Recovery has per-call timeouts but no overall deadline

**P2; source-confirmed reliability issue, without an end-to-end outage measurement.**

[Cloudflare verification](../../internal/backend/cloudflare/apply.go), line 188,
[Scaleway verification](../../internal/backend/scaleway/apply.go), line 114, and
[OVH compensation](../../internal/backend/ovh/apply.go), line 181, use
`context.WithoutCancel(ctx)`. They then perform sequential per-name reads or
per-record undo operations. Individual HTTP calls remain bounded, but the whole
recovery operation no longer has the DNS request's budget, ten seconds by default.

The [DNS handler](../../internal/dnsserver/handler.go), lines 295–313, retains
the zone lock until Apply returns. A large valid request followed by provider
degradation can therefore occupy the zone much longer than the advertised
request timeout or the shutdown window. This is not a demonstrated infinite
loop; the missing bound is on the sum of bounded operations and retries.

Give reconciliation an explicit overall budget, separate from the client
deadline, and model what happens when it expires. Preserve the need to repair
partial state; deleting `WithoutCancel` without a recovery strategy would make
integrity worse. Report pending or failed recovery through metrics and logs, and
align shutdown behavior with that strategy.

### F05 — A webhook timeout permits overlapping remote mutations

**P2; reproduced against a controlled local HTTP endpoint.**

[Webhook `post`](../../internal/backend/webhook/webhook.go), lines 270–297,
releases its per-zone lock when the HTTP client returns. The remote operation
can continue after that client timeout. A second same-zone request then starts
while the first still runs. The probe timed out the first request after 100 ms
and observed two concurrent remote operations when the second request arrived.

The statement in [the webhook documentation](../webhook.md), lines 90–91, that
the endpoint never applies two updates of a zone at once is therefore too
strong. Add/delete ordering can change after a timeout. The bundled Python
server has its own global serialization, but custom endpoints cannot infer
ordering from the relay's mutex.

Require endpoint-side ordering and define request identity, retry, and uncertain
outcome semantics. A client mutex alone cannot prove that a remote operation has
finished. Consider an idempotency identifier and a status/reconciliation API if
stronger guarantees are needed.

There is also a narrower **P3 acknowledgement issue** at lines 299–302: both
response-body read errors are ignored. A probe that flushed HTTP 200 and stalled
its body returned DNS success after the body timeout. Choose explicitly between
accepting success at headers and requiring complete response reception; do not
wait for completion and then silently discard the failure. The protocol currently
defines success by status, so this observation alone does not prove a lost write.

### F06 — Webhook timestamps limit replay age; they do not prevent replay

**P2; reproduced using the real example authentication and HTTP handlers.**

[The example verifier](../../examples/webhook/webhook.py), lines 184–190,
checks timestamp age and HMAC but stores no request identity. A signed add,
followed by a legitimate delete, followed by the exact original add again,
returned HTTP 204 each time and restored the deleted record in the probe's
in-memory provider. Individual operation idempotence does not prevent replay
across intervening operations.

[The webhook guide](../webhook.md), lines 120–133, says the timestamp check stops
replays and endorses signatures for plain HTTP or disabled TLS verification.
The signature authenticates the request body, not the HTTP response. An active
intermediary can also fabricate success without applying the request. This is
a protocol and documentation issue, not a break in HMAC.

Use verified HTTPS across networks, describe the bounded replay window honestly,
and add authenticated request identifiers with bounded replay/idempotency storage
if replay suppression is promised. Reconcile the guide with the stricter advice
in [security.md](../security.md). The distinction between timestamps and nonce
tracking is explained in [RFC 9421 §7.2.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2);
adopting that RFC wholesale is not required.

As a separate defense-in-depth improvement, constrain explicitly enabled
redirects to approved origins and prevent HTTPS-to-HTTP downgrade. The shared
[HTTP helper](../../internal/backend/httpclient/httpclient.go), lines 55–64,
checks status and redirect count but not destination trust. Redirects are
disabled by default; this is an opt-in hardening recommendation, not evidence
of credential exposure under the default configuration.

### F07 — The webhook example can be blocked before authentication

**P2, limited to the example server; reproduced over loopback.**

[The Python handler](../../examples/webhook/webhook.py), lines 151–157, reads
the declared body before authenticating it. Lines 220–225 use single-threaded
`HTTPServer` without a socket read deadline. A client that declared ten bytes
and sent only one blocked the next request; closing that connection immediately
allowed the queued request to receive HTTP 401.

Validate nonnegative content lengths as well as the upper limit, impose header
and body deadlines, and put explicit request limits around any deployment of
the example. If connection handling becomes concurrent, preserve zone ordering
inside the endpoint. Clearly distinguish illustrative code from an exposed
production service. [Python's HTTP server documentation](https://docs.python.org/3/library/http.server.html)
also cautions against production use and describes the blocking behavior of
`HTTPServer`.

### F08 — Resolving a configured secret can produce an empty credential

**P2; reproduced through check-config, with the send behavior confirmed in source.**

[Secret resolution](../../internal/config/validate.go), lines 239–252, returns
success after trimming file or environment content, without checking the result
for emptiness. TSIG keys receive a later empty-key check, but the generic secret
consumers do not all receive that protection.

A webhook with `signature.secretFile` pointing to a whitespace-only file was
accepted as valid. It emitted a warning that no authentication was present.
[Webhook construction](../../internal/backend/webhook/webhook.go), lines
176–178, then leaves signing disabled; an empty bearer token similarly selects
no bearer header. Configuring authentication should not be transformed into
optional authentication because a mounted file is empty. Provider constructors
may reject empty credentials later, which does not fix the validator's contract.

Validate nonempty resolved values after normalization, name the exact setting
in the error, and fail startup when an explicitly configured authentication
method lacks its credential. Keep genuinely optional authentication a separate
configuration decision. Add empty-file and whitespace-only environment fixtures.

### F09 — Helm's secret guard misses custom authentication headers

**P2; reproduced with Helm template.**

[The chart's guard](../../chart/templates/_helpers.tpl), lines 124–152, rejects
known inline secret fields but does not examine `webhook.headers[].value`.
A configuration with `name: Authorization` and an inline bearer value rendered
that credential verbatim inside the ConfigMap, although the chart claims to
refuse inline secrets.

Require `valueFile` or `valueEnv` for sensitive headers, at least Authorization
and commonly used credential headers, or make all inline custom header values
an explicit exception to a narrower documented guarantee. A general header can
contain a secret under an arbitrary name, so a blacklist cannot prove that the
ConfigMap contains none. Add invalid chart fixtures for the chosen contract.
The reproduction used only a visibly fake marker, not a real credential.

### F10 — SOA responses are not finalized to the UDP transport budget

**P2; reproduced using the real UDP listener.**

[The handler](../../internal/dnsserver/handler.go), lines 52–54 and 137–153,
writes replies without truncating them to the client's payload budget. Adding
an OPT record with a 1232-byte capability is not response truncation, and the
pinned DNS library does not do this automatically in WriteMsg.

A legal 213-byte unsigned SOA query with no EDNS received a 651-byte UDP reply
with `TC=false`. A client limited to the traditional 512-byte buffer cannot
decode it and has no truncation signal to retry over TCP. Ordinary short SOA
records are unaffected.

Centralize response finalization: determine the transport and EDNS budget,
reserve TSIG overhead, compress when appropriate, and truncate before signing.
Keep TCP replies complete. Test long legal names, a small advertised EDNS
budget, and signed responses. See [RFC 1035 §4.2.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.1)
and [RFC 6891 §6.2.3](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.2.3).

### F11 — A slow failed SOA refresh arrives with an expired cache entry

**P2; reproduced with a context-aware timed backend.**

[The SOA cache](../../internal/dnsserver/server.go), lines 340–350, samples
`now` before the backend read and sets its five-second failure expiry relative
to that time. A read failing after 5.10 seconds left the negative entry already
expired. The immediately following query performed a second backend lookup.

This weakens protection against unsigned query traffic during slow outages.
Refreshes remain serialized, so the demonstrated effect is repeated reads, not
unbounded parallel backend calls. Calculate expiry from refresh completion.

The cache also uses an ordinary mutex rather than the context-aware mechanism
used for updates. A probe confirmed that a waiting caller cannot abandon that
mutex on its own cancellation. Treat cancellable cache waiting as an additional
robustness improvement, not proof that normal queries always exceed their
configured timeout.

### F12 — Truncated TSIG signatures fail with the wrong protocol meaning

**P2 compatibility; reproduced, fail-closed.**

[Keyring Verify](../../internal/auth/keyring.go), lines 107–117, compares the
received MAC to the complete HMAC. A correctly signed SHA-256 request carrying
the valid first 16 bytes of its MAC received NOTAUTH/BADSIG and did not reach
the backend.

[RFC 8945](https://www.rfc-editor.org/rfc/rfc8945.html#section-5.2.2.1)
distinguishes valid truncated MAC verification, malformed lengths, and a
BADTRUNC policy rejection. A full-length-only policy can be deliberate, but
valid truncation is not a bad signature. Implement the length rules and explicit
truncation policy, using constant-time prefix comparison where allowed, and test
the corresponding error responses. No authentication bypass was demonstrated.

### F13 — The parser accepts an ordinary A addition with no address

**P2; invalid persistence reproduced on the memory backend only.**

[Update prescan](../../internal/update/request.go), lines 157–178, checks class,
type, and TTL rules but does not establish that ordinary additions contain
valid type-specific RDATA. The DNS library intentionally represents zero-length
RDATA as empty typed records to support UPDATE deletion syntax.

A signed IN A addition with `RDLENGTH=0` received NOERROR and stored
`empty.example.test. 60 IN A` in memory. An A record requires an address under
[RFC 1035 §3.4.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.4.1).
Real providers may reject the generated request and return SERVFAIL instead;
production-zone corruption across providers was not demonstrated.

Validate typed data at the shared parser boundary for additions and
value-dependent prerequisites. Preserve legal empty data for types that allow
it; a blanket nonzero-RDLENGTH requirement would be incorrect. Add raw-wire
fixtures, since ordinary presentation-format scenario builders tend to produce
well-formed records automatically.

### F14 — The chart's Recreate strategy is not a fencing mechanism

**P2; source-confirmed deployment assumption.**

[The Deployment](../../chart/templates/deployment.yaml), lines 10–15, says
one replica and Recreate mean never two instances at once. The process-local
lock relies on that single-writer assumption. Kubernetes only provides the
stated termination-before-replacement behavior for Recreate upgrades: manually
deleting a Pod can create a replacement while the old Pod is still terminating.
This exception is explicit in the [Kubernetes Deployment documentation](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#recreate-deployment).

The old process deliberately finishes in-flight requests. The replacement can
therefore start provider writes before those requests have finished. The risk
is greater when recovery outlives the ordinary shutdown budget (F04). No cluster
race was reproduced during this audit.

Correct the guarantee and document operational constraints immediately. Evaluate
a single-replica StatefulSet for ordinary replacement semantics, and use an
appropriate lease/fencing or provider concurrency mechanism if strict exclusive
mutation is required. Neither switching workload kind nor adding a lease without
handling loss of ownership establishes universal protection against a stale
writer. Do not simply enable multiple replicas.

### F15 — The tested Go runtime differs from the released one

**P2; source-confirmed and observed in the Dagger run.**

[go.mod](../../go.mod), line 3, declares Go 1.26.0.
[Dagger's base image](../../dagger/base.go), line 10, is Go 1.27.2 and sets
`GOTOOLCHAIN=auto` at line 44. The [release workflow](../../.github/workflows/release.yaml),
lines 69–74, selects Go from go.mod. CI therefore tests with a different
compiler and standard library from the release path.

`auto` does not downgrade a newer bundled toolchain to the go.mod minimum,
as the [Go toolchain documentation](https://go.dev/doc/toolchain) explains.
This also contradicts the repository's stated single source of truth for Go.
It can hide runtime differences and skew vulnerability results for the released
standard library. This audit did not establish a specific current vulnerability
or compilation failure caused by the mismatch.

Choose one authoritative release toolchain and run the main gates with it.
Keep a separate newer-Go compatibility job if desired. Pin the scanner version
independently from its vulnerability database: `govulncheckPath = "latest"`
currently also makes the scanner executable change outside a reviewed update.

### F16 — Strict configuration parsing has two acceptance gaps

**P3; reproduced.**

First, [Parse](../../internal/config/config.go), lines 237–252, decodes only
one YAML document. Appending `---` and an unknown setting after a valid
configuration still produced a successful check-config result. Unknown-field
validation applies only to the consumed document. Attempt a second decode and
require EOF; reject a second document or invalid trailing content explicitly.

Second, [name validation](../../internal/config/validate.go), lines 776–798,
uses CanonicalName and IsDomainName without normalizing wire-equivalent spellings.
For example, accepted `\101xample.test.` remains that spelling in configuration,
but packs and unpacks as `example.test.`. Likewise `a\046b.example.test.` becomes
`a\.b.example.test.`. Zone and key maps can therefore hold a spelling that never
matches its received equivalent. This is a fail-closed availability problem;
no policy bypass was demonstrated.

Use one label-aware normalization routine, or explicitly reject unsupported
spellings. Apply the same representation to zone names, keys, policy patterns,
and zone containment checks. Add tests where two spellings produce the same
wire name. These are separate parser fixes, not a reason to replace YAML.

### F17 — The PowerDNS 4.9 compatibility claim includes known data loss

**P2; known limitation, not a new discovery.**

[PowerDNS documentation](../powerdns.md), lines 46–49, and
[the disabled-record test](../../test/e2e/disabled_test.go), lines 48–61,
acknowledge that filtered lookups on the older supported server omit disabled
records. [The backend](../../internal/backend/powerdns/powerdns.go), lines
130–161, cannot preserve records it never receives when replacing an RRset.

The additional PowerDNS 4.9.17 E2E run reproduced the expected failure: the
disabled `192.0.2.9` record was missing after the update, and the scenario was
reported as skipped under its known-defect marker.

The existing known-defect mechanism usefully prevents this from disappearing
silently from the test suite. Nevertheless, a green test run with that expected
skip is not evidence of lossless PowerDNS 4.9 support. Use a version-aware lookup
that includes preservation metadata, reject affected operations/configurations,
or narrow the support statement. Keep this limitation visible in release
decisions rather than treating documentation as a fix.

### F18 — Live ACME failures can contaminate later test runs

**P3; source-confirmed, no live provider operations performed.**

[The live ACME flow](../../test/live/live_test.go), lines 141–157, registers
server shutdown in Cleanup but deletes TXT values only in the normal assertion
path. A Fatal after the first successful add leaves a random token under the
fixed test owner. The next run adds another token and expects exactly its own,
so stale state can trigger repeated failures.

Register bounded provider cleanup before the first write, use an independent
cleanup context, and report cleanup failures. Reset the explicitly owned test
owner or allocate a unique run-specific owner. The conformance suite's cleanup
does not cover this separate ACME owner.

### F19 — Hosted retries shorten Retry-After and ignore its date form

**P2; source-confirmed.**

[The shared HTTP client](../../internal/backend/hosted/api.go), lines 118–124,
caps every retry delay at five seconds, including a delay explicitly requested
by the server. A `Retry-After: 30` response is therefore retried after five
seconds when the parent deadline permits that wait. Lines 215–218 parse only
the integer form; the standard HTTP-date form falls back to local backoff.

This contradicts the client's stated behavior and spends requests during a
provider's known cooldown, potentially worsening throttling across zones. The
existing deadline test does not exercise a deadline long enough to expose the
five-second cap. No live provider rate limit was deliberately triggered.

Cap locally generated exponential backoff separately. Honor a valid server
delay, or return the original failure if the remaining operation budget cannot
accommodate it. Parse both forms defined by
[RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3),
with overflow and past-date handling, and test these rules with an injected
clock/wait function.

## Architectural recommendations beyond the bugs

### A01 — Express the guarantees of each mutation path honestly

The [Backend interface](../../internal/backend/backend.go) describes Apply as
all-or-nothing. The [architecture guide](../architecture.md) says a failed
backend call applies nothing. OVH compensation, transport ambiguity, and
partially applying webhook scripts cannot universally meet that contract.
Atomicity and outcome certainty are separate: an atomic transaction may commit
fully while its acknowledgement is lost. That does not violate atomicity, but
it does invalidate the stronger promise that an error means nothing changed.
Likewise, lazy reads in [zone.View](../../internal/zone/view.go) are a stable
working set for this request, not a provider-wide snapshot against other writers.
The existing concurrency warnings are good but should be reflected in the
interfaces and error model as well.

Define at least the difference between rejected-before-write, committed,
not-committed, and indeterminate/partially-recovered outcomes. Make prerequisite
support, atomic mutation, and recovery responsibility explicit capabilities.
The distinction between a backend and a relay is useful; strengthen it rather
than hiding every difference behind a generic plugin interface.

Also distinguish control-plane commit from authoritative DNS publication.
Cloudflare documents that its batch uses a database transaction while record
propagation is not atomic; the [provider comparison](../providers.md) should
qualify what its atomicity column promises. See the
[Cloudflare batch documentation](https://developers.cloudflare.com/dns/manage-dns-records/how-to/batch-record-changes/).

### A02 — Remove implicit state coupling between Lookup and Apply

[PowerDNS Lookup](../../internal/backend/powerdns/powerdns.go), lines 58–64 and
155–190, populates disabled-record preservation state consumed later by Apply.
That makes correctness depend on call ordering which the interface does not
express. The current in-process update discipline makes this workable, but
wrapping, independently reusing, or parallelizing the backend becomes harder.

Prefer explicit snapshot/preservation metadata or a fresh preservation read
owned by the mutation operation. For OVH, pending publication/recovery also
deserves an explicit lifecycle instead of a private boolean checked only when
Apply is called. The server skips Apply for an empty diff, so an idempotent
update is not a reliable trigger for hidden pending reconciliation.
Moving a preservation read into Apply must retain the locking discipline and
external-writer limitations; the fresh read alone is not a transaction.

### A03 — Make record representation and invariants single sources of truth

RRset owner, type, and TTL exist both on `backend.RRset` and on its individual
`dns.RR` values. Multiple layers repair those fields. Wire canonicalization is
also duplicated between [backend](../../internal/backend/backend.go) and
[zone](../../internal/zone/view.go).

Introduce focused constructors/validation and shared canonicalization helpers.
Document whether a string is a raw API value, DNS presentation data, or a
canonical wire identity. Keep provider-specific constraints in provider adapters.
An entirely new DNS object model would be disproportionate now; precise
boundaries and invariant tests offer a smaller, useful improvement.

### A04 — Consolidate provider composition without building a plugin framework

Adding a provider currently touches raw and validated configuration structs,
validation dispatch, application construction, chart secret guards, documentation,
and test expectations. [Configuration validation](../../internal/config/validate.go)
even imports OVH for endpoint knowledge. This creates repeated lists of provider
types and security-sensitive fields; F09 illustrates how a parallel list can lag.

Keep explicit constructors, but centralize provider metadata and separate
credential resolution from provider option validation. Give engine backends and
relays equally injectable factories; the current BackendFactory only covers
one path. Prefer a few typed helpers and exhaustive tests to reflection, global
registration, or a general-purpose dependency injection system.

### A05 — Bound total resource use and make overload visible

The 256-record request bound and context-aware zone update lock are good
defenses. They do not bound pre-existing RRset size, waiting handlers, open
connections, or aggregate provider-call rate. Repeated small authorized updates can grow
an RRset; the view then copies and sorts it repeatedly and compares sets through
quadratic membership checks. No throughput or capacity claim was validated here.

Add benchmarks for realistic ACME traffic, large TXT RRsets, many zones, and
slow providers before choosing optimizations. Add an admission/concurrency budget
and bounded queues if exposure or load requires them. Canonical record identity
indexes may improve the larger-RRset path once measurements justify them.

Metrics have bounded configured labels, which should be preserved. Extend them
with queue wait, overload rejection, provider rate limiting, uncertain commits,
and reconciliation failures. `/readyz` currently describes listening state,
not provider usability; that is a reasonable deliberate choice if accompanied
by per-backend health signals rather than restarting healthy processes during a
provider outage. Rate limiting and replay limits are already disclosed in the
security guide and should remain explicit product constraints.

### A06 — Diversify test oracles and exercise failures after commit

Scenario reuse, conformance suites, and provider simulators give excellent
coverage breadth. They also share types, conversions, and expectations with the
implementation. A simulator can faithfully reproduce the same assumption as
its client. The conversion defects and uncertain-commit failure show why more
happy paths or statement coverage alone will not close the important gaps.

Add independent wire fixtures and provider response fixtures, codec properties,
and a fault matrix with failures before commit, after commit, during compensation,
after response headers, and after client cancellation. Test retries interleaved
with later updates, not just immediate repetitions. Periodic live checks can
validate a small representative set in dedicated zones, with explicit cleanup;
ordinary unit runs should remain credential-free.

[The handler fuzz target](../../internal/dnsserver/fuzz_test.go) reuses a mutable
backend/server across iterations and includes signed seeds with real timestamps.
Those seeds age out, and arbitrary mutations usually fail authentication before
reaching stateful logic. Reset state per case, separate authentication fuzzing
from freshly signed semantic fuzzing, and inject time where useful. The engine
fuzzer already resets its state and is a useful precedent.

### A07 — Make CI evidence durable and pipeline selection complete

The workflow hardening is substantial: pinned actions and images, constrained
permissions, release signing and provenance, and isolated Dagger checks. Preserve
those choices. Improve the evidence and coverage around them:

- Export the JUnit and coverage files created inside Dagger, plus mutation and
  fuzz artifacts, so historical quality trends and failures are inspectable.
- Include `dagger.json`, shared action definitions, and relevant tool scripts in
  test path selection. Changes to them can alter execution without matching the
  current Go filter in the test workflow.
- In [the mutation task](../../dagger/test.go), the `gremlins | grep` pipeline
  runs under `sh -euc` without pipefail. A gremlins failure can be hidden when
  grep succeeds. Preserve the producer's exit status explicitly.
- Keep current-version tests and release-runtime vulnerability analysis aligned
  with F15. A scanner result for another standard library is incomplete evidence
  for the published binary.
- Refresh stale overview text: CLAUDE.md still lists documentation, metrics and
  end-to-end clients as unfinished, and CLI long help still says PowerDNS only.
  These are small maintenance issues, but they mislead future contributors.

## Strengths and deliberate limitations

| Area | Assessment |
| --- | --- |
| Authorization | Whole-request policy checks and prerequisite-name restrictions occur before backend access; no bypass was demonstrated. |
| TSIG | Algorithm binding, copied secrets, constant-time comparison, signed BADTIME handling, and legacy opt-in are well structured; truncation remains a compatibility gap. |
| Update engine | Staged mutation, CNAME transitions, apex protection, serial arithmetic, and RRset ordering are explicit and well tested. |
| Memory backend | Locked copy-on-write behavior and copied read results support safe tests; malformed typed input still needs upstream validation. |
| RFC 2136 relay | Re-signing, upstream signature verification, unsigned-response rejection, bounded exchanges, and RDATA-less record handling are covered. No additional confirmed defect was found in this path. |
| PowerDNS | Batched mutations, bounded HTTP reads, redirect refusal, and preservation of exposed disabled records are useful safeguards; the older-server exception remains. |
| Hosted providers | Shared limits and conservative rejection of unsupported representations are the right direction; accepted values need stronger round-trip evidence. |
| Configuration | Unknown-field checking, readable error paths, and validation fixtures are good; resolved-secret and stream-completeness checks need tightening. |
| Operations | Structured logs, bounded metric label values, explicit timeouts, private admin guidance, and graceful shutdown are useful foundations. |
| Helm and containers | Non-root execution, read-only root, dropped capabilities, no service-account token, separate admin Service, and generated schema/docs are strong defaults. |
| Quality system | Race tests, differential BIND checks, real clients, ACME, chart tests, fuzzing, mutation, and security tasks provide complementary coverage. |

Lack of high availability, live configuration reload, universal record support,
and unlimited provider compatibility are not automatically defects. The project
can deliberately remain a single-writer gateway for a constrained use case.
The requirement is to enforce and communicate that scope, especially where a
successful DNS answer currently suggests a stronger guarantee.

## Verification performed

The official workflow was discovered through `task --list` and executed through
Task/Dagger. Initial Docker access required leaving the filesystem sandbox;
the authorized rerun succeeded. Temporary probes were kept in `/tmp` or removed
after execution. One full-check attempt captured a temporary unformatted probe
and was discarded as audit interference, not recorded as a project defect.

| Check | Result |
| --- | --- |
| `task check:quick` | Passed: formatting, Go lint with 0 issues, and 1,156 tests including 38 documented skips; race detector and shuffled order enabled. |
| Core coverage floors | Passed: update 92.2%, zone 94.1%, auth 97.9%, against 90% floors. |
| `task check` on the clean source | Passed: drift checks, all configured linters, unit and Helm tests, PowerDNS 5.0 E2E, nsupdate, lego/certbot ACME, webhook example, BIND differential, Gitleaks, govulncheck, and Trivy dependency/chart checks. |
| Integration test counts | PowerDNS 5.0 E2E: 154 tests, 2 skips. BIND differential: 206 tests, 12 intended skips. |
| `task test:e2e PDNS_VERSION=4.9` | Passed: 154 tests, 3 skips, including the reproduced disabled-record loss on PowerDNS 4.9.17 (F17). |
| Report validation | Markdown lint passed; local source links checked for existence. |
| Security scan interpretation | No leaks or vulnerabilities reported by the configured checks; this is limited to their scope, thresholds, suppressions, database state, and toolchain (see F15). |
| Native Go build | Passed with local Go 1.26.9; the Dagger gates used the pinned Go 1.27.2 image. |
| Targeted DNS probes | Confirmed oversized UDP response, truncated-MAC classification, empty A acceptance, cache-wait cancellation behavior, and expired-on-arrival failure caching. |
| Targeted hosted-provider probes | Confirmed OVH commit-then-error compensation defect, Cloudflare NAPTR/HTTPS codec issues, and Scaleway trailing-empty TXT loss. |
| Targeted webhook probes | Confirmed replay after delete, unauthenticated incomplete-body blocking, overlapping remote work after timeout, and ignored response-body timeout. |
| Configuration and chart probes | Confirmed empty resolved signature secret, ignored second YAML document, wire-name spelling differences, and inline Authorization in ConfigMap. |
| Live provider tests | Not run; no real provider credentials or zones were used. |
| Nightly acceptance, long fuzzing, mutation | Not separately run during this audit. |

The targeted tests passed by asserting the observed defects, not by establishing
correctness. Their minimal reproduction recipes are described with each finding
so they can become regression tests alongside the eventual fixes. Temporary
probe paths and logs are not durable repository test assets.

## Recommended implementation order

1. **Protect data integrity:** fix uncertain OVH compensation; define recovery
   outcomes and deadlines; close the proven conversion losses; resolve or
   explicitly restrict the PowerDNS 4.9 loss case. Add post-commit fault tests
   with each fix.
2. **Correct security and deployment promises:** fail on empty configured
   credentials; close the chart secret gap; document and enforce webhook
   transport, replay and ordering requirements; correct the single-writer
   deployment assumption.
3. **Harden DNS boundaries:** finalize UDP replies correctly, fix negative-cache
   expiry, validate type-specific wire data, handle TSIG truncation explicitly,
   and normalize accepted names consistently.
4. **Strengthen the architecture incrementally:** make capabilities and uncertain
   outcomes explicit, remove hidden preservation state, share normalization,
   align toolchains, improve fuzz oracles and live cleanup, then measure resource
   behavior before optimizing it.

Acceptance should be observable: failed writes must not silently leave a
different state, successful conversions must preserve DNS wire semantics,
configured authentication must remain active, and operational guarantees must
hold under cancellation and replacement as well as on the happy path.
