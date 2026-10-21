# PowerDNS

tsigoat applies the updates through the HTTP API of the PowerDNS Authoritative
Server. It is tested with PowerDNS 4.9 and 5.0.

## Requirements

- **The HTTP API**: `api=yes`, an `api-key`, and the webserver reachable from
  tsigoat (`webserver-address`, `webserver-allow-from`). tsigoat sends the key
  in the `X-API-Key` header; serve the API over HTTPS when it crosses a
  network, with `caFile` for a private certificate authority.
- **The zones**, which tsigoat never creates. `tsigoat check-config --backends`
  reads every zone through its backend, and `serve` logs a warning at startup
  for each zone it cannot read.
- **A serial that moves**: tsigoat leaves the SOA to PowerDNS. The zones
  created through the API bump their serial on every change, since their
  `SOA-EDIT-API` metadata is `DEFAULT`; set it on the other zones.

The URL must be the final address of the API: tsigoat refuses redirects,
which would turn its PATCH requests into GET requests and hand the API key to
another server.

## How tsigoat writes

- **One request per update.** tsigoat computes the whole update in memory,
  then sends its changes in a single PATCH request, which PowerDNS applies in
  one transaction: an update applies whole, or not at all. The records that
  it adds and removes go as EXTEND and PRUNE, which PowerDNS applies to the
  records of the RRset as they stand, so that the records that another
  instance of tsigoat writes meanwhile stay; an RRset whose TTL changes is
  replaced whole. PowerDNS takes EXTEND and PRUNE since 4.9.12 and 5.0.2:
  before, tsigoat replaces every RRset that changes, as it read it.
  Removals come first, so that a CNAME may replace other data at a name, or
  the reverse.
- **Contents in presentation format**, the format of the API, so that every
  record type that both tsigoat and PowerDNS know works. PowerDNS refuses a
  content that it would write differently: tsigoat writes SVCB and HTTPS
  records the PowerDNS way, and for any other type it sends the request again
  with the form that PowerDNS reports, once it checked that both encode the
  same data.
- **Timeouts**: every call has the timeout of the backend, five seconds by
  default. An update that fails gets SERVFAIL. A PATCH request that left whole
  but got no answer, or got a 502 or 504 from a gateway in front of PowerDNS,
  may have applied: tsigoat reads its RRsets again, and answers NOERROR when
  they show the update. Otherwise the update gets SERVFAIL, and its outcome is
  unknown, since the request may still apply: the update log tells so, and the
  [TsigoatUncertainUpdates](operations.md#tsigoatuncertainupdates) alert
  fires.
- **Lookups by name**: tsigoat reads the RRsets of the names an update
  touches, with the `rrset_name` filter of the API. PowerDNS 4.9 leaves the
  disabled records out of such lookups: tsigoat reads the whole zone there
  instead, one request per name, which costs more on large zones.

## PowerDNS-specific records

- **ALIAS and LUA** records, which only PowerDNS knows, can be tested by
  prerequisites and deleted, but tsigoat never writes them.
- **Disabled records** are invisible to clients, since PowerDNS does not serve
  them. An update keeps them, even when it removes every record that clients
  see: PowerDNS drops them from an RRset that EXTEND or PRUNE change, and
  tsigoat puts them back, in the same PATCH request.

## Concurrency

tsigoat serializes the updates of a zone within its process. Other instances
of tsigoat, and other writers through the API, may change the same RRsets
meanwhile: the records that an update adds and removes apply to the records
as they stand, so that theirs stay. What an update checks before it writes,
and an RRset that it replaces whole, still race with them: see
[Several instances](operations.md#several-instances).
