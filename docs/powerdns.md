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
  then sends its RRset changes in a single PATCH request, which PowerDNS
  applies in one transaction: an update applies whole, or not at all.
  Deletions come before replacements, so that a CNAME may replace other data
  at a name, or the reverse.
- **Contents in presentation format**, the format of the API, so that every
  record type that both tsigoat and PowerDNS know works. PowerDNS refuses a
  content that it would write differently: tsigoat writes SVCB and HTTPS
  records the PowerDNS way, and for any other type it sends the request again
  with the form that PowerDNS reports, once it checked that both encode the
  same data.
- **Timeouts**: every call has the timeout of the backend, five seconds by
  default. An update that fails or times out gets SERVFAIL. A request that
  times out may still commit afterwards: a remote API cannot tell.
- **Lookups by name**: tsigoat reads the RRsets of the names an update
  touches, with the `rrset_name` filter of the API. PowerDNS 4.9 leaves the
  disabled records out of such lookups: tsigoat reads the whole zone there
  instead, one request per name, which costs more on large zones.

## PowerDNS-specific records

- **ALIAS and LUA** records, which only PowerDNS knows, can be tested by
  prerequisites and deleted, but tsigoat never writes them.
- **Disabled records** are invisible to clients, since PowerDNS does not serve
  them. An update that rewrites their RRset keeps them.

## Concurrency

tsigoat serializes the updates of a zone within its process. Other writers of
the same zones, through the API or another tsigoat, race with it: an update
reads, then writes whole RRsets, and could undo a change made in between. Run
a single instance of tsigoat, and keep other writers away from the records
that it manages.
