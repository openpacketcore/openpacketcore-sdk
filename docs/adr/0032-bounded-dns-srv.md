# ADR 0032: Bounded RFC 2782 service discovery

## Status

Accepted.

## Context

The DNS contracts and source-bound client in ADRs 0030 and 0031 need service
discovery that preserves priority, weighted target selection, ports and timing.
The existing deterministic endpoint selector must consume that result without
turning raw SRV weights into a largest-weight preference. Fanout must stay
bounded within the existing cache, source-plane and cancellation contracts.

## Decision

Extend `DnsClient` Service mode to query an explicit `_service._proto.domain.`.
Keep the operator service label separate from the DNS service label, and
require the protocol label to match the requested transport. Validate host
labels using RFC 1123 section 2.1, including leading digits. Names remain
absolute and ASCII; no search list, default-port fallback or IDNA is added.

Order SRV records by ascending priority. Within each priority, use RFC 2782's
inclusive weighted draw with zero weights placed first, removing the selected
record and repeating. Shuffle the initial group so all-zero weights have no
fixed name preference. Canonicalize and deduplicate before selection so wire
order and duplicate records do not change the weighted order for a given seed.
Use an OS seed by default; expose `resolve_with_seed` for repeatable selection.
The internal SplitMix64 generator is only for selection, with bounded rejection
sampling to avoid modulo bias. Query IDs retain independent OS entropy; source
ports follow the kernel's allocation policy. Preserve SRV priority and encode the selected order in descending
legacy candidate weights. Those weights are preference ranks, not raw SRV data.
Selection is drawn once per refresh; connections using one cached answer
reuse that order until the next refresh.

A sole root target returns `ServiceUnavailable { expires_at }` with the
minimum SRV/CNAME deadline, without an invented SOA. The cache treats this as
a withdrawal bounded by its negative TTL cap: cold entries are `Negative`,
last-good entries remain `Stale`, and retries wait until the bounded deadline.
Consumers inspect the accompanying error when deciding whether to use stale
endpoints after withdrawal. Zero, high-bit and expired deadlines use paced
failure retries without granting negative lifetime.

Skip root records mixed with hosts, invalid host targets and reserved port 0.
Use each valid SRV port and ignore the configured default. Accept compressed
SRV targets under the shared decoder's existing pointer and length bounds,
following the receiver guidance in RFC 3597 section 4. Structurally malformed
messages remain errors; an unusable target does not hide valid sibling records.
A CNAME at
a target invalidates that whole target, including addresses learned from
another family. It is never followed, and other valid targets remain usable.
Service-owner aliases still use bounded in-answer traversal.

Use exact-target IN A/AAAA additional data and query missing families through
the same configured-server transport. Additional records never nominate DNS
servers or populate another cache key. Although RFC 2181 section 5.4.1 ranks
additional data lowest, this stub trusts the configured recursive server and
its matched response, including exact target names outside the service zone.
That same server already supplies the service's SRV targets.
Memoize each target's address work across ports. Select targets before
stably ordering their addresses by destination rank, retaining DNS wire order
for equal ranks (RFC 6724 section 6, rule 10). Deduplicate endpoints and retain
at most sixteen candidates. Stop starting work when the selected prefix can
fill that cap, and finish already-started lookups within the overall deadline.
Partial
target/family successes remain usable. An address-question denial cannot
negatively cache the service key; only an SRV-question denial carries that
authority. Target negatives with no usable addresses map to `Unavailable`.
Retain the original per-family outcomes, including additional-data resolution,
budget failures and whole-target alias rejection. A partial success inherits
the address client's freshness bound: at most `partial_failure_ttl` (zero or
one second through five minutes) after a transient/local failure, or the
denial's SOA deadline. Preserve the separate negative freshness bound so the
cache also applies its tunable negative TTL cap when publishing a partial success.
This bounds retries without rewriting record TTL provenance or granting
service-negative authority to a target's SOA.

Preserve each response's observation time. Normalize SRV and address RRsets
to their minimum effective TTL before deduplication or truncation. Each chain
includes service-owner aliases, SRV and the terminal address. The cache's
`fresh_until` applies the earliest absolute expiry and the configured TTL cap;
later target lookups never restart the SRV TTL.

The behavior follows these clauses:

| Behavior | Authority |
|---|---|
| Query format, priority, inclusive weight algorithm, root target, ports, additional addresses and forbidden target aliases | [RFC 2782, The format of the SRV RR and Usage rules](https://www.rfc-editor.org/rfc/rfc2782.html) |
| Receiver decompression of legacy SRV targets | [RFC 3597 section 4](https://www.rfc-editor.org/rfc/rfc3597.html#section-4) |
| Reserved port zero | [RFC 6335 section 6](https://www.rfc-editor.org/rfc/rfc6335.html#section-6) |
| Host labels and leading digits | [RFC 1123 section 2.1](https://www.rfc-editor.org/rfc/rfc1123.html#section-2.1) |
| Minimum RRset TTL and conservative high-bit policy | [RFC 2181 sections 5.2 and 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-5.2) |
| Address-order tie breaking | [RFC 6724 section 6, rule 10](https://www.rfc-editor.org/rfc/rfc6724.html#section-6) |
| Service-question negative authority and SOA timing | [RFC 2308 sections 2.2 and 5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5) |
| Partial failure retry bounds and short-lived server timeout history | [RFC 2308 sections 7.1–7.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-7) |

### Resource bounds

The existing parser retains at most 128 wire records across all sections.
Order the complete valid, deduplicated SRV RRset first, then apply work
limits: 32 expanded records, 16 unique targets and 32 address lookups by
default, with respective ceilings of 128, 32 and 64. Larger pools remain
usable. Response counters report distinct valid records and targets skipped
by work/candidate limits. Address-lookup allowances are reserved in selection
order, independent of completion order. Additional data needs no lookup
allowance; zero permits only additional data. Budget-blocked families retain
`LimitExceeded` outcomes and the partial-failure bound. An alias or deadline
can leave reserved allowance unused.

Poll at most four targets concurrently by default, configurable from one to
32, refilling slots as soon as they become free. Missing A and AAAA queries
within each target are sequential. Futures belong to the caller; no task is
spawned and no Send/Sync requirement is added to the clock callback.
Results and diagnostics remain in target/family selection order.

An overall `srv_refresh_timeout` includes the initial SRV lookup, retries,
fallbacks and all target work. Zero selects the automatic default:
`timeout * (servers.len() + 1)`, capped at 300 seconds and derived from the final
configuration in `DnsClient::new`. This allows one pass over configured servers
plus time for target work. Explicit nonzero budgets retain the 1 ms–300 second
range. On expiry, return completed candidates and record
`Timeout` for unfinished selected families, applying partial-failure bounds.
Keep timed-out configured servers behind other servers across SRV refreshes
and clones of the same client, retaining them as fallback destinations. Each
hint expires five minutes after that server's latest timeout, using Tokio's
monotonic clock independently of the caller's cache clock. A matched reply
clears the hint sooner. The client retains at most eight timestamps, with no
lock held across I/O. This ordering hint does not cache another query's failure
or change the server set. Address-mode calls keep configured server order.

Each lookup also retains its configured retry and per-server attempt bound.
Total server attempts remain at most
`(1 + max_srv_address_lookups) * attempts * servers.len()`, while the total
I/O duration is bounded by `srv_refresh_timeout`, including the worst case.
The driver should allow a cache lease longer than that budget, with margin
for bounded decoding, runtime scheduling and publication, or cancel at its
own shorter lease deadline.

One admission permit covers the entire refresh, including target work.
Open DNS sockets can reach `max_in_flight * max_srv_concurrent_targets`,
or 256 with the defaults and 32,768 at the configured maxima.
Memoization retains at most sixteen addresses per target; temporary address
decoding remains bounded by 128 records per response and two families.
The final answer retains sixteen candidates, each with at most sixteen
provenance records. Service-owner chains therefore allow at most fourteen
CNAMEs before SRV plus address. Response-source metadata is bounded by one
SRV source plus the configured address lookup budget and includes the question
owner for programmatic correlation. Terminal outcomes retain the SRV question
plus each requested family once per visited target, at most `1 + 2 * max_srv_targets`.
Repeated target names reuse those outcomes across ports. Diagnostics remain redacted.

## Consequences

The change adds no dependency, background task, second cache or unsafe code.
The legacy getaddrinfo bridge remains address-only. Dropping the future closes
all active sockets and releases admission. There is no durable state, node
cleanup, operator action or application-session ownership. S-NAPTR, DNSSEC,
authenticated DNS transports and connection racing remain outside this slice.

Independent byte fixtures exercise SRV framing, target/owner compression with
bounded pointers, truncation and hostile mutation. Loopback servers cover
seeded distribution and mutation-sensitive zero-weight/wire-order fixtures,
priority, root and alias targets, negative authority, TTL chains, work limits,
dead-server ordering, concurrent progress, overall deadlines, cancellation,
source binding and transport fallback. No test uses system or public DNS.

### S-NAPTR follow-up

Keep direct `_service._proto.domain.` validation at the Service-mode entry.
An S-NAPTR "S" flag supplies the SRV query name in REPLACEMENT
([RFC 3958 section 2.2.3](https://www.rfc-editor.org/rfc/rfc3958.html#section-2.2.3)),
which need not have that direct-query shape. The shared SRV parser and ordering
already accept a generic owner. S4 must preserve NAPTR chain timing and bound
its own traversal. The RFC 2782 Usage-rules address fallback remains an explicit
Address-mode call by consumers who require it.
