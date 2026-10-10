# RFC 031: Bounded S-NAPTR peer discovery

Status: **Implemented; code review and qualification pending.**

## Purpose

Extend `opc-peer-discovery` with service-filtered NAPTR discovery that produces
bounded candidate sets for APN and Diameter realm names. Build on the DNS
identity/cache, source-bound client and SRV contracts in
[ADR 0030](../adr/0030-dns-discovery-contracts.md),
[ADR 0031](../adr/0031-source-bound-dns-client.md) and
[ADR 0032](../adr/0032-bounded-dns-srv.md). Resolution supplies candidates and
their derivation; the consumer owns connection attempts, authentication against
the original domain, topology/collocation policy and application failover.

## API and selection data

The interfaces are:

```text
SnaptrOrdering = Rfc3958 | ThreeGpp
SnaptrFilter::new(service_tag, protocol_tag, ordering) -> Result<SnaptrFilter, DnsError>
DnsQuery::with_snaptr_filter(filter) -> Result<DnsQuery, DnsError>
DnsCandidate::snaptr() -> Option<&SnaptrProvenance>
DnsAnswer::snaptr_hosts() -> Option<&[SnaptrHost]>
DnsClientResponse::snaptr_root() -> Option<&SnaptrRootObservation>
```

One query requests one application service/protocol pair. Its existing
`ServiceDiscoveryInput` supplies the operator label, original name, explicit
endpoint transport and service-defined default port. Validate a nonzero
default port before any I/O, even if the eventual records all use `s`.
Keep the operator label separate from the DNS service tag: `PeerLabel` does
not admit the `+` in Diameter tags.
The filter is required in `Snaptr` mode and invalid in other modes. Its
canonical tags and ordering profile participate in `DnsQuery` equality and
`DnsCacheKey`; resolver/source/family identity remains part of that key.
Multiple protocols use independent queries/keys, so a descendant cannot switch
the protocol selected at the root. No protocol preference is inferred from
DNS names or tag substrings.

Keep using `DnsClient::resolve` / `resolve_with_seed`, `DnsClientResponse`,
`DnsAnswer` and `DnsCache`. Coalesce duplicate `(transport, SocketAddr)` values
at their best rank in `DnsAnswer::candidates()`, retaining at most 16 distinct
endpoints. The host view groups these by `(advertised terminal host name,
transport, port)` and carries output rank, address indices and provenance
references. Preserve distinct host names even when they share an endpoint;
the endpoint is stored once. A repeated direct/delegated path to the same
host enriches its provenance rather than consuming another endpoint slot.

Provenance includes the original name and matched pair, timed records, each
NAPTR hop's order/preference/flag/services/replacement, and any SRV owner's
priority/raw weight/port/target. Keep the best path and up to three alternate
paths per endpoint, each with at most 16 records; host references identify
their actual path. A new host/path that cannot retain this evidence is omitted
and counted, without removing the retained endpoint. Bound the host view to
16 hosts with at most 16 address references each. Reserve space for each
endpoint's primary host before admitting alternate host names. Rebuild host
references after final endpoint ordering; no index may reference omitted data.
Coverage metadata identifies incomplete hosts, omitted paths/addresses,
unvisited branches, and counts of refused and failed branches. These counts
survive cache publication, including excluded higher-ranked paths. Neither this
view nor its prefix promises exhaustive topology/collocation search; the
consumer owns that selection and decides whether the reported coverage is
sufficient. No topology ranking is performed in the SDK.

Use the same legacy weight encoding as address and SRV mode:
`weight = u16::MAX - index` in the final deduplicated endpoint order, through
one shared helper. S-NAPTR uses priority zero, as address mode does; direct
SRV retains its existing SRV priority. Raw NAPTR and SRV selection fields
remain separate in provenance. New public enums/metadata are non-exhaustive;
diagnostic formatting redacts names, tags, endpoints and resolver identities.

## Service matching and public naming

Inspect only the first SERVICES token (bytes before the first colon) to
identify the application. If it does not equal the requested service tag
under ASCII case folding, filter the record without parsing its remaining
services, flags or regexp. This includes ENUM `E2U+sip`, legacy `AAA+D2S` and
malformed unrelated fields. Root classification may recognize a Diameter
family marker without validating that unrelated record for traversal.

For a matching first token, validate the SERVICES grammar in
[RFC 3958 section 6.5](https://www.rfc-editor.org/rfc/rfc3958.html#section-6.5)
and [RFC 6408 section 3](https://www.rfc-editor.org/rfc/rfc6408.html#section-3).
`MalformedService` means a matching application's field has non-ASCII bytes,
illegal token characters/initial character, an overlong token, or an empty
colon-delimited protocol token. Tags have at most 32 octets and the wire
field at most 255. A valid but unsupported protocol is a non-match, not a
malformed field. Empty services do not match. Compare whole protocol tokens
at every hop. Malformed framing is handled by the codec separately.

For Diameter, validate the requested `aaa+ap<ID>` as a decimal `u32` without
leading zeros (except `0` itself). A different or noncanonical received ID
does not match that first token, except that the relay tag `aaa+ap4294967295`
matches every requested Diameter application, using the relay record's own
order and preference ([RFC 6408 section 7.1](https://www.rfc-editor.org/rfc/rfc6408.html#section-7.1)). Compare tags such as `diameter.sctp` whole;
do not split them on dots or manufacture an SRV name from them. A matching
application-only `aaa+ap<ID>` record follows
[RFC 6408 section 5(c)](https://www.rfc-editor.org/rfc/rfc6408.html#section-5): use this
query's explicitly configured supported protocol/transport and record that
the protocol was not advertised. A protocol-specific descendant must still
match that protocol. Legacy `aaa` records do not satisfy an application-ID
filter; the root classification below exposes legacy presence to the caller.
Preserve security-bearing protocol tags for the consumer's handshake.

Defaults come from the requested service definition: GTP-C uses 2123
([TS 29.274 V8.0.0, clause 4.3.1.1](https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/08.00.00_60/ts_129274v080000p.pdf));
Diameter TCP/SCTP uses 3868, and its TLS/DTLS profiles use 5658
([RFC 6733 section 2.1](https://www.rfc-editor.org/rfc/rfc6733.html#section-2.1)).
Caller configuration supplies the protocol/transport/default-port association
before resolution. An `a` record uses that default; an `s` record uses the
explicit SRV port. A remote zone never defines or changes the default.

Examples use `x-3gpp-pgw:x-s2b-gtp` with
`ims.apn.epc.mnc001.mcc001.3gppnetwork.org.`, and
`aaa+ap16777264:diameter.sctp` with
`nai.epc.mnc001.mcc001.3gppnetwork.org.`. The caller supplies the absolute
APN-FQDN or realm; the resolver does not derive it from subscriber information.
The APN form and PGW service usage follow
[TS 29.303 V18.0.0, clause 5.1.2.1](https://www.etsi.org/deliver/etsi_ts/129300_129399/129303/18.00.00_60/ts_129303v180000p.pdf).
DCN/network-capability qualifier matching is a separate extension: reject
unsupported `+ue`/`+nc` query filters, and never strip those qualifiers to
match a base protocol.

## Root classification and caller-owned Diameter fallback

Return a typed `SnaptrRootObservation` independently of endpoint success.
Classify the entire bounded root NAPTR RRset before applying traversal limits.
The three kinds are `NoNaptr`, `PresentNoMatch { reason }` and `Match`.
`Match` means the root advertises the requested pair (including the Diameter
application-only case); a later branch failure does not turn it into absence.
For an application-ID query, use these distinct reasons/actions:

| Root observation | Meaning and caller action |
| --- | --- |
| `NoNaptr` | Initial NXDOMAIN/NODATA, retaining the original typed DNS error and SOA/alias timing. The caller may perform the RFC 6408 section 5(f) SRV fallback. |
| `PresentNoMatch(ExtendedPresentNoMatch)` | Extended Diameter records exist but no pair matches. Abandon this queried protocol per section 5(b)/(c), while independently querying other supported protocols; legacy records alongside them do not enable downgrade. |
| `PresentNoMatch(LegacyOnly)` | Legacy Diameter records only (`aaa[:protocol]`, `AAA+D2T`, `AAA+D2S`). The caller chooses explicit section 5(d)/(e) compatibility handling. |
| `PresentNoMatch(NotAdvertised)` | NAPTR exists for unrelated applications only. Diameter is not advertised; section 5(f) fallback is available. |
| `PresentNoMatch(MalformedRequestedService)` | The requested first token occurs, but malformed service syntax prevents a match. Report its branch refusal; do not authorize fallback. |
| `Match` | Resolve the advertised paths; endpoint failure or truncation never authorizes section 5(f). |

A valid match takes precedence over non-matches. Without one, requested-field
malformation takes precedence over extended presence, then legacy presence,
then unrelated-only data. Conservatively treat an `aaa+ap` family marker as
extended presence even if its ID is noncanonical; do not infer absence from
it. Non-Diameter queries use `PresentNoMatch(ServiceNotOffered)` as needed.
Root SERVFAIL, REFUSED, timeout, invalid query or unparseable response has
**no classification**, preserving its typed error. None means unobserved,
never `NoNaptr` or `NotAdvertised`.

For permitted fallback, the caller issues a separate Service-mode query using
its selected transport/security policy and the names in
[RFC 6733 section 5.2](https://www.rfc-editor.org/rfc/rfc6733.html#section-5):
`_diameter._sctp.<realm>.`, `_diameter._tcp.<realm>.`,
`_diameters._tcp.<realm>.` or `_diameters._sctp.<realm>.`.
The SDK exposes the distinction and performs no implicit fallback.

The diagnostic observation retains root/alias timing. Actionable no-match
classifications travel in `DnsError::Snaptr { reason, expires_at }`, with
`reason = NoMatchingService(kind)` and the minimum absolute root RRset/alias
deadline. `negative_deadline()` exposes that deadline to the existing cache,
just as for `ServiceUnavailable`; present no-match answers need no SOA.
`NoNaptr` remains `NxDomain`/`NoData`, using the original SOA/alias timing.
Without an SOA it grants no negative lifetime. A malformed requested field
is `Snaptr(MalformedService)` with no reusable decision lifetime.

Publish `response.result` through the existing `DnsCache::finish_refresh`.
No new cache lifecycle or `DnsCacheStatus` fields are introduced. The cache
caps no-match deadlines by its negative TTL cap, paces retry until expiry,
and reports `Negative` on a cold entry or `Stale` with `last_error` while
preserving last-good endpoints. Zero/high-bit/expired TTLs grant no freshness;
uncacheable decisions use existing retry pacing. Token fencing and clearing
on the next unclassified failure remain unchanged. This is an application
decision lifetime, not new DNS negative authority.

`Ok` and `Snaptr(NoUsablePath)` imply a root match. A later `Timeout`,
`LimitExceeded`, or semantic refusal never authorizes absence fallback;
neither does a root transport/RCODE failure. `snaptr_root()` is optional
diagnostic context only; callers need not retain it to make the safe fallback
decision. A match never delays an earlier endpoint/partial-failure refresh.

## Traversal and ordering

Decode IN NAPTR (type 35) with exact RDLENGTH consumption: two `u16` fields,
three counted byte strings, then REPLACEMENT. Retain the codec's existing
message, label-boundary and pointer-step limits. While senders must not
compress REPLACEMENT, accept bounded, valid incoming compression according to
[RFC 3403 section 4.1](https://www.rfc-editor.org/rfc/rfc3403.html#section-4.1)
and the receiver guidance in
[RFC 3597 section 4](https://www.rfc-editor.org/rfc/rfc3597.html#section-4).
Unparseable packet framing invalidates that question; it cannot yield trusted
record boundaries. Other completed branches survive. Well-framed records
with invalid semantics are refused individually. An eligible record with a
nonempty REGEXP is refused; REPLACEMENT is the only traversal operand.

| Flag (ASCII case-insensitive) | Next step |
| --- | --- |
| empty | Query NAPTR at REPLACEMENT and apply the same filter. |
| `s` | Query SRV at the exact REPLACEMENT, then resolve selected targets. This name need not have the direct Service-mode `_service._proto` shape. |
| `a` | Query A/AAAA at REPLACEMENT using the requested families and the service default validated before I/O. |
| any other value, including multiple flags | Typed unsupported-flag refusal. |

Require a usable absolute replacement, rejecting root and names outside the
client's public name contract. Reuse bounded in-answer CNAME processing for
NAPTR owners and direct address terminals, retaining aliases in provenance.
The SRV target-alias prohibition and target/port validation remain those of
ADR 0032. Initially ignore NAPTR-response additional data and issue the needed
questions; SRV-response exact-target additional addresses retain their existing
handling. No answer supplies a new resolver destination.

Use a shared exhaustive question-type mapping for A=1, AAAA=28, SRV=33 and
NAPTR=35 in both transport source metadata and traversal outcomes. The shared
`dns_wire::record_type` replaces the former catch-all-to-AAAA mappings in the
client and SRV traversal. Unsupported question types are rejected.

Use an explicit queue of ranked continuations. At each owner, keep order groups
separate and rank lower order first. `Rfc3958` ranks lower preference first
within a group. Canonicalize/deduplicate records before seeded tie ordering.
Follow the successive-path rules of
[RFC 3958 sections 2.2.1–2.2.5 and Appendix A.2](https://www.rfc-editor.org/rfc/rfc3958.html#section-2.2.1):
collect alternatives for backtracking, preserving the full ancestral order.
Within available budgets, include higher-order candidates even when a
lower-order path succeeds, placing them after every retained candidate from
the lower group. Connection attempts advance to them only after the earlier
candidates fail. Child ranks never move a candidate ahead of an earlier
ancestor's branch. The consumer may subsequently apply its explicitly chosen
topology/collocation policy to the host view.

`ThreeGpp` uses ascending order but draws within each order group with weight
`65535 - preference`, as required by TS 29.303 Annex B.2(3). This profile is an
explicit input, not inferred from a service name. Its draw and subsequent SRV
draws reuse the bounded inclusive
[RFC 2782 algorithm](https://www.rfc-editor.org/rfc/rfc2782.html), with distinct draw state
per RRset and reproducibility through `resolve_with_seed`. At an `s` terminal,
SRV priority/weight apply only within that NAPTR path; address order follows
the existing destination policy.

Obtain one refresh seed from fallible OS entropy, or use the supplied `u64`.
For each NAPTR/SRV RRset in this traversal, initialize SplitMix64 from FNV-1a-64
of this exact concatenation:

```text
"opc-snaptr-draw-v1\0" || BE64(refresh_seed) || BE16(record_type)
  || profile_byte || frame(canonical_owner) || frame(service_tag) || frame(protocol_tag)
frame(x) = BE16(byte_length(x)) || ASCII_bytes(x)
profile_byte = 0 for Rfc3958, 1 for ThreeGpp
```

Use lowercase absolute owner text (including the final dot), lowercase tags,
FNV offset `0xcbf29ce484222325` and prime `0x100000001b3`, with wrapping `u64`
multiplication after XORing each byte. Canonicalize the RRset before drawing;
neither TTLs, wire order, arrival time nor task scheduling enters the seed.
Memoized shared children reuse their one draw per refresh. Direct Service-mode
seed behavior is retained. These states serve selection only; DNS IDs retain
independent OS entropy.

Loop detection uses canonical names on the active NAPTR/alias path. A shared
child reached by two independent branches is valid, not a global-visited loop.
Per-refresh memoization shares DNS data while preserving distinct path
identities and observation times; provenance retention limits still apply.
It expires with the refresh and is not another cache.

## Work bounds and failures

The immutable `DnsClientConfig` limits are SDK policy, not limits
imposed by the standards. New count limits must be nonzero and within their
ceilings. Reject invalid configurations before network I/O.

| Bound | Default | Ceiling / accounting |
| --- | --- | --- |
| `max_snaptr_depth` | 8 | 14 NAPTR records per path, including the terminal NAPTR. |
| `max_snaptr_records` | 128 | 1024 eligible NAPTR records expanded across the refresh; repeated logical visits consume allowance too. |
| `max_snaptr_lookups` | 64 | 256 logical NAPTR/SRV/A/AAAA evaluations, including root and memoized visits. Retries remain bounded per evaluation. |
| Retained endpoints / hosts | 16 / 16 | Deduplicated endpoint pool plus host groups; at most 16 address references per host. |
| Paths / record provenance | 4 / 16 | Up to four paths per retained endpoint, including its primary; at most 64 retained chains in total. Aliases, NAPTR, SRV and address all count toward each chain's 16-record bound. |
| SRV work and address concurrency | existing configuration | Share record/target/address-query allowances across all terminals; do not reset them at each `s` or `a`. |
| `snaptr_refresh_timeout` | automatic | Zero derives `timeout * (servers.len() + 1)`, capped at 300 s; explicit 1 ms–300 s. |

The codec still bounds each response to 128 wire records. Decode, normalize,
filter and order that whole RRset before applying expansion/retention limits;
limits must not turn wire order into selection order or hide root presence.
Counters distinguish filtered records, eligible records/targets not expanded,
omitted endpoints/alternate paths and unfinished lookups. Counts describe
observed work only: an unvisited subtree has unknown size. Expose a coverage
flag rather than claiming that the counters enumerate that subtree.

Use one admission permit and one absolute refresh deadline for all questions,
server retries, EDNS retry, TCP fallback and terminal work. Factor the internal
address/SRV workers to accept that session and remaining budgets; never recurse
through the public resolver or acquire a second permit. Sibling paths progress
concurrently within `max_srv_concurrent_targets` (default 4, maximum 32),
refilling a free slot without waiting for an earlier silent branch. Count each
pending logical question against that ceiling even when it shares an in-flight
exchange; repeated paths must not consume the expansion allowance before the
first child progresses. Memoized completed data needs no exchange. Retain a
shared RRset cursor for unexpanded records, materializing one continuation at a
time instead of copying the entire fan-out for every path to a shared child.
Each target advances its address families in order, retaining whole-target SRV
alias rejection. Direct SRV retains its existing concurrent target expansion.

At admission of each non-root NAPTR, SRV, A or AAAA question, reserve
`min(timeout, remaining_refresh_time / 2)` at the end of the refresh for
backtracking. Enforce this earlier deadline only while a ready branch needs a
new network question queued behind the concurrency limit. A running sibling
already has its own slot and does not justify cancellation. Reevaluate after
every completion;
shared waiters for the same question, branches below a full endpoint prefix,
and work whose next question cannot be admitted are not alternatives. If none remain,
keep the original transport future and full remaining refresh deadline, with
its configured attempts and EDNS/TCP fallback. Root discovery always keeps its
original deadline. The reservation can cut retries or fallbacks short while an
alternative remains; it does not promise that every attempt fits. A lone path
can retry a lost packet or complete a slow healthy chain within the overall
budget. Backtracking still has time with one slot and a short explicit budget.
The work/deadline limits bound how many dead branches can be explored; coverage
never promises an exhaustive search.

Inspect queued work in ready-path rank order on a bounded snapshot of the
traversal and ready queue. The inspection calls the exact same `step`, `reserve`
and prefix-admission functions as execution; it has no separate loop, depth,
budget, alias or prefix rules. Completed memoized answers advance through those
steps without I/O. A question already in flight consumes its logical allowance
but is not new network work. Inspection stops at the first admissible exchange
waiting for a slot, or when no such exchange remains. It never changes actual
allowances, outcomes or endpoints. Compute the decision once per queue change,
not on every future poll, and drop the snapshot before polling network work.

Keep lazy logical admission instead of eagerly draining every cached/shared
continuation: duplicate paths can otherwise spend the record allowance before
the first child's descendants make progress. The snapshot uses those same hard
bounds and shares immutable parsed RRsets through `Arc`; its additional memory
is temporary and never part of a retained answer.

Server attempts are bounded by
`max_snaptr_lookups * attempts * servers.len()`. Response sources/outcomes are
bounded by the lookup budget; branch outcomes by expanded NAPTR records plus
logical lookups, with at most 16 prefix records per outcome. If more semantic
failures are already visible in one SRV response, retain the best-ranked trace
entries and count omitted details in `omitted_branch_outcomes`. Cached refusal
and failure counts still include every such branch. Cached coverage also
retains unexpanded SRV record paths and distinct skipped SRV target counts.
Dropping the future cancels its sockets and releases admission, with no spawned
background work, durable state or new dependency.

Extend `DnsError` with `Snaptr { reason: SnaptrFailure, expires_at: Option<PeerDiscoveryTime> }`. Reasons distinguish
`UnsupportedFlag`, `RegexpNotEmpty`, `MalformedService`, `InvalidReplacement`,
`Loop`, `DepthLimit`, `ProvenanceLimit`, `NoMatchingService(SnaptrNoMatch)`
and `NoUsablePath`. Only root `NoMatchingService` carries a cacheable deadline.
Each has a stable, redacted code. Record/target/lookup/candidate work exhaustion
uses existing `LimitExceeded` and the corresponding counters. Invalid default
ports are `InvalidQuery` before admission, never remote-dependent refusals.

An invalid flag, regexp, service, replacement, loop or overlong chain excludes
only that branch. Retain its typed refusal and timed prefix in the resolution
trace, alongside per-question outcomes, and continue healthy siblings. Child
DNS negatives, SRV withdrawals, SERVFAIL and timeouts follow the same branch
isolation rule. Partial-result provenance and coverage survive cache publication.

Admit work in rank order among currently ready paths; ancestors must first
respond before their descendants can compete for the shared work allowances.
An unresolved subtree has no reserved claim to the entire remaining allowance.
Once 16 distinct endpoints are
assembled, stop starting lower-ranked work; finish already admitted work within
the shared deadline. Keep the best-ranked completed endpoints, independent of
completion order. A better-ranked late completion replaces a worse retained
entry. Apply the same rule to primary and bounded alternate paths, and rebuild
host references from the final order. Already admitted questions retain their
outcomes and coverage counts even if the endpoint pool fills while they wait.
Apply a failure's freshness bound only if the pool is not full at completion
or the failing branch can rank ahead of its 16th endpoint. A strictly lower
failure cannot shorten a complete prefix's freshness.
A cap or deadline never discards an assembled usable result: publish
the retained prefix and mark omissions/unfinished branches. Primary paths and
their hosts take precedence over alternate metadata; an alternate-path cap
does not remove the accepted endpoint. Incomplete higher-ranked branches get
`LimitExceeded` or `Timeout` outcomes and the partial-failure freshness bound.
Consumers can distinguish a prefix from exhaustive results without losing
the available hosts.

Only an empty endpoint set produces a whole-resolution failure. Preserve a
root question's DNS error unchanged. Root no-match returns `Snaptr` with
`NoMatchingService` (or `MalformedService`) plus its typed root observation.
After a root match, exhaustion of the overall deadline/work allowance returns
`Timeout`/`LimitExceeded`. Otherwise, if all paths fail, return the first
semantic refusal in deterministic traversal order, or `Snaptr(NoUsablePath)`
when failures are only DNS/withdrawal outcomes. Child errors remain in the
trace; a child's SERVFAIL, NXDOMAIN or timeout is never returned as if it were
the root question's error, and a child's SOA is never promoted to the root.

## Freshness and negative authority

Normalize a relevant RRset to its shortest effective TTL before filtering,
deduplication or candidate retention, preserving each response's observation
time. Every retained primary/alternate path keeps its own complete chain;
host/answer freshness cannot outlive any retained path on which it relies.
Expiry is the minimum absolute deadline of its CNAME/NAPTR/SRV/address records,
not the minimum TTL restarted at completion. Coalescing endpoints never
restarts a deadline or removes a shorter retained-path freshness bound.
Answer freshness is the minimum of candidate expiries and failure bounds;
`DnsCache` then applies its configured caps. This extends ADRs 0030–0032
and [RFC 2181 sections 5.2 and 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8).
Publication validates observation times and computes expiry across retained
alternate chains as well as the primary `DnsCandidate::records()` chains.
Zero/high-bit/expired TTLs grant no fresh lifetime; last-good retention and
paced refresh remain distinct from freshness.

Only a denial of the original NAPTR question, including its validated owner
alias chain, can negatively cache that query. Reuse the enclosing-authority
SOA and `min(SOA TTL, SOA.MINIMUM)` rules of
[RFC 2308 section 5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5).
A replacement NAPTR, SRV or address denial cannot lend negative authority to
the root; neither can a child SRV `ServiceUnavailable` result. Preserve these
as branch outcomes. For a partial positive result, bound refresh by the
shortest failed branch-prefix deadline and either its SOA/withdrawal deadline
or `failure_observed_at + partial_failure_ttl`. SOA/withdrawal bounds use the
existing negative-cap path. Refusals, transient failures and incomplete higher-ranked work cut by a
deadline or work budget use the ordinary partial-failure bound, with the stop
observation time for unstarted work. A prefix cut only because 16 endpoints
were assembled keeps its record-derived freshness: all unstarted branches
rank below every retained endpoint and add no partial-failure bound. Omitted alternate metadata alone does not
invalidate a complete retained primary path. Missing/zero SOA timing remains
uncacheable and uses paced retry. Every failure preserves last-good candidates
and their original deadlines. The typed no-match error follows the existing negative-deadline lifecycle
above; it never freshens stale endpoints.

## Retained size

The endpoint/host/path limits apply to cached payloads as well as responses.
At most 64 paths contain 16 timed records and 14 NAPTR hops each. On 64-bit
platforms, a conservative bound for retained DNS-derived metadata is 2 MiB
per answer (512 MiB for 256 maximally populated cache entries), excluding
allocator bookkeeping. Add up to `16 * L` per answer for copies of the
caller-owned label, where `L` is its allocated byte length; this existing
label API is not length-bounded. Cache query keys/configuration identities
are separate caller-owned storage.
This includes bounded names (254 text bytes), SERVICES (255 bytes), raw
selection metadata, endpoint/host references, and collection headers. Counted
collections are compacted before retention; common timed records may be shared.
The transient per-question/branch trace is not cached. A size regression must
check the bound against maximum-sized retained metadata, not just empty types.

## Test and qualification plan

Add deterministic byte fixtures and a `dns_snaptr` integration target using
the existing fake-server patterns and shared `tests/support::bind_dns_pair`.
All names/answers are synthetic; tests never contact public or system DNS.

| Contract | Required regression and discriminating mutation |
| --- | --- |
| Framing and branch isolation | Counted-string/RDLENGTH boundaries, valid/hostile compression, case-folded and mixed empty/`s`/`a` flags. For each semantic refusal, combine a bad record with a healthy sibling and require success plus the typed branch trace. Also test all paths refused. Accepting regexp, following an unknown flag, or aborting healthy siblings must fail. |
| Filters and coexistence | Exact PGW pair, multi-protocol records, wrong Diameter application/transport, application-only match, case equivalence, invalid requested ID/qualifier, and noncanonical received IDs. Mix ENUM `E2U+sip` with `u`/regexp, legacy `AAA+D2S`, and malformed unrelated SERVICES beside a valid match; malformed requested SERVICES alone must be a typed refusal. Whole-field parsing of unrelated records, prefix matching and child protocol switching must fail. |
| Host prefix and deduplication | Reproduce TS 29.303 A.3.5/G.3.3's direct/delegated two-PGW, four-address pool, then add a third PGW and a fifth address; duplicate paths must not consume endpoint slots. Nine dual-stack hosts must return the best 16-endpoint prefix with coverage counts. Include shared endpoints under distinct host names, partial host addresses, bounded alternate provenance, and mixed-mode legacy weights. Throwing away the prefix, duplicating endpoints or claiming exhaustive coverage must fail. |
| Ordering and seed | Retain higher-order candidates after a successful lower group; test two ancestral levels, order/preference conflicts, 3GPP weights at 0/65535, SRV priority/weight and ports. Check fixed seed-derivation vectors, owner/type separation, wire-order permutations, and a shared child drawn once. Force later siblings to release an earlier one; verify slot refilling, late replacement of full endpoint/path pools and rebuilt host references. Arrival-dependent order, flattened order/preference and a different S-NAPTR legacy weight encoding must fail. |
| Concurrency and backtracking | Use the default attempts and automatic budget with silent first-ranked delegations, address hosts, SRV owners and SRV targets; also use the full unmodified default limits. Retain healthy siblings, child Timeout outcomes and partial freshness. Bound concurrent questions, reserve backtracking time for each non-root kind while an alternative remains, progress nested siblings and share in-flight data without consuming the record budget prematurely. Use an in-process datagram fixture and paused time for deadline ordering: a lone path must retry a lost first packet and complete a healthy chain. A healthy retry or delayed answer must also survive a dead sibling already in flight. Release the cap when siblings finish; shared waiters, cached NAPTR/SRV paths to the same question, and exhausted allowances must not create alternatives. A cached path to a different admissible child still needs backtracking time. Pin logical allowance consumed by queued duplicates and keep two healthy queued branches within a short virtual-time budget. Assert outcomes, question counts and ordering; no correctness assertion depends on host-clock margins. |
| Completed prefix | Retain outcomes and coverage from admitted failures after the pool fills. Test transient, timeout and SOA failures above and below a full prefix, and below a partial prefix; only failures below all 16 endpoints avoid a freshness bound. With one slot, assert the exact wire questions and that a lower-ranked host is never queried after 16 better endpoints complete. Disabling the prefix stop or applying a lower failure's bound must fail. |
| Unrelated service syntax | Filter malformed first SERVICES tokens beside a valid match and in an unrelated-only Diameter realm. The latter must remain `NotAdvertised` through ordinary cache publication, allowing caller-owned section 5(f) fallback. |
| Bounds and cancellation | Self/two-node/case/alias loops and a shared-child diamond; exact depth/provenance boundaries; each record/lookup/target/retention limit with and without an already healthy path. A slow delegation after a healthy host must yield a timed-out partial answer. Budget-blocked higher-ranked paths must expose outcomes/freshness bounds. Resetting budgets per branch, dropping completed results, missing coverage or leaking work after cancellation must fail. |
| Root classification and RFC 6408 | No root NAPTR (NXDOMAIN and NODATA); unrelated-only NAPTR; extended application/transport mismatch under 5(b)/(c); legacy-only 5(d)/(e); matching explicit/application-only records; malformed requested fields; mixed extended/legacy records. Assert each typed classification and allowed caller action, including explicit 5(f) SRV names. Check classification TTL/negative cap, zero/high-bit/unknown timing, filter/profile cache isolation, `finish_refresh` publication fencing and refresh pacing. Include relay-only answers and an SCTP mismatch beside an independent TCP match. Conflating absence with mismatch, allowing downgrade, or caching a decision indefinitely must fail. |
| Root versus child failures | Root SERVFAIL/REFUSED/timeout must retain its type and have no root classification. Child SERVFAIL/timeout that could affect the retained prefix must shorten positive freshness via `partial_failure_ttl`; child SOA denials must use the negative-cap path instead. All-child SERVFAIL/NXDOMAIN/timeout must yield `Snaptr(NoUsablePath)` with `Match` and the original child outcomes, unless the overall work/deadline limit itself expires. Promoting a child DNS error to a root error must fail. |
| TTL and negative authority | Shortest TTL at every chain position; staggered observations; duplicate/filtered low-TTL RRset members; coalesced alternate paths; zero/high-bit TTLs; partial/capped results and retained last-good data. Check enclosing, missing and unrelated SOAs, root negatives versus child NAPTR/SRV/address denials and SRV withdrawal. Restarting TTLs, losing a shorter retained-path bound, or promoting child authority must fail. |
| Composition and defaults | Missing/zero service defaults rejected before I/O; GTP-C 2123 and Diameter 3868 address terminals; secure-profile default and explicit SRV ports; source/profile mismatch, UDP/EDNS/TCP, source binding, families, SRV aliases, admission and redaction. Assert A/AAAA/SRV/NAPTR source and outcome types, including delegated NAPTR. Any unknown-type-to-AAAA mapping must fail. |

Record failing tests before implementation, then demonstrate the targeted
mutations are detected. Run all peer-discovery tests, focused Clippy, format
and documentation checks on the final candidate, followed by the repository's
required final gates, including retained-platform compilation. Reuse stable
worktree-local build caches and retain command, source revision, profile and
result evidence separately. The wire and cache regressions live in `tests/dns_snaptr.rs`, codec fixtures
in `src/dns_wire_tests.rs`, seed vectors in `src/dns_order.rs`, and retained
size checks in `src/snaptr.rs`. Qualification results remain external to the
public contract.
