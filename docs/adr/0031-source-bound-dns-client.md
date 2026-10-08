# ADR 0031: Bounded source-bound DNS stub client

## Status

Accepted.

## Context

The DNS contracts in ADR 0030 need a resolver that supplies actual TTLs and
negative SOA timing while respecting the consumer's configured servers and
source plane. The legacy getaddrinfo bridge cannot provide those properties.
The cache must remain independent of runtime, sockets and task ownership.

## Decision

Add a Tokio `DnsClient` producing the existing `DnsAnswer`/`DnsError` contracts,
with separate redacted response-source metadata and low-cardinality discard
counters. Configuration is immutable and must match the query's profile and
source-plane identities. Resolve only absolute names; do not apply search
lists, NSS, environment overrides or referral destinations. This preserves
peer identity across hosts (RFC 1034 section 3.1).

Use UDP with EDNS(0), one FORMERR retry without OPT, and TCP after a validated
truncated reply. All fallback work shares the same server-attempt deadline.
Use fresh sockets, fallible OS randomness for IDs, kernel ephemeral-port
allocation honoring host range/reservations, concrete
UDP local binding, and strict response source/ID/question matching. TCP
connects only to the same configured server and validates its framed replies.
Source address and Linux interface binding apply to both transports;
unsupported interface binding and kernel errors fail closed.

Follow CNAME chains only within the answer, with loop/conflict/depth checks.
Normalize each relevant RRset to its lowest effective TTL; high-bit values
participate as zero before selection. Retain per-response observation times
and all alias records. Only enclosing authority SOAs confer negative cache
lifetime. Two-family denial requires both families to be negative and uses
their shortest lifetime. A partial positive result retains its positive record
lifetimes, bounded by the failed family's SOA deadline or a configurable failure
interval of zero or one second through five minutes. Zero uses the cache's
paced refresh policy; nonzero intervals below one second are rejected.
`DnsAnswer::with_freshness_bound` only shortens freshness. SOA denials use
`with_negative_freshness_bound` so publication also applies S1's tunable
negative TTL cap, without granting negative authority to a positive answer.
Per-question outcomes expose the partial failure. Separate
family keys provide independent refresh and last-good retention today.
Retaining separate family RRsets within a dual-stack key remains a follow-up.
Order all usable candidates from both families using the existing destination
policy before retaining the first sixteen. The 128-record response bound limits
temporary candidates to 256. Normalize the complete RRset TTL before retention,
including addresses outside the final candidate cap. Invalid wire names remain
malformed answers, including names in the echoed question.

The behaviors are anchored to these clauses:

| Behavior | Authority |
|---|---|
| A envelope, compression, TCP framing | [RFC 1035 sections 3.4.1, 4.1 and 4.2.2](https://www.rfc-editor.org/rfc/rfc1035.html) |
| AAAA wire address | [RFC 3596 section 2.2](https://www.rfc-editor.org/rfc/rfc3596.html#section-2.2) |
| CNAME relationships | [RFC 1034 section 3.6.2](https://www.rfc-editor.org/rfc/rfc1034.html#section-3.6.2), [RFC 2181 section 10.1](https://www.rfc-editor.org/rfc/rfc2181.html#section-10.1) |
| EDNS payload and fallback | [RFC 6891 sections 6.1, 6.2.2–6.2.3](https://www.rfc-editor.org/rfc/rfc6891.html#section-6) |
| Truncation/TCP support and combined prefix/message write | [RFC 7766 sections 4, 5 and 8](https://www.rfc-editor.org/rfc/rfc7766.html#section-4), [RFC 2181 section 9](https://www.rfc-editor.org/rfc/rfc2181.html#section-9) |
| Reply matching and entropy | [RFC 5452 sections 9.1–9.2](https://www.rfc-editor.org/rfc/rfc5452.html#section-9) |
| Consistent RRset TTL and conservative high-bit policy | [RFC 2181 sections 5.2, 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-5.2) |
| NODATA/referral distinction, SOA timing and partial-failure freshness | [RFC 2308 sections 2.2, 5, 7.1 and 7.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-5) |

### Wire format and dependencies

Keep a small internal codec instead of adding a general resolver stack. It
encodes one IN A/AAAA question and optional OPT; it decodes the envelope,
address/CNAME/SOA data and OPT extended errors. Legacy name-bearing records
are parsed only to validate compression boundaries. Unknown records/options
are skipped with exact length checks. Wire labels accept arbitrary binary data
per RFC 2181 section 11; non-ASCII-contract owners cannot match a query, and
unused SOA/NS/MX names need only framing validation. Caller names and required
CNAME targets retain the public ASCII contract. The 128 records, 256 name-parser
steps and a fixed 2 KiB compression-boundary bitmap keep work and memory bounded.
Pointer targets inside unsupported opaque RDATA are rejected. This is a strict
stub-client subset, not a general DNS forwarding codec.

There is no new DNS wire dependency or second cache/runtime. The additional
direct dependency edges reuse versions already in the workspace lockfile:

| Dependency | Purpose and features | License | Declared MSRV |
|---|---|---|---|
| Tokio 1.53.1 | Existing workspace runtime/net/macros, plus `io-util`, `sync`, `time`; upstream defaults are empty | MIT | 1.71 |
| socket2 0.6.4 | Safe socket construction and Linux `SO_BINDTODEVICE`; `all` exposes platform options, no default features | MIT OR Apache-2.0 | 1.70 |
| getrandom 0.4.2 | Fallible OS entropy, default features disabled; no RNG state shared across queries | MIT OR Apache-2.0 | 1.85 |

Their licenses are already allowed by `deny.toml`; Rust 1.89 remains the
workspace floor. The crate adds no unsafe code. CI checks Linux and retained
FreeBSD/Apple compilation paths. Tests use independent RFC byte fixtures,
bounded hostile mutations and in-process loopback servers, including source
binding, identity mismatch, fallback, CNAME, negatives, failover and limits.

## Consequences

The getaddrinfo bridge is unchanged. The client owns no background worker,
queue, durable file or session. Dropping a resolution future closes its
sockets and releases admission; crash/restart requires no operator or node
cleanup. Callers continue to own cache leases, publication and refresh
scheduling. Configuration replacement is live through a new client/identity.

DNSSEC validation, authenticated DNS transports, SRV and S-NAPTR are out of
scope. The AD bit is not an authentication signal. Public diagnostic output
contains no names, answers, servers, source addresses or opaque IDs.

The strict reply matcher drops a questionless FORMERR, so it cannot trigger
EDNS fallback. In-answer CNAME traversal with no terminal data/SOA returns
uncacheable NODATA. Scoped link-local resolv.conf servers are skipped while
retaining other servers. Kernels before Linux 5.7 require CAP_NET_RAW for
interface binding. Families remain sequential: a dead first server costs its
full timeout again for the other family. Oversized UDP packets are dropped
within the discard/deadline bounds, allowing a subsequent valid reply.
