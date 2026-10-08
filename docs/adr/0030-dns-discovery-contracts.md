# ADR 0030: DNS discovery contracts and consumer-owned cache lifetime

## Status

Accepted.

## Context

The system address resolver provides endpoints without DNS record TTLs or
authoritative failure classification. A caller-selected cache interval cannot
represent record freshness, and automatic cache eviction can discard the last
usable answer during a resolver outage. Existing callers need compatibility.

## Decision

Add `DnsQuery`, `DnsAnswer`, `DnsError` and `DnsCache` alongside the legacy
`opc-peer-discovery` APIs. Query identity compares all canonical name, mode,
service, transport, port, resolver profile, source plane and family fields.
Opaque profile/plane IDs identify immutable caller-owned configurations.

Each candidate retains its traversed record owners, types, remaining TTLs and
monotonic observation times. The shortest absolute record deadline determines
set freshness. Zero TTL and unavailable TTL never gain an invented lifetime.
High-bit TTLs follow the conservative zero interpretation from
[RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8).
The seven-day positive cap follows the recommendation in
[RFC 8767 section 4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4),
without adopting its later unsigned high-bit interpretation. Cold authoritative
negatives use observed SOA timing and any earlier alias-chain deadline, capped
at three hours by default per
[RFC 2308 section 5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5).
Both caps are tunable and clamped to 2^31 - 1 seconds under the conservative
TTL policy; the negative cap cannot exceed the positive cap.
Caps apply at publication without extending any existing record deadline.
`DnsCacheStatus::fresh_until` exposes the effective positive deadline, including
the cap, even after expiry. Drivers schedule using that deadline and retry/flight
state; `DnsAnswer::expires_at()` reports only uncapped record provenance.

Transient failures and uncacheable negatives use bounded exponential retry
with jitter, capped at five minutes per
[RFC 2308 sections 7.1–7.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-7).
Zero/unknown/expired-TTL successes use a separate tunable refresh interval,
defaulting to five seconds with equal jitter from half to all of the interval.
This success setting does not change failure backoff. Retry pacing never grants
freshness or authoritative negative state. Every failure preserves
the positive last-good answer, its provenance and its original freshness
deadline; observations expose stale age and the last stable error code.

The consumer retains positive data until explicit removal. At capacity,
reclaim expired cold failures without in-flight work, then reject new keys if
no room remains. Reclaimed cold keys leave `refresh_due` and lose their last
error; drivers keep their configured key set and re-admit needed keys. Never
evict last-good answers. Bound each DNS payload to
16 candidates with at most 16 records each. One bounded refresh lease per key
deduplicates work. One-use tokens fence late results, removal/recreation and
cross-cache publication. A driver owns synchronization, notification, I/O and
its monotonic clock. Expired leases become timeouts on the next admission or
due-key scan; no operator action is involved.

Address ordering uses only destination information available to this library:
default precedence, scope and stable input order from
[RFC 6724 section 6](https://www.rfc-editor.org/rfc/rfc6724.html#section-6).
Source-dependent routing and usability decisions remain with the host/driver.
The legacy bridge keeps system resolver order, with family filtering only;
IPv4-mapped IPv6 endpoints follow the IPv4 family policy.
Names, addresses and configuration IDs never enter new DNS diagnostics.

## Consequences

The old resolver and caller-TTL cache keep their public shapes and behavior.
The system adapter can bridge to the DNS API with unknown TTL and ambiguous
legacy failures; it cannot honor source binding or enforce cancellation.
Consumers opt into the DNS-aware cache explicitly. There are no new dependencies
or durable formats. Public enums and public-field structs are non-exhaustive
to accommodate later resolver capabilities.

The next implementation supplies asynchronous DNS transport and real response
timing. SRV target weighting/ports and bounded S-NAPTR traversal follow
separately, preserving the same cache and provenance contracts. Full behavior
and driving instructions are in the
[crate README](../../crates/opc-peer-discovery/README.md#dns-contracts-and-cache).
