# opc-peer-discovery

## Purpose

`opc-peer-discovery` provides transport-neutral peer discovery and deterministic
endpoint selection for packet-core CNFs. It owns static-peer ordering,
resolver-result selection, redaction-safe evidence, negative caching, and a
pure stale-while-revalidate address cache.

The crate includes an address-mode resolver over an injected lookup port.
Service/SRV and S-NAPTR modes are modeled but currently report unavailable.

## API Shape

- Selection: `discover_and_select`, `PeerDiscoveryRequest`, `SelectedPeer`,
  `PeerCandidate`, `PeerCandidateSource`, `CandidateDecision`, and
  `PeerDiscoveryEvidence`.
- Resolver port: `PeerResolver`, `PeerResolverError`, `ServiceDiscoveryInput`,
  `ServiceDiscoveryMode`, `DiscoveryTarget`, `ResolvedPeers`, and
  `DiscoveryEvidence`.
- Address resolver: `AddressLookup`, `AddressLookupError`,
  `AddressPeerResolver`, and `StdAddressLookup`.
- Caches: `PeerNegativeCache`, `PeerAddressCache`, `CachedPeers`,
  `DiscoveryCacheKey`, and `PeerDiscoveryTime`.
- Identity and transport: `PeerLabel`, `PeerTransport`, and
  `TELCO_PEER_DISCOVERY_PROFILE`.
- Errors: `PeerDiscoveryError` and `PeerDiscoveryErrorCode` carry only safe
  labels, stable keys, and stable reason codes.

## Usage

```rust,no_run
use std::time::Duration;

use opc_peer_discovery::{
    discover_and_select, PeerCandidate, PeerDiscoveryRequest, PeerDiscoveryTime,
    PeerLabel, PeerNegativeCache, PeerResolver, PeerResolverError, PeerTransport,
    ResolvedPeers, ServiceDiscoveryInput,
};

struct NoopResolver;

impl PeerResolver for NoopResolver {
    fn resolve(
        &mut self,
        _input: &ServiceDiscoveryInput,
        _timeout: Duration,
    ) -> Result<ResolvedPeers, PeerResolverError> {
        Err(PeerResolverError::Unavailable)
    }
}

let request = PeerDiscoveryRequest {
    static_peers: vec![PeerCandidate::static_peer(
        PeerLabel::new("pgw-a").unwrap(),
        "127.0.0.1:2123".parse().unwrap(),
        PeerTransport::Udp,
        10,
        100,
    )],
    now: PeerDiscoveryTime::from_millis(1_000),
    ..PeerDiscoveryRequest::default()
};

let mut resolver = NoopResolver;
let mut negative_cache = PeerNegativeCache::default();
let selected = discover_and_select(request, &mut resolver, &mut negative_cache).unwrap();
assert_eq!(selected.label.as_str(), "pgw-a");
```

## Relationships

- Product crates inject resolvers for DNS, NRF, static inventory, or tests.
- `StdAddressLookup` uses the blocking system resolver; async callers should
  run it off the request hot path and cache results with `PeerAddressCache`.
- SBI/NRF-specific discovery logic belongs in `opc-sbi`; this crate remains
  transport-neutral.

## Status And Limits

- `AddressPeerResolver` supports `ServiceDiscoveryMode::Address` with a default
  port and caps one lookup to 16 candidates.
- `Service` and `Snaptr` modes are not implemented yet and return
  `PeerResolverError::Unavailable`.
- Selection is deterministic: lower priority wins, then higher weight, then a
  stable tie-break.
- `Debug` for targets, endpoints, and selected peers avoids raw host/address
  disclosure.

## Roadmap

- Add SRV and S-NAPTR resolvers without changing the resolver port.
- Keep asynchronous lookup driving outside the pure selection/cache core.
- Preserve redaction-safe evidence as new resolver modes are added.

## Verification

```sh
cargo test -p opc-peer-discovery
```
