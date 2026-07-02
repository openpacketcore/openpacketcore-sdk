# opc-peer-discovery

## Purpose

`opc-peer-discovery` provides transport-neutral peer discovery and deterministic endpoint selection for packet-core CNFs. It does not perform live DNS itself; products inject a resolver for address, service, S-NAPTR, NRF-backed, or deterministic test-table discovery. The crate keeps shared mechanics for static peers, resolver timeouts, negative caching, priority/weight ordering, and redaction-safe selection evidence in one place.

## Usage

```rust,no_run
use std::time::Duration;

use opc_peer_discovery::{
    discover_and_select, PeerCandidate, PeerDiscoveryRequest, PeerDiscoveryTime, PeerLabel,
    PeerNegativeCache, PeerResolver, PeerResolverError, PeerTransport, ResolvedPeers,
    ServiceDiscoveryInput,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let request = PeerDiscoveryRequest {
        static_peers: vec![PeerCandidate::static_peer(
            PeerLabel::new("pgw-a")?,
            "127.0.0.1:2123".parse()?,
            PeerTransport::Udp,
            10,
            100,
        )],
        now: PeerDiscoveryTime::from_millis(1_000),
        ..PeerDiscoveryRequest::default()
    };

    let mut resolver = NoopResolver;
    let mut negative_cache = PeerNegativeCache::default();
    let selected = discover_and_select(request, &mut resolver, &mut negative_cache)?;

    assert_eq!(selected.label.as_str(), "pgw-a");
    Ok(())
}
```

## Testing

```bash
cargo test -p opc-peer-discovery
```

## Architecture

The crate exposes pure discovery data types, the injected `PeerResolver` port, and `discover_and_select` for deterministic selection. Its manifest has no async runtime, DNS, NRF, or transport dependencies; `thiserror` is the only external dependency and is used for redaction-safe errors. Product crates own the resolver implementation and pass `PeerDiscoveryRequest` values into the SDK, while `PeerNegativeCache` keeps deterministic not-found suppression at the boundary.
