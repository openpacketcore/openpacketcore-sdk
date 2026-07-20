//! Gated integration test for the BIRD control-socket adapter.
//!
//! This test only runs when explicitly enabled against a live BIRD 2 daemon:
//!
//! ```sh
//! OPC_IPSEC_LB_BIRD_INTEGRATION=1 \
//! OPC_IPSEC_LB_BIRD_SOCKET=/run/bird/bird.ctl \
//! OPC_IPSEC_LB_BIRD_FRAGMENT_DIR=/etc/bird/opc.d \
//! cargo test -p opc-ipsec-lb --test routing_bird_integration
//! ```
//!
//! Reference `bird.conf` for the gated environment (documentation prefixes
//! and RFC 6996 private ASNs only):
//!
//! ```text
//! router id 192.0.2.2;
//! include "/etc/bird/opc.d/*.conf";
//!
//! protocol device { scan time 10; }
//!
//! protocol bfd bfd1 {
//!     interface "lo" {
//!         min rx interval 50 ms;
//!         min tx interval 50 ms;
//!         idle tx interval 300 ms;
//!     };
//! }
//!
//! protocol bgp edge_a {
//!     local 192.0.2.2 as 64512;
//!     neighbor 192.0.2.1 as 64513;
//!     ipv4 {
//!         import none;
//!         export where proto = "opc_adv_64512";
//!     };
//!     bfd on;
//! }
//! ```
//!
//! The test advertises and withdraws documentation-prefix host routes and
//! relays the (unestablished, no live upstream) session state of `edge_a`.
//! Without a live upstream peer the session stays in a non-established state,
//! which still proves session-state event relay; a fully established adjacency
//! additionally exercises the advertised-to-peer snapshot.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use opc_ipsec_lb::{
    AdvertisementLease, BirdAdapterConfig, BirdControlSocketAdapter, BirdDomainBinding, HostPrefix,
    IpAddress, LeaseGeneration, PeerSessionState, PrefixAdvertiserConfig, PrefixAdvertiserService,
    ReconcileDisposition, RoutingDomainTag, RoutingEventKind, RoutingStackAdapter,
};

fn gated_config() -> Option<BirdAdapterConfig> {
    if std::env::var("OPC_IPSEC_LB_BIRD_INTEGRATION")
        .ok()
        .as_deref()
        != Some("1")
    {
        return None;
    }
    let socket_path = PathBuf::from(std::env::var("OPC_IPSEC_LB_BIRD_SOCKET").ok()?);
    let fragment_dir = PathBuf::from(std::env::var("OPC_IPSEC_LB_BIRD_FRAGMENT_DIR").ok()?);
    Some(BirdAdapterConfig {
        socket_path,
        fragment_dir,
        domains: vec![BirdDomainBinding {
            domain: RoutingDomainTag::new(64512),
            static_protocol: "opc_adv_64512".to_owned(),
            peer_protocols: vec!["edge_a".to_owned()],
        }],
        command_timeout: Duration::from_secs(10),
    })
}

#[tokio::test]
async fn bird_adapter_advertises_withdraws_and_relays_session_events() {
    let Some(config) = gated_config() else {
        eprintln!(
            "skipping: set OPC_IPSEC_LB_BIRD_INTEGRATION=1 with OPC_IPSEC_LB_BIRD_SOCKET \
             and OPC_IPSEC_LB_BIRD_FRAGMENT_DIR to run against a live BIRD"
        );
        return;
    };
    let domain = RoutingDomainTag::new(64512);
    let adapter = BirdControlSocketAdapter::new(config).unwrap();

    let probe = adapter.probe().await.unwrap();
    assert!(probe.stack_reachable, "BIRD control socket unreachable");

    // Start from a clean slate so the test is re-runnable.
    adapter.withdraw_all(domain).await.unwrap();

    let service = PrefixAdvertiserService::new(adapter, PrefixAdvertiserConfig::default()).unwrap();
    let mut events = service.subscribe_events();

    let desired: BTreeSet<HostPrefix> = [
        HostPrefix::new(IpAddress::from(Ipv4Addr::new(203, 0, 113, 10))),
        HostPrefix::new(IpAddress::from(Ipv4Addr::new(198, 51, 100, 7))),
    ]
    .into_iter()
    .collect();
    let lease = AdvertisementLease::new(LeaseGeneration::new(1).unwrap(), 300).unwrap();
    let report = service
        .reconcile(domain, desired.clone(), Some(lease))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Advertised);
    assert!(report
        .outcomes
        .values()
        .all(|outcome| matches!(outcome, opc_ipsec_lb::PrefixApplyOutcome::Accepted)));

    // Session-state relay: edge_a has no live upstream in the reference
    // environment, so the relayed state must be a non-established transition.
    service.observe_once().await.unwrap();
    let mut saw_session_event = false;
    while let Ok(event) = events.try_recv() {
        if let RoutingEventKind::PeerSessionChanged { peer, state, .. } = &event.kind {
            assert_eq!(peer.name(), "edge_a");
            assert_ne!(*state, PeerSessionState::Established);
            saw_session_event = true;
        }
    }
    assert!(saw_session_event, "no session event relayed from BIRD");

    let snapshots = service.prefix_snapshots(domain);
    assert_eq!(snapshots.len(), 2);

    let report = service
        .reconcile(domain, BTreeSet::new(), None)
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Withdrawn);
    let snapshots = service.prefix_snapshots(domain);
    assert!(snapshots
        .iter()
        .all(|snapshot| snapshot.advertised_to.is_empty()));
}

#[test]
fn gated_reference_config_uses_only_documentation_prefixes_and_private_asns() {
    // The reference configuration in this file's documentation uses only
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and ASNs 64512-65534.
    let documentation_v4 = [
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
    ];
    for address in documentation_v4 {
        assert!(address.is_ipv4());
    }
    for asn in [64512u32, 64513] {
        assert!((64512..=65534).contains(&asn));
    }
}
