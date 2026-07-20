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
//! The reference `bird.conf` for the gated environment is shipped at
//! `tests/fixtures/bird_reference.conf` and validated by
//! [`reference_config_uses_only_documentation_prefixes_and_private_asns`].
//!
//! The test advertises and withdraws documentation-prefix host routes and
//! relays the (unestablished, no live upstream) session state of `edge_a`.
//! Without a live upstream peer the session stays in a non-established state,
//! which still proves session-state event relay; a fully established adjacency
//! additionally exercises the advertised-to-peer snapshot.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use opc_ipsec_lb::{
    AdvertisementLease, BirdAdapterConfig, BirdControlSocketAdapter, BirdDomainBinding, HostPrefix,
    IpAddress, LeaseGeneration, PeerSessionState, PrefixAdvertiserConfig, PrefixAdvertiserService,
    PrefixApplyOutcome, ReconcileDisposition, RoutingDomainTag, RoutingEventKind,
    RoutingStackAdapter,
};

const REFERENCE_CONFIG: &str = include_str!("fixtures/bird_reference.conf");

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
        HostPrefix::new(IpAddress::V4([203, 0, 113, 10])),
        HostPrefix::new(IpAddress::V4([198, 51, 100, 7])),
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
        .all(|outcome| matches!(outcome, PrefixApplyOutcome::Accepted)));

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

/// Parse the shipped reference configuration and prove it stays inside
/// documentation prefixes and RFC 6996 private ASNs.
#[test]
fn reference_config_uses_only_documentation_prefixes_and_private_asns() {
    let mut saw_bgp = false;
    let mut saw_bfd = false;
    let mut previous_token = "";
    for token in REFERENCE_CONFIG.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')) {
        if token.is_empty() {
            continue;
        }
        if let Ok(address) = token.parse::<IpAddr>() {
            let documentation = match address {
                IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    octets[..3] == [192, 0, 2] || octets[..3] == [198, 51, 100] || {
                        octets[..3] == [203, 0, 113]
                    }
                }
                IpAddr::V6(v6) => v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8,
            };
            assert!(
                documentation,
                "non-documentation address {address} in reference config"
            );
        }
        if previous_token == "as" {
            let asn: u32 = token.parse().expect("ASN after 'as' keyword");
            assert!(
                (64512..=65534).contains(&asn),
                "non-private ASN {asn} in reference config"
            );
        }
        saw_bgp |= token == "bgp";
        saw_bfd |= token == "bfd";
        previous_token = token;
    }
    assert!(saw_bgp, "reference config must contain a BGP peer");
    assert!(saw_bfd, "reference config must contain a BFD instance");
    assert!(REFERENCE_CONFIG.contains("protocol bgp edge_a"));
    assert!(REFERENCE_CONFIG.contains("opc_adv_64512"));
}
