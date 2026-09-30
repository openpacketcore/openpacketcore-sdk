//! Public contract for the RFC 021 N3IWF session intent and state lifecycle.
//!
//! Synthetic addresses only (RFC 1918, RFC 5737 and RFC 3849 ranges). These
//! tests exercise typed validation, the disposition model and the mock state
//! lifecycle. They make no packet-forwarding claim: every adapter keeps
//! reporting the N3IWF forwarding role as `Missing`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use opc_gtpu_dataplane::n3::{
    LocalN3DownlinkTnl, N3ForwardingRole, N3Qfi, N3iwfChildSa, N3iwfDownlinkSelection,
    N3iwfDownlinkUnknownQfi, N3iwfInstalledSession, N3iwfN3Tunnel, N3iwfQfiSet, N3iwfQosFlow,
    N3iwfSessionConflict, N3iwfSessionFlowUpdate, N3iwfSessionGeneration,
    N3iwfSessionInstallOutcome, N3iwfSessionIntent, N3iwfSessionLifecycleCapabilities,
    N3iwfSessionMismatchField, N3iwfSessionModelError, N3iwfSessionOccupancy, N3iwfSessionReadback,
    N3iwfSessionReconcileOutcome, N3iwfSessionRecoveryRequest, N3iwfSessionRemovalOutcome,
    N3iwfSessionSelector, N3iwfUplinkAdmission, ReceivedN3UplinkTnl, N3IWF_SESSION_MAX_CHILD_SAS,
};
#[cfg(target_os = "linux")]
use opc_gtpu_dataplane::EbpfGtpuDataplaneBackend;
use opc_gtpu_dataplane::{
    CreateGtpDeviceRequest, DscpCodepoint, GtpBearerMark, GtpDevice, GtpPdpContext, GtpuCapability,
    GtpuDataplaneBackend, GtpuError, GtpuProbe, GtpuSourcePortPolicy, GtpuUplinkSourcePortPolicy,
    LinuxGtpuDataplaneBackend, MockGtpuDataplaneBackend, MockPdpContextFault,
    PdpContextIndeterminateReason, PdpDeviceIncarnation, PdpRestartRecoveryProof,
    RemovePdpContextRequest, Teid, UnsupportedGtpuDataplaneBackend,
};

const LINK: u32 = 7;
const DEFAULT_MARK: u32 = 0x100;
const VOICE_MARK: u32 = 0x200;
const VIDEO_MARK: u32 = 0x300;

fn qfi(value: u8) -> N3Qfi {
    N3Qfi::new(value).unwrap()
}

fn mark(value: u32) -> GtpBearerMark {
    GtpBearerMark::new(value).unwrap()
}

fn teid(value: u32) -> Teid {
    Teid::new(value).unwrap()
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(last: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x45, 0, 0, 0, 0, last))
}

fn qfis(values: &[u8]) -> N3iwfQfiSet {
    N3iwfQfiSet::try_from_qfis(values.iter().map(|value| qfi(*value))).unwrap()
}

fn ue_v4() -> IpAddr {
    v4(10, 45, 0, 2)
}

fn up_v4() -> IpAddr {
    v4(10, 200, 0, 1)
}

fn tunnel(local_teid: u32) -> N3iwfN3Tunnel {
    N3iwfN3Tunnel::new(
        LINK,
        ReceivedN3UplinkTnl::new(v4(192, 0, 2, 1), teid(0x1000_0001)).unwrap(),
        LocalN3DownlinkTnl::new(v4(192, 0, 2, 2), teid(local_teid)).unwrap(),
        GtpuSourcePortPolicy::Any,
        GtpuUplinkSourcePortPolicy::LegacyServicePort,
    )
    .unwrap()
}

fn child_sa(mark_value: u32, associated: &[u8]) -> N3iwfChildSa {
    N3iwfChildSa::new(mark(mark_value), ue_v4(), up_v4(), qfis(associated)).unwrap()
}

fn flows(values: &[u8]) -> Vec<N3iwfQosFlow> {
    values
        .iter()
        .map(|value| N3iwfQosFlow::new(qfi(*value), None))
        .collect()
}

/// Session flows 1, 5, 9 and 63. QFI 1 is explicit on the default Child SA,
/// QFIs 5 and 9 are explicit on the voice Child SA, and QFI 63 has no explicit
/// association, so TS 24.502 section 8.3.1 b) sends it on the default.
fn session(local_teid: u32) -> N3iwfSessionIntent {
    let mut qos_flows = flows(&[5, 9, 63]);
    qos_flows.push(N3iwfQosFlow::new(
        qfi(1),
        Some(DscpCodepoint::new(46).unwrap()),
    ));
    N3iwfSessionIntent::new(
        tunnel(local_teid),
        qos_flows,
        vec![child_sa(VOICE_MARK, &[5, 9]), child_sa(DEFAULT_MARK, &[1])],
        mark(DEFAULT_MARK),
        N3iwfDownlinkUnknownQfi::Drop,
    )
    .unwrap()
}

/// A PDU session modification of [`session`]: QFI 9 moves to a new video
/// Child SA, the voice Child SA is deleted so QFI 5 falls back to the
/// default, QFI 20 joins the session, and unknown downlink QFIs now use the
/// default Child SA.
fn modified_session(local_teid: u32) -> N3iwfSessionIntent {
    N3iwfSessionIntent::new(
        tunnel(local_teid),
        flows(&[1, 5, 9, 20, 63]),
        vec![child_sa(DEFAULT_MARK, &[1]), child_sa(VIDEO_MARK, &[9, 20])],
        mark(DEFAULT_MARK),
        N3iwfDownlinkUnknownQfi::DefaultChildSa,
    )
    .unwrap()
}

fn selector_by_mark(value: u32) -> N3iwfSessionSelector {
    N3iwfSessionSelector::child_sa(LINK, mark(value)).unwrap()
}

fn first_generation() -> N3iwfSessionGeneration {
    N3iwfSessionGeneration::FIRST
}

// ---------------------------------------------------------------------------
// Typed intent validation
// ---------------------------------------------------------------------------

#[test]
fn intent_is_canonical_and_exposes_every_field() {
    let intent = session(0x2000_0001);
    let reordered = N3iwfSessionIntent::new(
        tunnel(0x2000_0001),
        {
            let mut qos_flows = vec![N3iwfQosFlow::new(
                qfi(1),
                Some(DscpCodepoint::new(46).unwrap()),
            )];
            qos_flows.extend(flows(&[63, 9, 5]));
            qos_flows
        },
        vec![child_sa(DEFAULT_MARK, &[1]), child_sa(VOICE_MARK, &[9, 5])],
        mark(DEFAULT_MARK),
        N3iwfDownlinkUnknownQfi::Drop,
    )
    .unwrap();
    assert_eq!(intent, reordered, "input order must not change identity");

    let flow_qfis: Vec<u8> = intent
        .qos_flows()
        .iter()
        .map(|flow| flow.qfi().get())
        .collect();
    assert_eq!(flow_qfis, [1, 5, 9, 63]);
    assert_eq!(
        intent.qos_flow(qfi(1)).unwrap().n3_uplink_dscp(),
        Some(DscpCodepoint::new(46).unwrap())
    );
    assert_eq!(intent.qos_flow(qfi(5)).unwrap().n3_uplink_dscp(), None);
    assert!(intent.qos_flow(qfi(2)).is_none());

    let marks: Vec<u32> = intent
        .child_sas()
        .iter()
        .map(|sa| sa.mark().get())
        .collect();
    assert_eq!(marks, [DEFAULT_MARK, VOICE_MARK]);
    assert_eq!(intent.default_child_sa().mark(), mark(DEFAULT_MARK));
    let voice = intent.child_sa(mark(VOICE_MARK)).unwrap();
    assert_eq!(voice.ue_inner_address(), ue_v4());
    assert_eq!(voice.up_address(), up_v4());
    assert_eq!(
        voice
            .associated_qfis()
            .iter()
            .map(N3Qfi::get)
            .collect::<Vec<_>>(),
        [5, 9]
    );
    assert!(intent.child_sa(mark(VIDEO_MARK)).is_none());
    assert_eq!(intent.downlink_unknown_qfi(), N3iwfDownlinkUnknownQfi::Drop);

    let n3 = intent.n3();
    assert_eq!(n3.link_ifindex(), LINK);
    assert_eq!(n3.received_uplink().destination(), v4(192, 0, 2, 1));
    assert_eq!(n3.received_uplink().teid(), teid(0x1000_0001));
    assert_eq!(n3.local_downlink().local_address(), v4(192, 0, 2, 2));
    assert_eq!(n3.local_downlink().teid(), teid(0x2000_0001));
    assert_eq!(n3.downlink_source_port_policy(), GtpuSourcePortPolicy::Any);
    assert_eq!(
        n3.uplink_source_port_policy(),
        GtpuUplinkSourcePortPolicy::LegacyServicePort
    );

    // The UE rule of TS 24.502 section 8.3.1: explicit association, else the default.
    for (value, expected) in [
        (1, DEFAULT_MARK),
        (5, VOICE_MARK),
        (9, VOICE_MARK),
        (63, DEFAULT_MARK),
    ] {
        assert_eq!(
            intent.uplink_child_sa(qfi(value)).unwrap().mark(),
            mark(expected)
        );
    }
    assert!(intent.uplink_child_sa(qfi(2)).is_none());
}

#[test]
fn intent_accepts_mixed_family_child_sas_and_an_empty_default_association() {
    let intent = N3iwfSessionIntent::new(
        tunnel(0x2000_0002),
        flows(&[0, 1]),
        vec![
            N3iwfChildSa::new(mark(DEFAULT_MARK), ue_v4(), up_v4(), N3iwfQfiSet::empty()).unwrap(),
            N3iwfChildSa::new(mark(VOICE_MARK), v6(2), v6(0x100), qfis(&[1])).unwrap(),
        ],
        mark(DEFAULT_MARK),
        N3iwfDownlinkUnknownQfi::DefaultChildSa,
    )
    .unwrap();
    assert!(intent.default_child_sa().associated_qfis().is_empty());
    assert_eq!(
        intent.uplink_child_sa(qfi(0)).unwrap().mark(),
        mark(DEFAULT_MARK)
    );
    assert_eq!(
        intent.uplink_child_sa(qfi(1)).unwrap().mark(),
        mark(VOICE_MARK)
    );
}

#[test]
fn intent_refuses_each_malformed_shape() {
    let default_sa = || child_sa(DEFAULT_MARK, &[1]);
    let build = |qos_flows: Vec<N3iwfQosFlow>, sas: Vec<N3iwfChildSa>, default: u32| {
        N3iwfSessionIntent::new(
            tunnel(0x2000_0003),
            qos_flows,
            sas,
            mark(default),
            N3iwfDownlinkUnknownQfi::Drop,
        )
    };

    assert_eq!(
        build(Vec::new(), vec![default_sa()], DEFAULT_MARK).unwrap_err(),
        N3iwfSessionModelError::NoQosFlows
    );
    assert_eq!(
        build(flows(&[1, 2, 1]), vec![default_sa()], DEFAULT_MARK).unwrap_err(),
        N3iwfSessionModelError::DuplicateQfi
    );
    assert_eq!(
        build(flows(&[1]), Vec::new(), DEFAULT_MARK).unwrap_err(),
        N3iwfSessionModelError::NoChildSas
    );
    let too_many: Vec<N3iwfChildSa> = (0..=N3IWF_SESSION_MAX_CHILD_SAS)
        .map(|index| child_sa(0x1000 + u32::try_from(index).unwrap(), &[]))
        .collect();
    assert_eq!(too_many.len(), N3IWF_SESSION_MAX_CHILD_SAS + 1);
    assert_eq!(
        build(flows(&[1]), too_many, 0x1000).unwrap_err(),
        N3iwfSessionModelError::TooManyChildSas
    );
    let at_limit: Vec<N3iwfChildSa> = (0..N3IWF_SESSION_MAX_CHILD_SAS)
        .map(|index| child_sa(0x1000 + u32::try_from(index).unwrap(), &[]))
        .collect();
    assert!(build(flows(&[1]), at_limit, 0x1000).is_ok());
    assert_eq!(
        build(
            flows(&[1]),
            vec![child_sa(DEFAULT_MARK, &[]), child_sa(DEFAULT_MARK, &[])],
            DEFAULT_MARK
        )
        .unwrap_err(),
        N3iwfSessionModelError::DuplicateChildSaMark
    );
    assert_eq!(
        build(flows(&[1]), vec![default_sa()], VOICE_MARK).unwrap_err(),
        N3iwfSessionModelError::UnknownDefaultChildSa
    );
    assert_eq!(
        build(
            flows(&[1]),
            vec![child_sa(DEFAULT_MARK, &[1, 2])],
            DEFAULT_MARK
        )
        .unwrap_err(),
        N3iwfSessionModelError::AssociatedQfiNotInSession
    );
    assert_eq!(
        build(
            flows(&[1, 2]),
            vec![child_sa(DEFAULT_MARK, &[1]), child_sa(VOICE_MARK, &[1, 2])],
            DEFAULT_MARK
        )
        .unwrap_err(),
        N3iwfSessionModelError::QfiAssociatedTwice
    );
    let other_ue =
        N3iwfChildSa::new(mark(VOICE_MARK), v4(10, 45, 0, 3), up_v4(), qfis(&[2])).unwrap();
    assert_eq!(
        build(flows(&[1, 2]), vec![default_sa(), other_ue], DEFAULT_MARK).unwrap_err(),
        N3iwfSessionModelError::InconsistentUeInnerAddress
    );
    // NWu inner addresses must not alias either N3 endpoint.
    for (ue, up) in [
        (v4(192, 0, 2, 2), up_v4()),
        (v4(192, 0, 2, 1), up_v4()),
        (ue_v4(), v4(192, 0, 2, 1)),
    ] {
        let aliased = N3iwfChildSa::new(mark(DEFAULT_MARK), ue, up, qfis(&[1])).unwrap();
        assert_eq!(
            build(flows(&[1]), vec![aliased], DEFAULT_MARK).unwrap_err(),
            N3iwfSessionModelError::AliasedAddress
        );
    }
    // The UP address may equal the local N3 address: one host address can serve both.
    let shared_local =
        N3iwfChildSa::new(mark(DEFAULT_MARK), ue_v4(), v4(192, 0, 2, 2), qfis(&[1])).unwrap();
    assert!(build(flows(&[1]), vec![shared_local], DEFAULT_MARK).is_ok());
}

#[test]
fn child_sa_and_tunnel_refuse_unusable_addresses() {
    let bad = [
        v4(0, 0, 0, 0),
        v4(224, 0, 0, 1),
        v4(255, 255, 255, 255),
        v4(127, 0, 0, 1),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        "ff02::1".parse().unwrap(),
    ];
    for address in bad {
        let peer = if address.is_ipv4() {
            up_v4()
        } else {
            v6(0x100)
        };
        assert_eq!(
            N3iwfChildSa::new(mark(1), address, peer, N3iwfQfiSet::empty()).unwrap_err(),
            N3iwfSessionModelError::InvalidInnerAddress
        );
        let ue = if address.is_ipv4() { ue_v4() } else { v6(2) };
        assert_eq!(
            N3iwfChildSa::new(mark(1), ue, address, N3iwfQfiSet::empty()).unwrap_err(),
            N3iwfSessionModelError::InvalidInnerAddress
        );
    }
    assert_eq!(
        N3iwfChildSa::new(mark(1), ue_v4(), v6(0x100), N3iwfQfiSet::empty()).unwrap_err(),
        N3iwfSessionModelError::MixedChildSaFamily
    );
    assert_eq!(
        N3iwfChildSa::new(mark(1), ue_v4(), ue_v4(), N3iwfQfiSet::empty()).unwrap_err(),
        N3iwfSessionModelError::AliasedAddress
    );

    let uplink = ReceivedN3UplinkTnl::new(v4(192, 0, 2, 1), teid(1)).unwrap();
    let downlink = LocalN3DownlinkTnl::new(v4(192, 0, 2, 2), teid(2)).unwrap();
    let downlink6 = LocalN3DownlinkTnl::new(v6(9), teid(2)).unwrap();
    assert_eq!(
        N3iwfN3Tunnel::new(
            0,
            uplink,
            downlink,
            GtpuSourcePortPolicy::Any,
            GtpuUplinkSourcePortPolicy::LegacyServicePort
        )
        .unwrap_err(),
        N3iwfSessionModelError::InvalidLinkIfindex
    );
    assert_eq!(
        N3iwfN3Tunnel::new(
            LINK,
            uplink,
            downlink6,
            GtpuSourcePortPolicy::Any,
            GtpuUplinkSourcePortPolicy::LegacyServicePort
        )
        .unwrap_err(),
        N3iwfSessionModelError::MixedN3Family
    );
    for invalid in [
        GtpuUplinkSourcePortPolicy::Selected(0),
        GtpuUplinkSourcePortPolicy::Selected(2152),
    ] {
        assert_eq!(
            N3iwfN3Tunnel::new(LINK, uplink, downlink, GtpuSourcePortPolicy::Any, invalid)
                .unwrap_err(),
            N3iwfSessionModelError::InvalidSourcePortPolicy
        );
    }
    assert!(N3iwfN3Tunnel::new(
        LINK,
        uplink,
        downlink,
        GtpuSourcePortPolicy::Exact(40_000),
        GtpuUplinkSourcePortPolicy::selected(40_001).unwrap()
    )
    .is_ok());
}

#[test]
fn qfi_set_is_bounded_ordered_and_rejects_duplicates() {
    assert_eq!(
        N3iwfQfiSet::try_from_qfis([qfi(3), qfi(1), qfi(3)]).unwrap_err(),
        N3iwfSessionModelError::DuplicateQfi
    );
    let set = N3iwfQfiSet::empty()
        .try_with(qfi(63))
        .unwrap()
        .try_with(qfi(0))
        .unwrap();
    assert_eq!(
        set.try_with(qfi(0)).unwrap_err(),
        N3iwfSessionModelError::DuplicateQfi
    );
    assert_eq!(set.iter().map(N3Qfi::get).collect::<Vec<_>>(), [0, 63]);
    assert_eq!(set.len(), 2);
    assert!(set.contains(qfi(63)) && !set.contains(qfi(62)));
    let all = N3iwfQfiSet::try_from_qfis((0..=63).map(qfi)).unwrap();
    assert_eq!(all.len(), 64);
    assert_eq!(
        all.iter().map(N3Qfi::get).collect::<Vec<_>>(),
        (0..=63).collect::<Vec<_>>()
    );
    assert!(N3iwfQfiSet::empty().is_empty());
}

#[test]
fn flow_update_and_selectors_refuse_invalid_inputs() {
    let current = N3iwfInstalledSession::new(session(0x2000_0004), first_generation());
    assert_eq!(
        N3iwfSessionFlowUpdate::new(current.clone(), session(0x2000_0005)).unwrap_err(),
        N3iwfSessionModelError::N3TunnelChanged
    );
    let update =
        N3iwfSessionFlowUpdate::new(current.clone(), modified_session(0x2000_0004)).unwrap();
    assert_eq!(update.expected(), &current);
    assert_eq!(update.desired(), &modified_session(0x2000_0004));

    assert_eq!(
        N3iwfSessionSelector::child_sa(0, mark(1)).unwrap_err(),
        N3iwfSessionModelError::InvalidLinkIfindex
    );
    assert_eq!(
        N3iwfSessionSelector::local_downlink(0, session(0x2000_0004).n3().local_downlink())
            .unwrap_err(),
        N3iwfSessionModelError::InvalidLinkIfindex
    );
    let from_intent = N3iwfSessionSelector::from_intent(&session(0x2000_0004));
    assert_eq!(
        from_intent,
        N3iwfSessionSelector::local_downlink(LINK, session(0x2000_0004).n3().local_downlink())
            .unwrap()
    );
    assert_eq!(from_intent.link_ifindex(), LINK);

    assert_eq!(first_generation().get(), 1);
    assert_eq!(first_generation().next().unwrap().get(), 2);
    let last = N3iwfSessionGeneration::new(std::num::NonZeroU64::MAX);
    assert!(last.next().is_none(), "generations never wrap");
}

// ---------------------------------------------------------------------------
// Disposition model (RFC 021 section 6), checked against an independent oracle
// ---------------------------------------------------------------------------

/// Independent statement of RFC 021 rows U1 to U4 for [`session`]: explicit
/// associations, the session QFI set and the default Child SA, written out
/// from the fixture rather than read from the intent.
fn oracle_uplink(child_sa_mark: u32, value: u8) -> N3iwfUplinkAdmission {
    let explicit = |q: u8| match q {
        1 => Some(DEFAULT_MARK),
        5 | 9 => Some(VOICE_MARK),
        _ => None,
    };
    let in_session = matches!(value, 1 | 5 | 9 | 63);
    if child_sa_mark != DEFAULT_MARK && child_sa_mark != VOICE_MARK {
        return N3iwfUplinkAdmission::UnknownChildSa;
    }
    if !in_session {
        return N3iwfUplinkAdmission::UnknownQfi;
    }
    let required = explicit(value).unwrap_or(DEFAULT_MARK);
    if required == child_sa_mark {
        N3iwfUplinkAdmission::Admitted
    } else {
        N3iwfUplinkAdmission::WrongChildSa
    }
}

#[test]
fn uplink_admission_matches_the_independent_model_for_every_qfi() {
    let intent = session(0x2000_0006);
    let mut admitted = 0;
    for child_sa_mark in [DEFAULT_MARK, VOICE_MARK, VIDEO_MARK, 1, u32::MAX] {
        for value in 0..=63 {
            let actual = intent.uplink_admission(mark(child_sa_mark), qfi(value));
            assert_eq!(
                actual,
                oracle_uplink(child_sa_mark, value),
                "uplink disposition for one synthetic Child SA/QFI pair"
            );
            if actual == N3iwfUplinkAdmission::Admitted {
                admitted += 1;
            }
        }
    }
    // QFIs 1 and 63 on the default, 5 and 9 on the voice Child SA.
    assert_eq!(admitted, 4);
}

#[test]
fn downlink_selection_matches_the_independent_model_for_every_qfi_and_policy() {
    for policy in [
        N3iwfDownlinkUnknownQfi::Drop,
        N3iwfDownlinkUnknownQfi::DefaultChildSa,
    ] {
        let base = session(0x2000_0007);
        let intent = N3iwfSessionIntent::new(
            *base.n3(),
            base.qos_flows().to_vec(),
            base.child_sas().to_vec(),
            mark(DEFAULT_MARK),
            policy,
        )
        .unwrap();
        for value in 0..=63u8 {
            let selection = intent.downlink_selection(qfi(value));
            match value {
                5 | 9 => {
                    assert!(
                        matches!(selection, N3iwfDownlinkSelection::Associated(sa) if sa.mark() == mark(VOICE_MARK))
                    );
                }
                1 => {
                    assert!(
                        matches!(selection, N3iwfDownlinkSelection::Associated(sa) if sa.mark() == mark(DEFAULT_MARK))
                    );
                }
                63 => {
                    assert!(
                        matches!(selection, N3iwfDownlinkSelection::SessionFlowDefault(sa) if sa.mark() == mark(DEFAULT_MARK))
                    );
                }
                _ => match policy {
                    N3iwfDownlinkUnknownQfi::Drop => {
                        assert!(matches!(selection, N3iwfDownlinkSelection::Drop));
                    }
                    N3iwfDownlinkUnknownQfi::DefaultChildSa => {
                        assert!(
                            matches!(selection, N3iwfDownlinkSelection::UnknownQfiDefault(sa) if sa.mark() == mark(DEFAULT_MARK))
                        );
                    }
                    _ => unreachable!("only the two declared policies exist"),
                },
            }
            assert_eq!(
                selection.child_sa().is_none(),
                matches!(selection, N3iwfDownlinkSelection::Drop)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

#[test]
fn value_bearing_types_redact_debug_and_errors_stay_static() {
    let intent = session(0x2000_0008);
    let installed = N3iwfInstalledSession::new(intent.clone(), first_generation());
    let update =
        N3iwfSessionFlowUpdate::new(installed.clone(), modified_session(0x2000_0008)).unwrap();
    let recovery = N3iwfSessionRecoveryRequest::new(
        GtpDevice {
            name: String::from("n3"),
            ifindex: LINK,
        },
        PdpDeviceIncarnation::from_bytes([7; 16]).unwrap(),
        installed.clone(),
        PdpRestartRecoveryProof::previous_writer_stopped(),
    );
    let values: [(&dyn std::fmt::Debug, &str); 10] = [
        (&intent, "N3iwfSessionIntent(<redacted>)"),
        (intent.n3(), "N3iwfN3Tunnel(<redacted>)"),
        (&intent.child_sas()[0], "N3iwfChildSa(<redacted>)"),
        (&intent.qos_flows()[0], "N3iwfQosFlow(<redacted>)"),
        (&qfis(&[1, 2]), "N3iwfQfiSet(<redacted>)"),
        (&installed, "N3iwfInstalledSession(<redacted>)"),
        (&first_generation(), "N3iwfSessionGeneration(<redacted>)"),
        (&update, "N3iwfSessionFlowUpdate(<redacted>)"),
        (&recovery, "N3iwfSessionRecoveryRequest(<redacted>)"),
        (
            &selector_by_mark(VOICE_MARK),
            "N3iwfSessionSelector(<redacted>)",
        ),
    ];
    for (value, expected) in values {
        assert_eq!(format!("{value:?}"), expected);
    }
    let selection = intent.downlink_selection(qfi(5));
    assert_eq!(format!("{selection:?}"), "Associated(<redacted>)");
    let readback = N3iwfSessionReadback::Present(installed);
    assert!(!format!("{readback:?}").contains("192"));

    for error in [
        N3iwfSessionModelError::InvalidInnerAddress,
        N3iwfSessionModelError::AliasedAddress,
        N3iwfSessionModelError::QfiAssociatedTwice,
    ] {
        let text = error.to_string();
        assert!(
            !text.chars().any(|c| c.is_ascii_digit() && c != '3'),
            "{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// Backend defaults: exact unsupported results, forwarding stays Missing
// ---------------------------------------------------------------------------

async fn assert_lifecycle_refused(backend: &dyn GtpuDataplaneBackend) {
    let intent = session(0x2000_0009);
    let current = N3iwfInstalledSession::new(intent.clone(), first_generation());
    assert_eq!(
        backend.n3iwf_session_lifecycle_capabilities(),
        N3iwfSessionLifecycleCapabilities::unsupported()
    );
    assert!(matches!(
        backend
            .read_n3iwf_session(N3iwfSessionSelector::from_intent(&intent))
            .await,
        Err(GtpuError::UnsupportedFeature {
            feature: "n3iwf_session_readback"
        })
    ));
    assert!(matches!(
        backend
            .install_n3iwf_session_classified(intent.clone())
            .await,
        Err(GtpuError::UnsupportedFeature {
            feature: "n3iwf_session_classified_install"
        })
    ));
    let update =
        N3iwfSessionFlowUpdate::new(current.clone(), modified_session(0x2000_0009)).unwrap();
    assert!(matches!(
        backend.reconcile_n3iwf_session_flows(update).await,
        Err(GtpuError::UnsupportedFeature {
            feature: "n3iwf_session_flow_reconcile"
        })
    ));
    assert!(matches!(
        backend.remove_n3iwf_session_exact(current.clone()).await,
        Err(GtpuError::UnsupportedFeature {
            feature: "n3iwf_session_exact_removal"
        })
    ));
    assert_recovery_refused(backend, current).await;
}

async fn assert_recovery_refused(
    backend: &dyn GtpuDataplaneBackend,
    current: N3iwfInstalledSession,
) {
    let request = N3iwfSessionRecoveryRequest::new(
        GtpDevice {
            name: String::from("n3"),
            ifindex: LINK,
        },
        PdpDeviceIncarnation::from_bytes([7; 16]).unwrap(),
        current,
        PdpRestartRecoveryProof::previous_writer_stopped(),
    );
    assert!(matches!(
        backend.recover_n3iwf_session_exact(request).await,
        Err(GtpuError::UnsupportedFeature {
            feature: "n3iwf_session_restart_recovery"
        })
    ));
}

#[tokio::test]
async fn real_and_unsupported_backends_refuse_the_lifecycle_exactly() {
    let backends: Vec<Box<dyn GtpuDataplaneBackend>> = vec![
        Box::new(LinuxGtpuDataplaneBackend::new()),
        #[cfg(target_os = "linux")]
        Box::new(EbpfGtpuDataplaneBackend::new()),
        Box::new(UnsupportedGtpuDataplaneBackend::new()),
    ];
    for backend in backends {
        assert_lifecycle_refused(backend.as_ref()).await;
    }
}

#[tokio::test]
async fn every_adapter_keeps_the_n3iwf_forwarding_role_missing() {
    let backends: Vec<Box<dyn GtpuDataplaneBackend>> = vec![
        Box::new(MockGtpuDataplaneBackend::new()),
        Box::new(LinuxGtpuDataplaneBackend::new()),
        #[cfg(target_os = "linux")]
        Box::new(EbpfGtpuDataplaneBackend::new()),
        Box::new(UnsupportedGtpuDataplaneBackend::new()),
        Box::new(ExternalBackend),
    ];
    for backend in backends {
        assert_eq!(
            backend.n3_forwarding_capability(N3ForwardingRole::N3iwf),
            GtpuCapability::Missing
        );
    }
}

/// A third-party implementation that predates RFC 021 and overrides only the
/// required methods.
#[derive(Debug)]
struct ExternalBackend;

#[async_trait]
impl GtpuDataplaneBackend for ExternalBackend {
    async fn create_device(
        &self,
        _request: CreateGtpDeviceRequest,
    ) -> Result<GtpDevice, GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn resolve_device(&self, _name: &str) -> Result<GtpDevice, GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn remove_device(&self, _device: &GtpDevice) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn install_pdp_context(&self, _request: GtpPdpContext) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn remove_pdp_context(&self, _request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn probe(&self) -> Result<GtpuProbe, GtpuError> {
        Ok(GtpuProbe::unsupported())
    }
}

#[tokio::test]
async fn an_external_implementation_inherits_the_exact_unsupported_lifecycle() {
    assert_lifecycle_refused(&ExternalBackend).await;
}

// ---------------------------------------------------------------------------
// Mock state lifecycle parity
// ---------------------------------------------------------------------------

async fn read(
    backend: &MockGtpuDataplaneBackend,
    selector: N3iwfSessionSelector,
) -> N3iwfSessionReadback {
    backend.read_n3iwf_session(selector).await.unwrap()
}

#[tokio::test]
async fn mock_reports_the_state_lifecycle_but_not_recovery_or_live_writer() {
    let backend = MockGtpuDataplaneBackend::new();
    assert_eq!(
        backend.n3iwf_session_lifecycle_capabilities(),
        N3iwfSessionLifecycleCapabilities {
            readback: GtpuCapability::Available,
            classified_install: GtpuCapability::Available,
            flow_reconcile: GtpuCapability::Available,
            exact_removal: GtpuCapability::Available,
            restart_recovery: GtpuCapability::Missing,
            live_writer_removal: GtpuCapability::Missing,
        }
    );
    assert_recovery_refused(
        &backend,
        N3iwfInstalledSession::new(session(0x2000_000a), first_generation()),
    )
    .await;
}

#[tokio::test]
async fn mock_install_and_readback_are_exact_and_idempotent() {
    let backend = MockGtpuDataplaneBackend::new();
    let intent = session(0x2000_0010);
    let selector = N3iwfSessionSelector::from_intent(&intent);
    assert_eq!(
        read(&backend, selector).await,
        N3iwfSessionReadback::Absent
    );

    assert_eq!(
        backend
            .install_n3iwf_session_classified(intent.clone())
            .await
            .unwrap(),
        N3iwfSessionInstallOutcome::Installed(first_generation())
    );
    let expected = N3iwfSessionReadback::Present(N3iwfInstalledSession::new(
        intent.clone(),
        first_generation(),
    ));
    assert_eq!(read(&backend, selector).await, expected);
    assert_eq!(
        read(&backend, selector_by_mark(DEFAULT_MARK)).await,
        expected
    );
    assert_eq!(read(&backend, selector_by_mark(VOICE_MARK)).await, expected);
    assert_eq!(
        read(&backend, selector_by_mark(VIDEO_MARK)).await,
        N3iwfSessionReadback::Absent
    );
    // Another link never sees this session.
    assert_eq!(
        read(
            &backend,
            N3iwfSessionSelector::child_sa(LINK + 1, mark(VOICE_MARK)).unwrap()
        )
        .await,
        N3iwfSessionReadback::Absent
    );

    assert_eq!(
        backend
            .install_n3iwf_session_classified(intent.clone())
            .await
            .unwrap(),
        N3iwfSessionInstallOutcome::ExactAlreadyPresent(first_generation())
    );
    let log = format!("{:?}", backend.n3iwf_session_operations());
    assert!(!log.contains("192") && !log.contains("10.45"), "{log}");
    assert_eq!(backend.n3iwf_session_operations().len(), 8);
}

#[tokio::test]
async fn mock_install_classifies_occupancy_without_mutation() {
    let backend = MockGtpuDataplaneBackend::new();
    let first = session(0x2000_0011);
    backend
        .install_n3iwf_session_classified(first.clone())
        .await
        .unwrap();

    // The same local TEID with a different table.
    let changed = modified_session(0x2000_0011);
    let outcome = backend
        .install_n3iwf_session_classified(changed)
        .await
        .unwrap();
    let N3iwfSessionInstallOutcome::Conflict(conflict) = outcome else {
        panic!("expected a local TEID conflict, got {outcome:?}");
    };
    assert_eq!(conflict.occupancy(), N3iwfSessionOccupancy::LocalTeid);
    assert_eq!(
        conflict.mismatches(),
        [
            N3iwfSessionMismatchField::QosFlows,
            N3iwfSessionMismatchField::ChildSas,
            N3iwfSessionMismatchField::DownlinkUnknownQfi,
        ]
    );

    // A different session that reuses the voice Child SA mark.
    let intruder = N3iwfSessionIntent::new(
        tunnel(0x2000_0012),
        flows(&[1]),
        vec![child_sa(VOICE_MARK, &[1])],
        mark(VOICE_MARK),
        N3iwfDownlinkUnknownQfi::Drop,
    )
    .unwrap();
    let outcome = backend
        .install_n3iwf_session_classified(intruder.clone())
        .await
        .unwrap();
    let N3iwfSessionInstallOutcome::Conflict(conflict) = outcome else {
        panic!("expected a Child SA mark conflict, got {outcome:?}");
    };
    assert_eq!(conflict.occupancy(), N3iwfSessionOccupancy::ChildSaMark);
    assert!(conflict
        .mismatches()
        .contains(&N3iwfSessionMismatchField::LocalDownlink));
    assert_eq!(
        read(&backend, N3iwfSessionSelector::from_intent(&intruder)).await,
        N3iwfSessionReadback::Absent
    );

    // An occupied TEID and a mark owned by a third session.
    let third = N3iwfSessionIntent::new(
        tunnel(0x2000_0013),
        flows(&[1]),
        vec![child_sa(VIDEO_MARK, &[1])],
        mark(VIDEO_MARK),
        N3iwfDownlinkUnknownQfi::Drop,
    )
    .unwrap();
    backend
        .install_n3iwf_session_classified(third)
        .await
        .unwrap();
    let both = N3iwfSessionIntent::new(
        tunnel(0x2000_0011),
        flows(&[1]),
        vec![child_sa(VIDEO_MARK, &[1])],
        mark(VIDEO_MARK),
        N3iwfDownlinkUnknownQfi::Drop,
    )
    .unwrap();
    let outcome = backend
        .install_n3iwf_session_classified(both)
        .await
        .unwrap();
    let N3iwfSessionInstallOutcome::Conflict(conflict) = outcome else {
        panic!("expected a two-selector conflict, got {outcome:?}");
    };
    assert_eq!(conflict.occupancy(), N3iwfSessionOccupancy::Both);

    // Nothing changed.
    assert_eq!(
        read(&backend, N3iwfSessionSelector::from_intent(&first)).await,
        N3iwfSessionReadback::Present(N3iwfInstalledSession::new(first, first_generation()))
    );
}

#[tokio::test]
async fn mock_flow_swap_is_atomic_and_fences_stale_writers() {
    let backend = MockGtpuDataplaneBackend::new();
    let original = session(0x2000_0020);
    backend
        .install_n3iwf_session_classified(original.clone())
        .await
        .unwrap();
    let current = N3iwfInstalledSession::new(original.clone(), first_generation());
    let desired = modified_session(0x2000_0020);
    let second = first_generation().next().unwrap();

    let update = N3iwfSessionFlowUpdate::new(current.clone(), desired.clone()).unwrap();
    assert_eq!(
        backend
            .reconcile_n3iwf_session_flows(update.clone())
            .await
            .unwrap(),
        N3iwfSessionReconcileOutcome::Reconciled(second)
    );
    let present =
        N3iwfSessionReadback::Present(N3iwfInstalledSession::new(desired.clone(), second));
    assert_eq!(
        read(&backend, N3iwfSessionSelector::from_intent(&desired)).await,
        present
    );
    assert_eq!(read(&backend, selector_by_mark(VIDEO_MARK)).await, present);
    assert_eq!(
        read(&backend, selector_by_mark(DEFAULT_MARK)).await,
        present
    );
    assert_eq!(
        read(&backend, selector_by_mark(VOICE_MARK)).await,
        N3iwfSessionReadback::Absent
    );

    // A lost acknowledgement: the same update reports the desired state.
    assert_eq!(
        backend.reconcile_n3iwf_session_flows(update).await.unwrap(),
        N3iwfSessionReconcileOutcome::ExactAlreadyPresent(second)
    );

    // A stale writer still holding generation one cannot swap back.
    let stale = N3iwfSessionFlowUpdate::new(current, session(0x2000_0020)).unwrap();
    let outcome = backend.reconcile_n3iwf_session_flows(stale).await.unwrap();
    let N3iwfSessionReconcileOutcome::Conflict(conflict) = outcome else {
        panic!("expected a stale-writer conflict, got {outcome:?}");
    };
    assert_eq!(conflict.occupancy(), N3iwfSessionOccupancy::LocalTeid);
    assert!(conflict
        .mismatches()
        .contains(&N3iwfSessionMismatchField::Generation));
    assert_eq!(read(&backend, selector_by_mark(VIDEO_MARK)).await, present);

    // The current writer can swap back (a UE may reject a modification,
    // TS 24.502 section 7.6.3).
    let back = N3iwfSessionFlowUpdate::new(
        N3iwfInstalledSession::new(desired, second),
        original.clone(),
    )
    .unwrap();
    let third = second.next().unwrap();
    assert_eq!(
        backend.reconcile_n3iwf_session_flows(back).await.unwrap(),
        N3iwfSessionReconcileOutcome::Reconciled(third)
    );
    assert_eq!(
        read(&backend, selector_by_mark(VOICE_MARK)).await,
        N3iwfSessionReadback::Present(N3iwfInstalledSession::new(original, third))
    );
    assert_eq!(
        read(&backend, selector_by_mark(VIDEO_MARK)).await,
        N3iwfSessionReadback::Absent
    );
}

#[tokio::test]
async fn mock_flow_swap_refuses_absent_sessions_and_foreign_marks() {
    let backend = MockGtpuDataplaneBackend::new();
    let absent = N3iwfSessionFlowUpdate::new(
        N3iwfInstalledSession::new(session(0x2000_0030), first_generation()),
        modified_session(0x2000_0030),
    )
    .unwrap();
    assert_eq!(
        backend.reconcile_n3iwf_session_flows(absent).await.unwrap(),
        N3iwfSessionReconcileOutcome::Absent
    );

    let original = session(0x2000_0031);
    backend
        .install_n3iwf_session_classified(original.clone())
        .await
        .unwrap();
    let owner = N3iwfSessionIntent::new(
        tunnel(0x2000_0032),
        flows(&[1]),
        vec![child_sa(VIDEO_MARK, &[1])],
        mark(VIDEO_MARK),
        N3iwfDownlinkUnknownQfi::Drop,
    )
    .unwrap();
    backend
        .install_n3iwf_session_classified(owner.clone())
        .await
        .unwrap();
    let update = N3iwfSessionFlowUpdate::new(
        N3iwfInstalledSession::new(original.clone(), first_generation()),
        modified_session(0x2000_0031),
    )
    .unwrap();
    let outcome = backend.reconcile_n3iwf_session_flows(update).await.unwrap();
    let N3iwfSessionReconcileOutcome::Conflict(conflict) = outcome else {
        panic!("expected a foreign-mark conflict, got {outcome:?}");
    };
    assert_eq!(conflict.occupancy(), N3iwfSessionOccupancy::ChildSaMark);
    assert_eq!(
        read(&backend, N3iwfSessionSelector::from_intent(&original)).await,
        N3iwfSessionReadback::Present(N3iwfInstalledSession::new(original, first_generation()))
    );
    assert_eq!(
        read(&backend, selector_by_mark(VIDEO_MARK)).await,
        N3iwfSessionReadback::Present(N3iwfInstalledSession::new(owner, first_generation()))
    );
}

#[tokio::test]
async fn mock_exact_removal_fences_generations_and_releases_marks() {
    let backend = MockGtpuDataplaneBackend::new();
    let intent = session(0x2000_0040);
    backend
        .install_n3iwf_session_classified(intent.clone())
        .await
        .unwrap();
    let stale = N3iwfInstalledSession::new(intent.clone(), first_generation().next().unwrap());
    let outcome = backend.remove_n3iwf_session_exact(stale).await.unwrap();
    let N3iwfSessionRemovalOutcome::Conflict(conflict) = outcome else {
        panic!("expected a generation conflict, got {outcome:?}");
    };
    assert_eq!(
        conflict.mismatches(),
        [N3iwfSessionMismatchField::Generation]
    );

    let exact = N3iwfInstalledSession::new(intent.clone(), first_generation());
    assert_eq!(
        backend
            .remove_n3iwf_session_exact(exact.clone())
            .await
            .unwrap(),
        N3iwfSessionRemovalOutcome::Removed
    );
    assert_eq!(
        read(&backend, N3iwfSessionSelector::from_intent(&intent)).await,
        N3iwfSessionReadback::Absent
    );
    assert_eq!(
        read(&backend, selector_by_mark(VOICE_MARK)).await,
        N3iwfSessionReadback::Absent
    );
    assert_eq!(
        backend.remove_n3iwf_session_exact(exact).await.unwrap(),
        N3iwfSessionRemovalOutcome::AlreadyAbsent
    );

    // Released marks and TEIDs can be used again once exact removal returned.
    let reuse = N3iwfSessionIntent::new(
        tunnel(0x2000_0041),
        flows(&[1]),
        vec![child_sa(VOICE_MARK, &[1])],
        mark(VOICE_MARK),
        N3iwfDownlinkUnknownQfi::Drop,
    )
    .unwrap();
    assert_eq!(
        backend
            .install_n3iwf_session_classified(reuse)
            .await
            .unwrap(),
        N3iwfSessionInstallOutcome::Installed(first_generation())
    );
}

#[tokio::test]
async fn mock_faults_and_failures_fail_closed_without_mutation() {
    let backend = MockGtpuDataplaneBackend::new();
    let intent = session(0x2000_0050);
    backend
        .install_n3iwf_session_classified(intent.clone())
        .await
        .unwrap();
    let current = N3iwfInstalledSession::new(intent.clone(), first_generation());
    let update =
        N3iwfSessionFlowUpdate::new(current.clone(), modified_session(0x2000_0050)).unwrap();

    for (fault, reason) in [
        (
            MockPdpContextFault::ChangingReadback,
            PdpContextIndeterminateReason::StateChanged,
        ),
        (
            MockPdpContextFault::CorruptState,
            PdpContextIndeterminateReason::IncompleteState,
        ),
        (
            MockPdpContextFault::TransitionalState,
            PdpContextIndeterminateReason::IncompleteState,
        ),
    ] {
        backend.set_pdp_context_fault(Some(fault));
        assert!(matches!(
            backend
                .read_n3iwf_session(N3iwfSessionSelector::from_intent(&intent))
                .await,
            Err(GtpuError::StateIndeterminate { .. })
        ));
        assert_eq!(
            backend
                .install_n3iwf_session_classified(session(0x2000_0051))
                .await
                .unwrap(),
            N3iwfSessionInstallOutcome::Indeterminate(reason)
        );
        assert_eq!(
            backend
                .reconcile_n3iwf_session_flows(update.clone())
                .await
                .unwrap(),
            N3iwfSessionReconcileOutcome::Indeterminate(reason)
        );
        assert_eq!(
            backend
                .remove_n3iwf_session_exact(current.clone())
                .await
                .unwrap(),
            N3iwfSessionRemovalOutcome::Indeterminate(reason)
        );
    }
    backend.set_pdp_context_fault(None);

    backend.set_failure(GtpuError::UnsupportedPlatform);
    assert!(matches!(
        backend
            .install_n3iwf_session_classified(session(0x2000_0052))
            .await,
        Err(GtpuError::UnsupportedPlatform)
    ));
    assert!(matches!(
        backend.remove_n3iwf_session_exact(current.clone()).await,
        Err(GtpuError::UnsupportedPlatform)
    ));
    backend.clear_failure();

    assert_eq!(
        read(&backend, N3iwfSessionSelector::from_intent(&intent)).await,
        N3iwfSessionReadback::Present(current)
    );
    assert_eq!(
        read(
            &backend,
            N3iwfSessionSelector::from_intent(&session(0x2000_0051))
        )
        .await,
        N3iwfSessionReadback::Absent
    );
}

#[tokio::test]
async fn mock_device_removal_drops_the_devices_sessions() {
    let backend = MockGtpuDataplaneBackend::new();
    let device = backend
        .create_device(CreateGtpDeviceRequest::new("n3"))
        .await
        .unwrap();
    let intent = N3iwfSessionIntent::new(
        N3iwfN3Tunnel::new(
            device.ifindex,
            ReceivedN3UplinkTnl::new(v4(192, 0, 2, 1), teid(0x1000_0001)).unwrap(),
            LocalN3DownlinkTnl::new(v4(192, 0, 2, 2), teid(0x2000_0060)).unwrap(),
            GtpuSourcePortPolicy::Any,
            GtpuUplinkSourcePortPolicy::LegacyServicePort,
        )
        .unwrap(),
        flows(&[1]),
        vec![child_sa(DEFAULT_MARK, &[1])],
        mark(DEFAULT_MARK),
        N3iwfDownlinkUnknownQfi::Drop,
    )
    .unwrap();
    backend
        .install_n3iwf_session_classified(intent.clone())
        .await
        .unwrap();
    backend.remove_device(&device).await.unwrap();
    assert_eq!(
        read(&backend, N3iwfSessionSelector::from_intent(&intent)).await,
        N3iwfSessionReadback::Absent
    );
    assert_eq!(
        read(
            &backend,
            N3iwfSessionSelector::child_sa(device.ifindex, mark(DEFAULT_MARK)).unwrap()
        )
        .await,
        N3iwfSessionReadback::Absent
    );
}

#[test]
fn conflict_evidence_requires_a_named_difference() {
    let intent = session(0x2000_0070);
    assert!(
        N3iwfSessionConflict::between(N3iwfSessionOccupancy::LocalTeid, &intent, &intent).is_none()
    );
    assert!(N3iwfSessionConflict::from_mismatch_fields(
        N3iwfSessionOccupancy::LocalTeid,
        std::iter::empty()
    )
    .is_none());
    let other = N3iwfSessionConflict::other_role();
    assert_eq!(other.occupancy(), N3iwfSessionOccupancy::OtherRole);
    assert!(other.mismatches().is_empty());
    let fields = N3iwfSessionConflict::from_mismatch_fields(
        N3iwfSessionOccupancy::ChildSaMark,
        [
            N3iwfSessionMismatchField::ChildSas,
            N3iwfSessionMismatchField::LinkIfindex,
            N3iwfSessionMismatchField::ChildSas,
        ],
    )
    .unwrap();
    assert_eq!(
        fields.mismatches(),
        [
            N3iwfSessionMismatchField::LinkIfindex,
            N3iwfSessionMismatchField::ChildSas
        ]
    );
}
