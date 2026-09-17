//! Selection intentions are data, not kernel publication or packet authority.

use opc_ipsec_xfrm::child_sa::{
    ChildSaClass, ChildSaClassBinding, ChildSaId, ChildSaIncarnation, ChildSaOutboundSelection,
    ChildSaOutboundUse, ChildSaPair, ChildSaSelectionError as Error, ChildSaSelectionLimits,
    ChildSaSelectionPlan, ChildSaTrafficIdentity,
};
use opc_ipsec_xfrm::{IpAddress, XfrmId, XfrmLookupMark};

fn child(value: u64) -> ChildSaId {
    ChildSaId::new(value).unwrap()
}

fn class(value: u64) -> ChildSaClass {
    ChildSaClass::new(value).unwrap()
}

fn incarnation(value: u64) -> ChildSaIncarnation {
    ChildSaIncarnation::new(value).unwrap()
}

fn identity(spi: u32, inbound: bool) -> ChildSaTrafficIdentity {
    ChildSaTrafficIdentity::new(
        XfrmId {
            destination: IpAddress::Ipv4([192, 0, 2, if inbound { 1 } else { 2 }]),
            spi,
            protocol: 50,
        },
        None,
        None,
    )
    .unwrap()
}

fn pair(id: u64, generation: u64, spi: u32, selected: bool) -> ChildSaPair {
    ChildSaPair::new(
        child(id),
        incarnation(generation),
        identity(spi, true),
        identity(spi + 1, false),
        if selected {
            ChildSaOutboundUse::Selected
        } else {
            ChildSaOutboundUse::ReceiveOnly
        },
    )
}

fn limits() -> ChildSaSelectionLimits {
    ChildSaSelectionLimits {
        max_pairs: 16,
        max_classes: 32,
    }
}

fn binding(flow: u64, id: u64) -> ChildSaClassBinding {
    ChildSaClassBinding::new(class(flow), child(id))
}

fn plan(pairs: Vec<ChildSaPair>) -> Result<ChildSaSelectionPlan, Error> {
    ChildSaSelectionPlan::new(pairs, vec![binding(10, 1)], child(1), limits())
}

#[test]
fn signalling_and_two_user_plane_children_have_explicit_exact_selection() {
    // The product has classified NAS and two sets of user traffic. Their SA
    // selectors may all match every packet: selection must use these intents.
    let plan = ChildSaSelectionPlan::new(
        vec![
            pair(1, 1, 0x1001, true),
            pair(2, 1, 0x2001, true),
            pair(3, 1, 0x3001, true),
        ],
        vec![
            binding(10, 1),
            binding(20, 2),
            binding(21, 2),
            binding(30, 3),
            binding(31, 3),
        ],
        child(3),
        limits(),
    )
    .unwrap();
    for (flow, expected_child, expected_spi) in [
        (10, 1, 0x1002),
        (20, 2, 0x2002),
        (21, 2, 0x2002),
        (30, 3, 0x3002),
        (31, 3, 0x3002),
    ] {
        let selected = plan
            .select_outbound(ChildSaOutboundSelection::Class(class(flow)))
            .unwrap();
        assert_eq!(selected.child(), child(expected_child));
        assert_eq!(selected.outbound().id().spi, expected_spi);
    }
    let default = plan
        .select_outbound(ChildSaOutboundSelection::Default)
        .unwrap();
    assert_eq!(default.child(), child(3));
    assert_eq!(default.outbound().id().spi, 0x3002);
    assert_eq!(
        plan.select_outbound(ChildSaOutboundSelection::Class(class(99)))
            .unwrap_err(),
        Error::UnknownClass
    );
    assert_eq!(
        plan.match_inbound_intent(identity(0x9001, true), incarnation(1))
            .unwrap_err(),
        Error::UnknownInbound
    );
    assert_eq!(
        plan.match_inbound_intent(identity(0x2001, true), incarnation(1))
            .unwrap()
            .child(),
        child(2)
    );
    assert_eq!(
        plan.match_inbound_intent(identity(0x2002, false), incarnation(1))
            .unwrap_err(),
        Error::UnknownInbound
    );
}

#[test]
fn rekey_overlap_keeps_both_inbound_pairs_but_only_the_selected_outbound() {
    let old = pair(1, 1, 0x1001, false);
    let new = pair(1, 2, 0x2001, true);
    for pairs in [
        vec![old.clone(), new.clone()],
        vec![new.clone(), old.clone()],
    ] {
        let plan = plan(pairs).unwrap();
        let selected = plan
            .select_outbound(ChildSaOutboundSelection::Class(class(10)))
            .unwrap();
        assert_eq!(selected.incarnation(), incarnation(2));
        assert_eq!(selected.outbound().id().spi, 0x2002);
        assert_eq!(
            plan.match_inbound_intent(old.inbound(), incarnation(1))
                .unwrap()
                .incarnation(),
            incarnation(1)
        );
        assert_eq!(
            plan.match_inbound_intent(new.inbound(), incarnation(2))
                .unwrap()
                .incarnation(),
            incarnation(2)
        );
        assert_eq!(
            plan.match_inbound_intent(new.inbound(), incarnation(1))
                .unwrap_err(),
            Error::StaleIncarnation
        );
    }
    let retired = plan(vec![new]).unwrap();
    assert_eq!(
        retired
            .match_inbound_intent(old.inbound(), incarnation(1))
            .unwrap_err(),
        Error::UnknownInbound
    );
    let reinstalled = plan(vec![pair(1, 3, 0x1001, true)]).unwrap();
    assert_eq!(
        reinstalled
            .match_inbound_intent(old.inbound(), incarnation(1))
            .unwrap_err(),
        Error::StaleIncarnation
    );
}

#[test]
fn outbound_choice_never_depends_on_incarnation_sort_order() {
    let plan = plan(vec![pair(1, 1, 0x1001, true), pair(1, 2, 0x2001, false)]).unwrap();
    assert_eq!(
        plan.select_outbound(ChildSaOutboundSelection::Default)
            .unwrap()
            .incarnation(),
        incarnation(1)
    );
}

#[test]
fn every_child_needs_one_selected_outbound_and_unique_incarnations() {
    assert_eq!(
        plan(vec![pair(1, 1, 0x1001, false)]).unwrap_err(),
        Error::MissingOutbound
    );
    assert_eq!(
        plan(vec![pair(1, 1, 0x1001, true), pair(1, 2, 0x2001, true)]).unwrap_err(),
        Error::MultipleOutbound
    );
    assert_eq!(
        plan(vec![pair(1, 1, 0x1001, true), pair(1, 1, 0x2001, false)]).unwrap_err(),
        Error::DuplicateIncarnation
    );
    assert_eq!(
        plan(vec![pair(1, 1, 0x1001, true), pair(2, 1, 0x2001, false)]).unwrap_err(),
        Error::MissingOutbound
    );
}

#[test]
fn duplicate_classes_and_dangling_references_are_refused() {
    assert_eq!(
        ChildSaSelectionPlan::new(
            vec![pair(1, 1, 0x1001, true)],
            vec![binding(10, 1), binding(10, 1)],
            child(1),
            limits()
        )
        .unwrap_err(),
        Error::DuplicateClass
    );
    assert_eq!(
        ChildSaSelectionPlan::new(
            vec![pair(1, 1, 0x1001, true)],
            vec![binding(10, 2)],
            child(1),
            limits()
        )
        .unwrap_err(),
        Error::UnknownChild
    );
    assert_eq!(
        ChildSaSelectionPlan::new(vec![pair(1, 1, 0x1001, true)], vec![], child(2), limits())
            .unwrap_err(),
        Error::UnknownChild
    );
    let default_only = ChildSaSelectionPlan::new(
        vec![pair(1, 1, 0x1001, true)],
        vec![],
        child(1),
        ChildSaSelectionLimits {
            max_pairs: 1,
            max_classes: 0,
        },
    )
    .unwrap();
    assert_eq!(
        default_only
            .select_outbound(ChildSaOutboundSelection::Default)
            .unwrap()
            .child(),
        child(1)
    );
}

#[test]
fn caller_limits_are_inclusive_and_empty_rosters_are_refused() {
    assert_eq!(plan(vec![]).unwrap_err(), Error::EmptyRoster);
    assert_eq!(
        ChildSaSelectionPlan::new(
            vec![pair(1, 1, 0x1001, true)],
            vec![],
            child(1),
            ChildSaSelectionLimits {
                max_pairs: 0,
                max_classes: 0
            }
        )
        .unwrap_err(),
        Error::InvalidLimits
    );
    let exact = ChildSaSelectionLimits {
        max_pairs: 1,
        max_classes: 1,
    };
    ChildSaSelectionPlan::new(
        vec![pair(1, 1, 0x1001, true)],
        vec![binding(10, 1)],
        child(1),
        exact,
    )
    .unwrap();
    assert_eq!(
        ChildSaSelectionPlan::new(
            vec![pair(1, 1, 0x1001, true), pair(2, 1, 0x2001, true)],
            vec![],
            child(1),
            exact
        )
        .unwrap_err(),
        Error::CapacityExceeded
    );
    assert_eq!(
        ChildSaSelectionPlan::new(
            vec![pair(1, 1, 0x1001, true)],
            vec![binding(10, 1), binding(11, 1)],
            child(1),
            exact
        )
        .unwrap_err(),
        Error::CapacityExceeded
    );
}

#[test]
fn identity_validation_refuses_wildcards_non_esp_and_partial_marks() {
    let valid = identity(0x1001, true).id();
    for id in [
        XfrmId { spi: 0, ..valid },
        XfrmId {
            protocol: 0,
            ..valid
        },
        XfrmId {
            protocol: 51,
            ..valid
        },
        XfrmId {
            destination: IpAddress::Ipv4([0; 4]),
            ..valid
        },
        XfrmId {
            destination: IpAddress::Ipv6([0; 16]),
            ..valid
        },
    ] {
        assert_eq!(
            ChildSaTrafficIdentity::new(id, None, None).unwrap_err(),
            Error::InvalidSaIdentity
        );
    }
    assert_eq!(
        ChildSaTrafficIdentity::new(valid, None, Some(0)).unwrap_err(),
        Error::InvalidSaIdentity
    );
    assert_eq!(
        ChildSaTrafficIdentity::new(valid, Some(XfrmLookupMark::new(0x10, 0xf0).unwrap()), None)
            .unwrap_err(),
        Error::InvalidSaIdentity
    );
    for mark in [
        None,
        Some(XfrmLookupMark::full(0)),
        Some(XfrmLookupMark::full(u32::MAX)),
    ] {
        for if_id in [None, Some(1), Some(u32::MAX)] {
            let admitted = ChildSaTrafficIdentity::new(valid, mark, if_id).unwrap();
            assert_eq!(admitted.id(), valid);
            assert_eq!(admitted.query().mark, mark);
            assert_eq!(admitted.if_id(), if_id);
        }
    }
}

#[test]
fn linux_lookup_collisions_include_unmarked_domains_and_ignore_interface_id() {
    let first = pair(1, 1, 0x1001, true);
    let first_in = first.inbound();
    for mark in [
        None,
        Some(XfrmLookupMark::full(0)),
        Some(XfrmLookupMark::full(42)),
    ] {
        for if_id in [None, Some(41)] {
            let colliding = ChildSaTrafficIdentity::new(first_in.id(), mark, if_id).unwrap();
            let second = ChildSaPair::new(
                child(2),
                incarnation(1),
                colliding,
                identity(0x2002, false),
                ChildSaOutboundUse::Selected,
            );
            assert_eq!(
                plan(vec![first.clone(), second.clone()]).unwrap_err(),
                Error::AmbiguousSaIdentity
            );
            assert_eq!(
                plan(vec![second, first.clone()]).unwrap_err(),
                Error::AmbiguousSaIdentity
            );
        }
    }
    // A collision between opposite directions also names the same kernel SA.
    let second = ChildSaPair::new(
        child(2),
        incarnation(1),
        identity(0x2001, true),
        first_in,
        ChildSaOutboundUse::Selected,
    );
    assert_eq!(
        plan(vec![first, second]).unwrap_err(),
        Error::AmbiguousSaIdentity
    );
    let same = ChildSaPair::new(
        child(1),
        incarnation(1),
        first_in,
        first_in,
        ChildSaOutboundUse::Selected,
    );
    assert_eq!(plan(vec![same]).unwrap_err(), Error::AmbiguousSaIdentity);
}

#[test]
fn distinct_full_marks_disambiguate_but_inbound_matching_remains_exact() {
    let raw = identity(0x1001, true).id();
    let a = ChildSaTrafficIdentity::new(raw, Some(XfrmLookupMark::full(11)), Some(31)).unwrap();
    let b = ChildSaTrafficIdentity::new(raw, Some(XfrmLookupMark::full(12)), Some(32)).unwrap();
    let plan = plan(vec![
        ChildSaPair::new(
            child(1),
            incarnation(1),
            a,
            identity(0x1002, false),
            ChildSaOutboundUse::Selected,
        ),
        ChildSaPair::new(
            child(2),
            incarnation(1),
            b,
            identity(0x2002, false),
            ChildSaOutboundUse::Selected,
        ),
    ])
    .unwrap();
    assert_eq!(
        plan.match_inbound_intent(a, incarnation(1))
            .unwrap()
            .child(),
        child(1)
    );
    assert_eq!(
        plan.match_inbound_intent(b, incarnation(1))
            .unwrap()
            .child(),
        child(2)
    );
    for wrong in [
        ChildSaTrafficIdentity::new(raw, None, Some(31)).unwrap(),
        ChildSaTrafficIdentity::new(raw, Some(XfrmLookupMark::full(11)), None).unwrap(),
        ChildSaTrafficIdentity::new(raw, Some(XfrmLookupMark::full(11)), Some(32)).unwrap(),
        ChildSaTrafficIdentity::new(
            XfrmId {
                destination: IpAddress::Ipv4([192, 0, 2, 9]),
                ..raw
            },
            Some(XfrmLookupMark::full(11)),
            Some(31),
        )
        .unwrap(),
    ] {
        assert_eq!(
            plan.match_inbound_intent(wrong, incarnation(1))
                .unwrap_err(),
            Error::UnknownInbound
        );
    }
}

#[test]
fn tokens_refuse_zero_and_incarnations_never_wrap() {
    assert!(ChildSaId::new(0).is_none());
    assert!(ChildSaClass::new(0).is_none());
    assert!(ChildSaIncarnation::new(0).is_none());
    assert_eq!(child(u64::MAX).get(), u64::MAX);
    assert_eq!(class(u64::MAX).get(), u64::MAX);
    assert_eq!(incarnation(u64::MAX).get(), u64::MAX);
    assert_eq!(incarnation(1).checked_next(), Some(incarnation(2)));
    assert_eq!(
        incarnation(u64::MAX - 1).checked_next(),
        Some(incarnation(u64::MAX))
    );
    assert_eq!(incarnation(u64::MAX).checked_next(), None);
}

#[test]
fn diagnostics_are_value_free_for_every_data_bearing_type() {
    let pair = pair(1, 1, 0x1001, true);
    let plan = plan(vec![pair.clone()]).unwrap();
    let cases: Vec<(&dyn std::fmt::Debug, &str)> = vec![
        (&pair, "ChildSaPair(<redacted>)"),
        (&plan, "ChildSaSelectionPlan(<redacted>)"),
    ];
    for (value, expected) in cases {
        assert_eq!(format!("{value:?}"), expected);
        assert_eq!(format!("{value:#?}"), expected);
    }
    assert_eq!(format!("{:?}", child(27)), "ChildSaId(<redacted>)");
    assert_eq!(format!("{:?}", class(28)), "ChildSaClass(<redacted>)");
    assert_eq!(
        format!("{:?}", incarnation(29)),
        "ChildSaIncarnation(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", pair.inbound()),
        "ChildSaTrafficIdentity(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", binding(30, 31)),
        "ChildSaClassBinding(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", ChildSaOutboundSelection::Class(class(32))),
        "ChildSaOutboundSelection(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", limits()),
        "ChildSaSelectionLimits(<redacted>)"
    );
    for error in [
        Error::InvalidLimits,
        Error::EmptyRoster,
        Error::CapacityExceeded,
        Error::InvalidSaIdentity,
        Error::AmbiguousSaIdentity,
        Error::DuplicateIncarnation,
        Error::MissingOutbound,
        Error::MultipleOutbound,
        Error::DuplicateClass,
        Error::UnknownChild,
        Error::UnknownClass,
        Error::UnknownInbound,
        Error::StaleIncarnation,
    ] {
        assert!(!error.to_string().is_empty());
        assert!(error.to_string().len() < 100);
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn independent_lookup_domain_vectors_match_plan_admission() {
    let destinations = [
        IpAddress::Ipv4([192, 0, 2, 1]),
        IpAddress::Ipv4([192, 0, 2, 2]),
        IpAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        IpAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
    ];
    let marks = [
        None,
        Some(XfrmLookupMark::full(0)),
        Some(XfrmLookupMark::full(11)),
        Some(XfrmLookupMark::full(12)),
    ];
    let scopes = [None, Some(17), Some(18)];
    let mut count = 0;
    let mut ambiguous = 0;
    for line in include_str!("child_sa_lookup_cases.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let values: Vec<usize> = line
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 8);
        let a = ChildSaTrafficIdentity::new(
            XfrmId {
                destination: destinations[values[0]],
                protocol: 50,
                spi: 0x1001,
            },
            marks[values[3]],
            scopes[values[5]],
        )
        .unwrap();
        let b = ChildSaTrafficIdentity::new(
            XfrmId {
                destination: destinations[values[1]],
                protocol: 50,
                spi: 0x1001 + u32::try_from(values[2]).unwrap(),
            },
            marks[values[4]],
            scopes[values[6]],
        )
        .unwrap();
        let result = plan(vec![
            ChildSaPair::new(
                child(1),
                incarnation(1),
                a,
                identity(0x8001, false),
                ChildSaOutboundUse::Selected,
            ),
            ChildSaPair::new(
                child(2),
                incarnation(1),
                b,
                identity(0x8002, false),
                ChildSaOutboundUse::Selected,
            ),
        ]);
        if values[7] == 1 {
            assert_eq!(result.unwrap_err(), Error::AmbiguousSaIdentity);
            ambiguous += 1;
        } else {
            assert_eq!(values[7], 0);
            let plan = result.unwrap();
            assert_eq!(
                plan.match_inbound_intent(a, incarnation(1))
                    .unwrap()
                    .child(),
                child(1)
            );
            assert_eq!(
                plan.match_inbound_intent(b, incarnation(1))
                    .unwrap()
                    .child(),
                child(2)
            );
        }
        count += 1;
    }
    assert_eq!(count, 4608);
    assert_eq!(ambiguous, 360);
}

fn fixture_pairs(hex: &str) -> Vec<ChildSaPair> {
    // Decode the fixture inventory's synthetic record, not an IKE/XFRM wire
    // format. Its context booleans are never authentication or live authority.
    let bytes: Vec<u8> = hex
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect();
    let (records, remainder) = bytes.as_chunks::<12>();
    assert!(remainder.is_empty());
    records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            assert_eq!(record[0], 1);
            let generation = u32::from_be_bytes([0, record[1], record[2], record[3]]);
            let inbound = u32::from_be_bytes(record[4..8].try_into().unwrap());
            let outbound = u32::from_be_bytes(record[8..12].try_into().unwrap());
            ChildSaPair::new(
                child(1),
                incarnation(u64::from(generation)),
                identity(inbound, true),
                identity(outbound, false),
                if index + 1 == records.len() {
                    ChildSaOutboundUse::Selected
                } else {
                    ChildSaOutboundUse::ReceiveOnly
                },
            )
        })
        .collect()
}

#[test]
fn reviewed_roster_records_drive_overlap_and_explicit_selection() {
    let cases = [
        (
            include_str!(
                "../../opc-n3iwf-fixtures/fixtures/xfrm-roster/wire/positive-single-pair.hex"
            ),
            1,
            0x0a0b0c0e,
        ),
        (
            include_str!("../../opc-n3iwf-fixtures/fixtures/xfrm-roster/wire/overlap-rekey.hex"),
            2,
            0x0a0b0c10,
        ),
        (
            include_str!("../../opc-n3iwf-fixtures/fixtures/xfrm-roster/wire/rekey-new-pair.hex"),
            3,
            0x0a0b0c12,
        ),
        (
            include_str!(
                "../../opc-n3iwf-fixtures/fixtures/xfrm-roster/wire/ordering-old-then-new.hex"
            ),
            2,
            0x0a0b0c12,
        ),
    ];
    for (hex, expected_generation, expected_spi) in cases {
        let pairs = fixture_pairs(hex);
        for input in [pairs.clone(), pairs.iter().rev().cloned().collect()] {
            let plan = plan(input).unwrap();
            let selected = plan
                .select_outbound(ChildSaOutboundSelection::Default)
                .unwrap();
            assert_eq!(selected.incarnation().get(), expected_generation);
            assert_eq!(selected.outbound().id().spi, expected_spi);
            for pair in &pairs {
                assert_eq!(
                    plan.match_inbound_intent(pair.inbound(), pair.incarnation())
                        .unwrap(),
                    pair
                );
            }
        }
    }
    let duplicate = fixture_pairs(include_str!(
        "../../opc-n3iwf-fixtures/fixtures/xfrm-roster/wire/duplicate-spi.hex"
    ));
    assert_eq!(plan(duplicate).unwrap_err(), Error::AmbiguousSaIdentity);
    let known = plan(fixture_pairs(cases[0].0)).unwrap();
    let unknown = fixture_pairs(include_str!(
        "../../opc-n3iwf-fixtures/fixtures/xfrm-roster/wire/unknown-inbound-spi.hex"
    ));
    assert_eq!(
        known
            .match_inbound_intent(unknown[0].inbound(), unknown[0].incarnation())
            .unwrap_err(),
        Error::UnknownInbound
    );
}
