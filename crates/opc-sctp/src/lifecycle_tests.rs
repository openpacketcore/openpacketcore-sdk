//! Linux UAPI event schedules, independently specified from RFC 6525 section 6
//! and Linux v6.8 include/uapi/linux/sctp.h. These are native-endian notification
//! records, not SCTP wire packets or peer interoperability captures.
use super::*;

fn event(kind: u16, flags: u16, fields: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&(8u32 + fields.len() as u32).to_ne_bytes());
    bytes.extend_from_slice(fields);
    bytes
}

#[test]
fn lifecycle_notifications_are_typed_before_owner_can_admit_them() {
    let association = 11i32.to_ne_bytes();
    let stream_reset = [association.as_slice(), &3u16.to_ne_bytes()].concat();
    let association_reset = [
        association.as_slice(),
        &7u32.to_ne_bytes(),
        &9u32.to_ne_bytes(),
    ]
    .concat();
    let stream_change = [
        association.as_slice(),
        &8u16.to_ne_bytes(),
        &8u16.to_ne_bytes(),
    ]
    .concat();
    let partial_abort = [
        &0u32.to_ne_bytes(),
        association.as_slice(),
        &3u32.to_ne_bytes(),
        &7u32.to_ne_bytes(),
    ]
    .concat();
    for bytes in [
        event(0x800a, 1, &stream_reset),
        event(0x800b, 0, &association_reset),
        event(0x800c, 0, &stream_change),
        event(0x8006, 0, &partial_abort),
    ] {
        let parsed = parse_sctp_event(&bytes);
        assert!(parsed.is_some(), "complete lifecycle event must parse");
        assert!(
            !matches!(parsed, Some(SctpEvent::Unknown { .. })),
            "known lifecycle events need typed admission before generation ownership"
        );
    }
}

#[test]
fn stream_reset_flags_lists_and_bounds_follow_the_independent_event_contract() {
    let expected = [3, u16::MAX, 0, 3];
    let mut fields = 11i32.to_ne_bytes().to_vec();
    for stream in expected {
        fields.extend_from_slice(&stream.to_ne_bytes());
    }
    for flags in 0..=u16::MAX {
        let parsed = parse_sctp_event(&event(0x800a, flags, &fields));
        let accepted = matches!(flags, 1 | 2 | 3 | 5 | 6 | 7 | 9 | 10 | 11);
        assert!(
            parsed.is_some() == accepted,
            "reset flags have a finite qualified set"
        );
        if let Some(SctpEvent::StreamReset {
            streams,
            incoming,
            outgoing,
            status,
            assoc_id,
        }) = parsed
        {
            assert!(
                streams.as_slice() == expected,
                "list order and duplicates are preserved"
            );
            assert!(incoming == (flags % 4 == 1 || flags % 4 == 3));
            assert!(outgoing == (flags % 4 == 2 || flags % 4 == 3));
            assert!(assoc_id == 11);
            assert!(match status {
                SctpReconfigurationStatus::Completed => flags <= 3,
                SctpReconfigurationStatus::Denied => (5..=7).contains(&flags),
                SctpReconfigurationStatus::Failed => (9..=11).contains(&flags),
            });
            assert!(format!("{streams:?}") == "SctpResetStreams { .. }");
        }
    }
    for count in [0, 1, 63, 64, 65] {
        let streams: Vec<_> = (0..count).collect();
        let mut fields = 11i32.to_ne_bytes().to_vec();
        for stream in &streams {
            fields.extend_from_slice(&u16::to_ne_bytes(*stream));
        }
        let parsed = parse_sctp_event(&event(0x800a, 3, &fields));
        assert!(
            parsed.is_some() == (count <= 64),
            "explicit reset list bound"
        );
        assert!(SctpResetStreams::new(&streams).is_some() == (count <= 64));
        if let Some(SctpEvent::StreamReset { streams, .. }) = parsed {
            assert!(streams.as_slice().len() == usize::from(count));
            assert!(streams.includes(u16::MAX) == (count == 0));
        }
    }
    let mut odd = 11i32.to_ne_bytes().to_vec();
    odd.push(0);
    assert!(parse_sctp_event(&event(0x800a, 1, &odd)).is_none());
}

#[test]
fn lifecycle_events_reject_every_prefix_trailing_bytes_and_invalid_flags() {
    for (kind, fields, flags) in [
        (
            0x8006,
            vec![0u32, 11, 3, 7]
                .into_iter()
                .flat_map(u32::to_ne_bytes)
                .collect::<Vec<_>>(),
            0,
        ),
        (0x800a, 11i32.to_ne_bytes().to_vec(), 1),
        (
            0x800b,
            vec![11u32, 7, 9]
                .into_iter()
                .flat_map(u32::to_ne_bytes)
                .collect(),
            0,
        ),
        (
            0x800c,
            [
                11i32.to_ne_bytes().as_slice(),
                &8u16.to_ne_bytes(),
                &8u16.to_ne_bytes(),
            ]
            .concat(),
            0,
        ),
    ] {
        let valid = event(kind, flags, &fields);
        assert!(parse_sctp_event(&valid).is_some());
        for end in 0..valid.len() {
            assert!(
                parse_sctp_event(&valid[..end]).is_none(),
                "incomplete event must reject"
            );
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(
            parse_sctp_event(&trailing).is_none(),
            "trailing notification bytes must reject"
        );
        for offset in 4..8 {
            for bit in 0..8 {
                let mut changed = valid.clone();
                changed[offset] ^= 1 << bit;
                assert!(
                    parse_sctp_event(&changed).is_none(),
                    "declared extent must be exact"
                );
            }
        }
        for invalid in [12, 16, 0x8000, u16::MAX] {
            assert!(parse_sctp_event(&event(kind, invalid, &fields)).is_none());
        }
    }
    let fields: Vec<_> = [1u32, 11, 3, 7]
        .into_iter()
        .flat_map(u32::to_ne_bytes)
        .collect();
    assert!(
        parse_sctp_event(&event(0x8006, 0, &fields)).is_none(),
        "unknown partial-delivery indication"
    );
}

#[test]
fn association_and_shutdown_events_have_exact_native_extents() {
    let fields = [
        0u16.to_ne_bytes().as_slice(),
        &0u16.to_ne_bytes(),
        &8u16.to_ne_bytes(),
        &8u16.to_ne_bytes(),
        &11i32.to_ne_bytes(),
    ]
    .concat();
    for (kind, fields) in [(0x8001, fields), (0x8005, 11i32.to_ne_bytes().to_vec())] {
        let valid = event(kind, 0, &fields);
        assert!(parse_sctp_event(&valid).is_some());
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(parse_sctp_event(&trailing).is_none());
        assert!(parse_sctp_event(&event(kind, 1, &fields)).is_none());
    }
    for (raw, state) in [
        (0, SctpAssociationState::Established),
        (1, SctpAssociationState::Lost),
        (2, SctpAssociationState::Restarted),
        (3, SctpAssociationState::ShutdownComplete),
        (4, SctpAssociationState::CannotStart),
        (5, SctpAssociationState::Unknown),
        (u16::MAX, SctpAssociationState::Unknown),
    ] {
        assert!(SctpAssociationState::from_kernel(raw) == state);
    }
}
