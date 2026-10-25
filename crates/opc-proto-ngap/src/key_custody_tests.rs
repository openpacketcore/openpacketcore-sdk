//! Live drop observations never read deallocated memory or retain key bytes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use opc_protocol::DuplicateIePolicy;
use sensitive::audit;

fn wire(entries: &[(u16, Criticality, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    constructed::write_prefix(&mut body, entries.len());
    for (id, criticality, value) in entries {
        constructed::write_ie(&mut body, *id, *criticality as u8, value);
    }
    let mut result = vec![0, 14, 0];
    constructed::write_open_type(&mut result, &body);
    result
}

fn entries(pdu: &Pdu) -> &[messages::ProtocolIeField] {
    let PduKind::Initiating {
        message: Message::InitialContextSetupRequest(request),
        ..
    } = &pdu.kind
    else {
        panic!("initial context request");
    };
    &request.protocol_ies.0
}

fn observed_nonempty() -> Vec<(usize, usize, bool)> {
    audit::take().into_iter().filter(|v| v.1 != 0).collect()
}

#[test]
fn security_key_ownership_raw_and_ie_allocations_are_wiped_before_release() {
    for with_key in [false, true] {
        audit::take();
        let wire = if with_key {
            wire(&[(94, Criticality::reject, &[0xab; 32])])
        } else {
            wire(&[(85, Criticality::reject, &[0x80, 0x12, 0x34])])
        };
        let pdu = decode(&wire, DecodeContext::default()).unwrap();
        let raw = (pdu.raw.as_ptr() as usize, pdu.raw.len(), true);
        let ie = &entries(&pdu)[0].value;
        let decoded = (ie.as_ptr() as usize, ie.len(), true);
        if with_key {
            let key = n3iwf::SecurityKey::decode(ie, DecodeContext::default()).unwrap();
            let handoff: zeroize::Zeroizing<Vec<u8>> = key.to_zeroizing();
            assert_eq!(handoff.as_slice(), &[0xab; 32]);
        }
        assert!(observed_nonempty().is_empty());
        drop(pdu);
        let drops = observed_nonempty();
        assert_eq!(drops.len(), 2);
        assert!(drops.contains(&raw), "raw PDU allocation must be wiped");
        assert!(drops.contains(&decoded), "IE allocation must be wiped");
    }
}

#[test]
fn security_key_ownership_policy_selection_and_rejection_wipe_discarded_ies() {
    let wire = wire(&[
        (94, Criticality::reject, &[0xab; 32]),
        (94, Criticality::reject, &[0xcd; 32]),
        (65530, Criticality::ignore, &[0xef; 32]),
    ]);
    for policy in [
        DuplicateIePolicy::Reject,
        DuplicateIePolicy::First,
        DuplicateIePolicy::Last,
    ] {
        audit::take();
        let result = decode(
            &wire,
            DecodeContext {
                duplicate_ie_policy: policy,
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..DecodeContext::default()
            },
        );
        if policy == DuplicateIePolicy::Reject {
            assert!(result.is_err());
        } else {
            let pdu = result.as_ref().unwrap();
            assert_eq!(entries(pdu).len(), 1);
            let expected = if policy == DuplicateIePolicy::First {
                0xab
            } else {
                0xcd
            };
            assert_eq!(entries(pdu)[0].value.as_bytes(), &[expected; 32]);
        }
        drop(result);
        let drops = observed_nonempty();
        assert_eq!(drops.len(), 4, "raw PDU and all three decoded values");
        assert!(drops.iter().all(|drop| drop.2));
    }
}

#[test]
fn security_key_ownership_partial_decode_error_clears_completed_allocations() {
    audit::take();
    let mut wire = wire(&[(94, Criticality::reject, &[0xab; 32])]);
    wire[6] = 2; // Claim another IE, whose header is truncated.
    wire.extend_from_slice(&[0, 85, 0]);
    wire[3] += 3;
    assert!(decode(&wire, DecodeContext::default()).is_err());
    let drops = observed_nonempty();
    assert_eq!(drops.len(), 2);
    assert!(drops.iter().all(|drop| drop.2));
}

#[test]
fn security_key_ownership_fragmented_pdu_and_opaque_ie_are_wiped() {
    audit::take();
    let opaque = vec![0xab; 20_000];
    let wire = wire(&[
        (94, Criticality::reject, &[0xcd; 32]),
        (65530, Criticality::ignore, &opaque),
    ]);
    let pdu = decode(
        &wire,
        DecodeContext {
            max_message_len: 30_000,
            ..DecodeContext::default()
        },
    )
    .unwrap();
    assert_eq!(entries(&pdu)[1].value.as_bytes(), opaque.as_slice());
    drop(pdu);
    let drops = observed_nonempty();
    assert_eq!(
        drops.len(),
        4,
        "coalesced PDU, raw PDU, key and coalesced IE"
    );
    assert!(drops.iter().all(|drop| drop.2));
}

#[test]
fn security_key_ownership_sequence_additions_do_not_materialize_key_copies() {
    let mut wire = wire(&[(94, Criticality::reject, &[0xab; 32])]);
    wire[4] = 0x80;
    wire.extend_from_slice(&[1, 32]); // One present extension, open-type length 32.
    wire.extend_from_slice(&[0xcd; 32]);
    wire[3] += 34;
    for truncate in [false, true] {
        audit::take();
        let mut input = wire.clone();
        if truncate {
            input.pop();
            input[3] -= 1;
        }
        let result = decode(&input, DecodeContext::default());
        assert_eq!(result.is_err(), truncate);
        drop(result);
        let drops = observed_nonempty();
        assert_eq!(drops.len(), 2, "only raw PDU and root IE own contents");
        assert!(drops.iter().all(|drop| drop.2));
    }
}

#[test]
fn security_key_ownership_large_extension_bitmap_preserves_exact_framing() {
    // X.691 11.9.3.4: the long form carries n, whereas the short form carries n-1.
    let mut wire = wire(&[(94, Criticality::reject, &[0xab; 32])]);
    wire[4] = 0x80;
    wire.extend_from_slice(&[0x80, 65]);
    wire.extend_from_slice(&[0; 8]);
    wire.push(0x80); // Only addition 65 is present; seven zero alignment bits.
    wire.extend_from_slice(&[1, 0xcd]);
    wire[3] += 13;
    audit::take();
    let pdu = decode(&wire, DecodeContext::default()).unwrap();
    assert_eq!(pdu.raw.as_bytes(), wire.as_slice());
    drop(pdu);
    let drops = observed_nonempty();
    assert_eq!(drops.len(), 2);
    assert!(drops.iter().all(|drop| drop.2));
}

#[test]
fn security_key_ownership_fragmented_extension_bitmaps_keep_only_existing_owners() {
    for count in [16384, 16385] {
        let mut body = vec![0x80, 0, 1];
        constructed::write_ie(&mut body, 94, Criticality::reject as u8, &[0xab; 32]);
        body.extend_from_slice(&[0x80, 0xc1]);
        body.extend_from_slice(&[0; 2047]);
        if count == 16384 {
            body.extend_from_slice(&[1, 0]); // Final present bit, zero terminator.
        } else {
            body.extend_from_slice(&[0, 1, 0x80]); // One-bit terminal fragment.
        }
        body.push(32);
        body.extend_from_slice(&[0xcd; 32]);
        for truncate in [false, true] {
            let mut input = vec![0, 14, 0];
            let end = body.len() - usize::from(truncate);
            constructed::write_open_type(&mut input, &body[..end]);
            audit::take();
            let result = decode(&input, DecodeContext::default());
            assert_eq!(result.is_err(), truncate);
            if let Ok(pdu) = &result {
                assert_eq!(pdu.raw.as_bytes(), input.as_slice());
                assert_eq!(entries(pdu)[0].value.as_bytes(), &[0xab; 32]);
            }
            drop(result);
            let drops = observed_nonempty();
            assert_eq!(drops.len(), 2, "only raw PDU and root IE own contents");
            assert!(drops.iter().all(|drop| drop.2));
        }
    }
}

#[test]
fn security_key_ownership_zeroizing_input_rejects_trailing_bytes() {
    let wire = wire(&[(94, Criticality::reject, &[0xab; 32])]);
    let pdu = Pdu::decode_zeroizing(
        zeroize::Zeroizing::new(wire.clone()),
        DecodeContext::default(),
    )
    .unwrap();
    assert_eq!(entries(&pdu)[0].value.as_bytes(), &[0xab; 32]);
    let mut trailing = wire;
    trailing.push(0);
    assert!(
        Pdu::decode_zeroizing(zeroize::Zeroizing::new(trailing), DecodeContext::default()).is_err()
    );
}
