//! Rejection and boundary checks for the independent NAS identity recipes.
use super::*;

fn accepts(id: u16, bytes: &[u8], ctx: DecodeContext) -> bool {
    match id {
        3 => AmfSetId::decode(bytes, ctx).is_ok(),
        26 => FiveGStmsi::decode(bytes, ctx).is_ok(),
        171 => AmfRerouteInformation::decode(bytes, ctx).is_ok(),
        34 => MaskedImeisv::decode(bytes, ctx).is_ok(),
        443 => ExtendedAmfName::decode(bytes, ctx).is_ok(),
        _ => panic!("identity field"),
    }
}

fn rejects_leaf_and_message(id: u16, bytes: &[u8]) {
    let row = serde_json::json!({"message": if [3, 26, 171].contains(&id) {
        "InitialUEMessage"
    } else {
        "DownlinkNASTransport"
    }});
    let base = construct(&row).construct(context()).unwrap();
    let crit = if id == 26 {
        Criticality::reject
    } else {
        Criticality::ignore
    };
    let changed = with_extra(&base, id, crit, bytes);
    for unknown_ie_policy in [
        UnknownIePolicy::Preserve,
        UnknownIePolicy::Drop,
        UnknownIePolicy::Reject,
    ] {
        let ctx = DecodeContext {
            unknown_ie_policy,
            ..context()
        };
        assert!(!accepts(id, bytes, ctx), "malformed identity leaf admitted");
        assert!(
            NasMessage::from_pdu(&changed, ctx).is_err(),
            "malformed identity message admitted"
        );
    }
}

#[test]
fn identity_duplicates_select_distinct_values_and_reject_wrong_criticality() {
    let oracle = oracle();
    let mut duplicates = 0;
    let mut criticalities = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["identity_reroute_fields"] == true)
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        if row.get("invalid_identity_id").is_some() {
            assert!(row["reference_error"] == "ie-criticality");
            assert!(decode(&wire, context()).is_err());
            criticalities += 1;
        }
        if row.get("identity_duplicate_id").is_none() {
            continue;
        }
        assert!(row["reference_error"] == "duplicate-ie");
        assert!(decode(&wire, context()).is_err());
        for duplicate_ie_policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
            let ctx = DecodeContext {
                duplicate_ie_policy,
                ..context()
            };
            let pdu = decode(&wire, ctx).unwrap();
            let admitted = NasMessage::from_pdu(&pdu, ctx).unwrap();
            let prefix = if duplicate_ie_policy == DuplicateIePolicy::First {
                "first_"
            } else {
                "last_"
            };
            assert_identity_fields(&admitted.message, row, prefix);
            shared::reconstruct(&admitted.message, ctx, EncodeContext::default());
            assert!(pdu.raw.as_ref() == wire);
        }
        duplicates += 1;
    }
    assert_eq!((duplicates, criticalities), (5, 10));
}

#[test]
fn identity_roots_enforce_exact_extents_capacity_depth_and_redaction() {
    let oracle = oracle();
    let mut checked = 0;
    for row in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["identity_reroute_fields"] == true && r["construct"] == true)
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&wire, context()).unwrap();
        for id in [3, 26, 171, 34, 443] {
            let Some(value) = field_value(&pdu, id) else {
                continue;
            };
            for end in 0..value.len() {
                rejects_leaf_and_message(id, &value[..end]);
            }
            let mut trailing = value.to_vec();
            trailing.push(0);
            rejects_leaf_and_message(id, &trailing);
            let depth = if [3, 34].contains(&id) { 1 } else { 2 };
            let exact = DecodeContext {
                max_message_len: value.len(),
                max_depth: depth,
                max_ies: 0,
                ..context()
            };
            assert!(accepts(id, value, exact));
            assert!(!accepts(
                id,
                value,
                DecodeContext {
                    max_message_len: value.len() - 1,
                    ..exact
                }
            ));
            assert!(!accepts(
                id,
                value,
                DecodeContext {
                    max_depth: depth - 1,
                    ..exact
                }
            ));
            for length in [value.len(), value.len() - 1] {
                let ctx = EncodeContext {
                    max_message_len: length,
                    ..EncodeContext::default()
                };
                let encoded = match id {
                    3 => amf_set(&row["amf_set_id"]).unwrap().encode(ctx),
                    26 => stmsi(&row["fiveg_s_tmsi"]).unwrap().encode(ctx),
                    171 => reroute(&row["reroute"]).unwrap().encode(ctx),
                    34 => masked(&row["masked_imeisv"]).unwrap().encode(ctx),
                    443 => extended(&row["extended_old_amf"]).unwrap().encode(ctx),
                    _ => unreachable!(),
                };
                if length == value.len() {
                    assert!(encoded.unwrap().as_bytes() == value);
                } else {
                    assert!(encoded.is_err(), "identity encode capacity ignored");
                }
            }
            checked += 1;
        }
        for end in 0..wire.len() {
            assert!(decode(&wire[..end], context()).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        let (rest, prefix) = Pdu::decode(&trailing, context()).unwrap();
        assert!(rest == [0] && prefix.raw.as_ref() == wire);
        assert!(Pdu::decode_owned(Bytes::from(trailing), context()).is_err());
    }
    assert_eq!(checked, 220);
    assert_eq!(
        format!("{:?}", AmfSetId::new(731).unwrap()),
        "AmfSetId([REDACTED])"
    );
    assert_eq!(
        format!(
            "{:?}",
            FiveGStmsi::new(AmfSetId::new(731).unwrap(), 41, [1, 2, 3, 4]).unwrap()
        ),
        "FiveGStmsi([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", MaskedImeisv::new([0x12; 8])),
        "MaskedImeisv([REDACTED])"
    );
    assert_eq!(
        format!(
            "{:?}",
            AmfRerouteInformation::new(Some([0x12; 128]), None, None)
        ),
        "AmfRerouteInformation([REDACTED])"
    );
    assert_eq!(
        format!(
            "{:?}",
            ExtendedAmfName::new(Some("AMF-SECRET"), Some("AMF-秘密")).unwrap()
        ),
        "ExtendedAmfName([REDACTED])"
    );
}

#[test]
fn identity_padding_extensions_and_component_ranges_fail_closed() {
    for value in [1024, u16::MAX] {
        assert!(AmfSetId::new(value).is_err());
    }
    for value in [64, u8::MAX] {
        assert!(FiveGStmsi::new(AmfSetId::new(0).unwrap(), value, [0; 4]).is_err());
    }
    for bit in 0..6 {
        rejects_leaf_and_message(3, &[0, 1 << bit]);
        rejects_leaf_and_message(26, &[0, 0, 1 << bit, 0, 0, 0, 0]);
    }
    for flag in [0x80, 0x40] {
        rejects_leaf_and_message(26, &[flag, 0, 0, 0, 0, 0, 0]);
    }
    for flag in [0x80, 8, 4, 2, 1] {
        rejects_leaf_and_message(171, &[flag]);
    }
    for flag in [0x80, 0x10, 8, 4, 2, 1] {
        rejects_leaf_and_message(443, &[flag]);
    }
    // VisibleString's length-extension bit and its three alignment bits.
    rejects_leaf_and_message(443, &[0x48, 0, b'A']);
    for bit in 0..3 {
        rejects_leaf_and_message(443, &[0x40, 1 << bit, b'A']);
    }
    // Length 151 is outside the admitted root, even with all octets supplied.
    let mut long_visible = vec![0x44, 0xb0];
    long_visible.extend_from_slice(&[b'A'; 151]);
    rejects_leaf_and_message(443, &long_visible);
}

#[test]
fn identity_extended_names_enforce_unicode_counts_and_canonical_lengths() {
    for bad in ["", "\n", "\u{7f}", "é"] {
        assert!(ExtendedAmfName::new(Some(bad), None).is_err());
    }
    assert!(ExtendedAmfName::new(Some(&"A".repeat(151)), None).is_err());
    for bad in [
        String::new(),
        "A".repeat(151),
        "é".repeat(151),
        "😀".repeat(151),
    ] {
        assert!(ExtendedAmfName::new(None, Some(&bad)).is_err());
    }
    for bytes in [
        vec![0x20, 0],
        vec![0x20, 0x80, 1, b'A'],
        vec![0x20, 0xc1],
        vec![0x20, 2, 0xc0, 0xaf],
        vec![0x20, 3, 0xed, 0xa0, 0x80],
        vec![0x20, 4, 0xf4, 0x90, 0x80, 0x80],
        vec![0x20, 1, 0x80],
        vec![0x40, 0, 0x1f],
        vec![0x40, 0, 0x7f],
        vec![0x40, 0, 0xff],
    ] {
        rejects_leaf_and_message(443, &bytes);
    }
    // The UTF8String length determinant counts octets, but its ASN.1 SIZE
    // counts characters. Exercise both guards with fully supplied payloads.
    for value in ["A".repeat(151), "é".repeat(151), "😀".repeat(151)] {
        let length = u16::try_from(value.len()).unwrap();
        let mut bytes = vec![0x20];
        bytes.extend_from_slice(&(0x8000 | length).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
        rejects_leaf_and_message(443, &bytes);
    }
    let mut noncanonical = vec![0x20, 0x80, 127];
    noncanonical.extend_from_slice(&[b'A'; 127]);
    rejects_leaf_and_message(443, &noncanonical);
}
