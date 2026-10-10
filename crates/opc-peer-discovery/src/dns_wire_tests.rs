use super::*;

// RFC 1035 section 4.1: ID 0x1234, response/RD/RA, A/IN question for a.,
// compressed owner pointer to offset 12, TTL 30, address 192.0.2.1.
const ANSWER: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1,
    0, 0, 0, 30, 0, 4, 192, 0, 2, 1,
];

// RFC 3403 4.1: order 10, preference 20, "a", "x-a:x-b", empty regexp,
// replacement a. compressed to the question name (receiver rule, RFC 3597 4).
const NAPTR: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 35, 0, 1, 0xc0, 0x0c, 0, 35, 0,
    1, 0, 0, 0, 30, 0, 17, 0, 10, 0, 20, 1, b'a', 7, b'x', b'-', b'a', b':', b'x', b'-', b'b', 0,
    0xc0, 0x0c,
];

fn decode_naptr(bytes: &[u8]) -> Result<Message, DecodeError> {
    decode(bytes, 0x1234, &DnsName::new("a.").unwrap(), 35)
}

#[test]
fn spec_authored_naptr_counted_strings_and_compressed_replacement() {
    let message = decode_naptr(NAPTR).unwrap();
    let Data::Naptr(record) = &message.answers[0].data else {
        panic!("NAPTR was not decoded")
    };
    assert_eq!((record.order, record.preference), (10, 20));
    assert_eq!(&*record.flags, b"a");
    assert_eq!(&*record.services, b"x-a:x-b");
    assert!(record.regexp.is_empty());
    assert_eq!(record.replacement.as_ref().unwrap().as_str(), "a.");
    let mut query = NAPTR[..19].to_vec();
    query[2..4].copy_from_slice(&[1, 0]);
    query[6..8].fill(0);
    assert_eq!(
        encode(0x1234, &DnsName::new("a.").unwrap(), 35, None),
        query
    );
}

#[test]
fn naptr_framing_rejects_short_strings_bad_lengths_and_forged_pointers() {
    for end in 0..NAPTR.len() {
        assert!(decode_naptr(&NAPTR[..end]).is_err(), "prefix {end}");
    }
    for (offset, value) in [
        (30, 16),
        (30, 18),
        (35, 255),
        (37, 255),
        (45, 255),
        (47, 37),
        (47, 46),
        (47, 0),
    ] {
        let mut bytes = NAPTR.to_vec();
        bytes[offset] = value;
        assert!(
            decode_naptr(&bytes).is_err(),
            "offset {offset}, value {value}"
        );
    }
    let mut bytes = NAPTR.to_vec();
    bytes.push(0);
    assert!(decode_naptr(&bytes).is_err());
}

#[test]
fn framed_semantic_errors_remain_records_for_branch_isolation() {
    let mut regexp = NAPTR.to_vec();
    regexp[30] = 18;
    regexp[45] = 1;
    regexp.insert(46, b'x');
    let message = decode_naptr(&regexp).unwrap();
    assert!(matches!(&message.answers[0].data,Data::Naptr(record) if &*record.regexp==b"x"));
    let mut services = NAPTR.to_vec();
    services[44] = 0xff;
    let message = decode_naptr(&services).unwrap();
    assert!(
        matches!(&message.answers[0].data,Data::Naptr(record) if record.services.contains(&0xff))
    );
    let mut binary = NAPTR[..46].to_vec();
    binary[30] = 18;
    binary.extend([1, 0xff, 0]);
    let message = decode_naptr(&binary).unwrap();
    assert!(matches!(&message.answers[0].data,Data::Naptr(record) if record.replacement.is_none()));
}

#[test]
fn question_type_metadata_is_exhaustive_and_rejects_unknown_types() {
    for (wire, kind) in [
        (1, DnsRecordType::A),
        (28, DnsRecordType::Aaaa),
        (33, DnsRecordType::Srv),
        (35, DnsRecordType::Naptr),
    ] {
        assert_eq!(record_type(wire), Ok(kind));
    }
    for wire in [0, 5, 6, 34, 36, u16::MAX] {
        assert_eq!(record_type(wire), Err(DnsError::InvalidQuery));
    }
}

fn decode_a(bytes: &[u8]) -> Result<Message, DecodeError> {
    decode(bytes, 0x1234, &DnsName::new("a.").unwrap(), 1)
}

#[test]
fn spec_authored_compressed_address_fixture() {
    let message = decode_a(ANSWER).unwrap();
    assert_eq!(message.rcode, 0);
    assert!(!message.truncated);
    assert_eq!(message.answers.len(), 1);
    assert_eq!(message.answers[0].ttl, 30);
    assert!(matches!(message.answers[0].data, Data::A(ip) if ip.octets() == [192, 0, 2, 1]));
}

#[test]
fn query_matches_independent_rfc_bytes() {
    let bytes = encode(0x1234, &DnsName::new("a.").unwrap(), 1, None);
    assert_eq!(
        bytes,
        [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]
    );
}

#[test]
fn every_truncated_prefix_is_rejected() {
    for end in 0..ANSWER.len() {
        assert!(decode_a(&ANSWER[..end]).is_err(), "accepted prefix {end}");
    }
}

#[test]
fn bad_pointers_labels_counts_and_rdlengths_are_rejected() {
    for (offset, bytes) in [
        (19, vec![0xc0, 19]),   // self pointer
        (19, vec![0xc0, 21]),   // forward pointer
        (19, vec![0xff, 0xff]), // outside packet
        (19, vec![0xc0, 0]),    // header is not a domain name
        (19, vec![0x40]),       // reserved label tag
        (19, vec![0x80]),       // reserved label tag
        (29, vec![0, 3]),       // wrong A width
        (29, vec![0xff, 0xff]), // oversized RDATA
        (6, vec![0xff, 0xff]),  // excessive count
        (4, vec![0, 2]),        // multiple questions
        (2, vec![1]),           // query rather than answer
    ] {
        let mut bad = ANSWER.to_vec();
        bad[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(decode_a(&bad).is_err(), "accepted mutation at {offset}");
    }
    let mut trailing = ANSWER.to_vec();
    trailing.push(0);
    assert!(decode_a(&trailing).is_err());
}

#[test]
fn question_case_is_insensitive_but_type_class_and_id_must_match() {
    let mut bytes = ANSWER.to_vec();
    bytes[13] = b'A';
    assert!(decode_a(&bytes).is_ok());
    bytes[1] ^= 1;
    assert_eq!(decode_a(&bytes).err(), Some(DecodeError::Id));
    for (index, value) in [(13, b'b'), (16, 28), (18, 3)] {
        let mut bytes = ANSWER.to_vec();
        bytes[index] = value;
        assert_eq!(decode_a(&bytes).err(), Some(DecodeError::Question));
    }
    // A binary label is legal DNS syntax, but cannot match this ASCII question.
    let mut bytes = ANSWER.to_vec();
    bytes[13] = b'!';
    assert_eq!(decode_a(&bytes).err(), Some(DecodeError::Question));
}

#[test]
fn truncation_only_bypasses_record_parsing_after_identity_validation() {
    let mut bytes = ANSWER[..20].to_vec();
    bytes[2] |= 2;
    assert!(decode_a(&bytes).unwrap().truncated);
    bytes[13] = b'b';
    assert_eq!(decode_a(&bytes).err(), Some(DecodeError::Question));
}

#[test]
fn edns_extended_rcode_version_duplicate_and_option_lengths() {
    let mut bytes = ANSWER.to_vec();
    bytes[11] = 1;
    // Root OPT, size 1232, extended RCODE 1 (BADVERS), version 0, no data.
    let opt = [0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0];
    bytes.extend(opt);
    assert_eq!(decode_a(&bytes).unwrap().rcode, 16);
    let mut version = bytes.clone();
    version[ANSWER.len() + 6] = 1;
    assert!(decode_a(&version).is_err());
    let mut duplicate = bytes.clone();
    duplicate[11] = 2;
    duplicate.extend(opt);
    assert!(decode_a(&duplicate).is_err());
    let mut bad_option = bytes;
    *bad_option.last_mut().unwrap() = 4;
    bad_option.extend([0, 1, 0, 1]); // claims one missing option data octet
    assert!(decode_a(&bad_option).is_err());
}

#[test]
fn deterministic_hostile_bytes_never_panic() {
    // Bounded mutation corpus exercises every octet and every byte value;
    // independent malformed frames cover lengths and compression explicitly.
    for offset in 0..ANSWER.len() {
        for value in 0..=255 {
            let mut bytes = ANSWER.to_vec();
            bytes[offset] = value;
            let _ = decode_a(&bytes);
        }
    }
    for size in [0, 1, 11, 12, 255, 512, 4096, 65_535] {
        for value in [0, 0x40, 0x80, 0xc0, 0xff] {
            let _ = decode_a(&vec![value; size]);
        }
    }
}

#[test]
fn label_boundaries_cannot_be_forged_with_compression_offsets() {
    // Point into the two-octet TYPE field, whose zero byte looks like the
    // root name. RFC 1035 4.1.4 pointers must reference a prior *name*.
    let mut bytes = ANSWER.to_vec();
    bytes[20] = 15;
    assert_eq!(decode_a(&bytes).err(), Some(DecodeError::Malformed));
}

#[test]
fn cyclic_names_embedded_dots_and_expanded_lengths_are_rejected() {
    let mut bytes = ANSWER.to_vec();
    // A label followed by a backward pointer back to that label.
    bytes.splice(19..21, [1, b'b', 0xc0, 19]);
    assert!(decode_a(&bytes).is_err());
    let mut bytes = ANSWER.to_vec();
    bytes[13] = b'.';
    assert!(decode_a(&bytes).is_err());
    let mut bytes = ANSWER[..19].to_vec();
    for _ in 0..4 {
        bytes.push(63);
        bytes.extend([b'b'; 63]);
    }
    bytes.push(0);
    bytes.extend(&ANSWER[21..]);
    assert!(decode_a(&bytes).is_err());
}

#[test]
fn compressed_cname_target_can_be_reused_as_an_address_owner() {
    // a. CNAME b.a., then b.a. A 192.0.2.1. The second owner points to the
    // earlier CNAME RDATA at offset 31, whose suffix points to the question.
    let mut bytes = ANSWER[..19].to_vec();
    bytes[7] = 2;
    bytes.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 7, 0, 4, 1, b'b', 0xc0, 12]);
    bytes.extend([0xc0, 31, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1]);
    let decoded = decode_a(&bytes).unwrap();
    assert!(matches!(&decoded.answers[0].data, Data::Cname(Some(name)) if name.as_str() == "b.a."));
    assert_eq!(decoded.answers[1].owner.as_ref().unwrap().as_str(), "b.a.");
}

#[test]
fn compression_can_reference_ignored_ns_rdata_and_root_label() {
    // a. A 192.0.2.1, authority a. NS b.a., additional b.a. A ...
    let mut bytes = ANSWER.to_vec();
    bytes[9] = 1;
    bytes[11] = 1;
    bytes.extend([0xc0, 12, 0, 2, 0, 1, 0, 0, 0, 30, 0, 4, 1, b'b', 0xc0, 12]);
    bytes.extend([0xc0, 47, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 2]);
    assert!(decode_a(&bytes).is_ok());
    // RFC 1035 4.1.4 permits a pointer to the question's root terminator.
    let mut bytes = ANSWER.to_vec();
    bytes[20] = 14;
    assert_eq!(
        decode_a(&bytes).unwrap().answers[0]
            .owner
            .as_ref()
            .unwrap()
            .as_str(),
        "."
    );
}

// Independent RFC 2782 fixture: a. SRV 1 2 443 b. (TTL 30), then additional
// b. A 192.0.2.1 (TTL 60). The target is uncompressed, while the additional
// owner legally points back to its label boundary at offset 37.
const SRV: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 1, 1, b'a', 0, 0, 33, 0, 1, 0xc0, 12, 0, 33, 0, 1,
    0, 0, 0, 30, 0, 9, 0, 1, 0, 2, 1, 187, 1, b'b', 0, 0xc0, 37, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
    192, 0, 2, 1,
];

fn decode_srv(bytes: &[u8]) -> Result<Message, DecodeError> {
    decode(bytes, 0x1234, &DnsName::new("a.").unwrap(), 33)
}

#[test]
fn spec_authored_srv_preserves_fields_and_allows_compressed_additional_owner() {
    let message = decode_srv(SRV).unwrap();
    assert!(matches!(&message.answers[0].data,
        Data::Srv { priority: 1, weight: 2, port: 443, target: Some(target) } if target.as_str() == "b."));
    assert_eq!(message.answers[0].ttl, 30);
    assert_eq!(message.additional[0].owner.as_ref().unwrap().as_str(), "b.");
    assert_eq!(message.additional[0].ttl, 60);
    assert!(matches!(message.additional[0].data, Data::A(ip) if ip.octets() == [192, 0, 2, 1]));
}

#[test]
fn srv_truncated_lengths_compressed_targets_and_mutations_are_bounded() {
    for end in 0..SRV.len() {
        assert!(decode_srv(&SRV[..end]).is_err(), "accepted prefix {end}");
    }
    for data in [
        vec![],
        vec![0; 5],                         // missing port byte
        vec![0; 6],                         // missing target
        vec![0, 1, 0, 2, 1, 187, 0xc0, 0],  // header pointer
        vec![0, 1, 0, 2, 1, 187, 0xc0, 37], // self pointer
        vec![0, 1, 0, 2, 1, 187, 0xc0, 38], // forward pointer
        vec![0, 1, 0, 2, 1, 187, 0xc0, 13], // label interior
        vec![0, 1, 0, 2, 1, 187, 0, 0],     // trailing RDATA after root target
    ] {
        let mut bad = SRV[..31].to_vec();
        bad[11] = 0;
        bad[29..31].copy_from_slice(&(data.len() as u16).to_be_bytes());
        bad.extend(data);
        assert!(decode_srv(&bad).is_err());
    }
    for (data, expected) in [
        (vec![0, 1, 0, 2, 1, 187, 0xc0, 12], "a."),
        (vec![0, 1, 0, 2, 1, 187, 1, b'b', 0xc0, 12], "b.a."),
    ] {
        let mut bytes = SRV[..31].to_vec();
        bytes[11] = 0;
        bytes[29..31].copy_from_slice(&(data.len() as u16).to_be_bytes());
        bytes.extend(data);
        let message = decode_srv(&bytes).unwrap();
        assert!(matches!(&message.answers[0].data,
            Data::Srv { target: Some(target), .. } if target.as_str() == expected));
    }
    for offset in 0..SRV.len() {
        for value in 0..=255 {
            let mut mutated = SRV.to_vec();
            mutated[offset] = value;
            let _ = decode_srv(&mutated);
        }
    }
}
