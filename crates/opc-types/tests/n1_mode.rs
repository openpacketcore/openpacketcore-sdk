use opc_types::n1_mode::{N1ModeValueError, PduSessionId, PlmnIdentity, SnssaiValue};

// Independent value octets from TS 24.501 V18.11.1 Table 9.11.2.8.1.
const SLICES: &[&[u8]] = &[
    &[1],
    &[1, 2],
    &[1, 0x12, 0x34, 0x56],
    &[1, 0x12, 0x34, 0x56, 2],
    &[1, 0x12, 0x34, 0x56, 2, 0x65, 0x43, 0x21],
];

#[test]
fn pdu_identity_distinguishes_unassigned_assigned_and_reserved() {
    for wire in 0..=15 {
        let id = PduSessionId::new(wire).unwrap();
        assert_eq!(id.value(), wire);
        assert_eq!(id.is_assigned(), wire != 0);
    }
    assert_eq!(PduSessionId::UNASSIGNED.value(), 0);
    for wire in 16..=255 {
        assert_eq!(PduSessionId::new(wire), Err(N1ModeValueError::PduSessionId));
    }
}

#[test]
fn all_five_slice_forms_preserve_complete_value_and_mapping() {
    for wire in SLICES {
        let value = SnssaiValue::from_bytes(wire).unwrap();
        assert_eq!(value.as_bytes(), *wire);
        assert_eq!(value.sst(), 1);
        assert_eq!(value.sd(), (wire.len() >= 4).then_some([0x12, 0x34, 0x56]));
        assert_eq!(
            value.mapped_hplmn_sst(),
            matches!(wire.len(), 2 | 5 | 8).then_some(2)
        );
        assert_eq!(
            value.mapped_hplmn_sd(),
            (wire.len() == 8).then_some([0x65, 0x43, 0x21])
        );
    }
    // "No SD associated" is a valid field encoding when mapped fields follow.
    let absent_sd = [0x80, 0xff, 0xff, 0xff, 0x81, 0xff, 0xff, 0xff];
    assert_eq!(
        SnssaiValue::from_bytes(&absent_sd).unwrap().as_bytes(),
        absent_sd
    );
}

#[test]
fn reserved_slice_lengths_are_rejected() {
    for len in [0, 3, 6, 7, 9, 255, 4096] {
        assert_eq!(
            SnssaiValue::from_bytes(&vec![1; len]),
            Err(N1ModeValueError::SnssaiLength)
        );
    }
}

#[test]
fn plmn_preserves_two_and_three_digit_mnc_without_accepting_bad_tbcd() {
    for wire in [[0x00, 0xf1, 0x10], [0x13, 0x00, 0x62]] {
        assert_eq!(PlmnIdentity::from_bytes(wire).unwrap().as_bytes(), &wire);
    }
    let valid = [0x13, 0x00, 0x62];
    for nibble in 0..6 {
        for digit in 10..=15 {
            let mut wire = valid;
            let shift = (nibble % 2) * 4;
            wire[nibble / 2] = (wire[nibble / 2] & !(0xf << shift)) | (digit << shift);
            let parsed = PlmnIdentity::from_bytes(wire);
            if nibble == 3 && digit == 15 {
                assert!(parsed.is_ok());
            } else {
                assert_eq!(parsed, Err(N1ModeValueError::PlmnIdentity));
            }
        }
    }
}

#[test]
fn value_diagnostics_are_fixed_and_do_not_expose_payloads() {
    assert_eq!(
        format!("{:?}", PduSessionId::new(15).unwrap()),
        "PduSessionId(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", SnssaiValue::from_bytes(SLICES[4]).unwrap()),
        "SnssaiValue(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", PlmnIdentity::from_bytes([0x13, 0, 0x62]).unwrap()),
        "PlmnIdentity(<redacted>)"
    );
    assert_eq!(
        PduSessionId::new(16).unwrap_err().to_string(),
        PduSessionId::new(255).unwrap_err().to_string()
    );
    assert_eq!(
        SnssaiValue::from_bytes(&[1; 3]).unwrap_err().to_string(),
        SnssaiValue::from_bytes(&[2; 9]).unwrap_err().to_string()
    );
}
