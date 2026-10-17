use opc_proto_ikev2::n1_mode::{
    build_ikev2_n1_mode_notify, decode_ikev2_n1_mode_notify, Ikev2N1ModeNotifications,
    Ikev2N1ModeNotify, Ikev2N1ModeNotifyError, PduSessionId, PlmnIdentity, SnssaiValue,
    IKEV2_NOTIFY_N1_MODE_CAPABILITY, IKEV2_NOTIFY_N1_MODE_INFORMATION,
    IKEV2_NOTIFY_N1_MODE_S_NSSAI_PLMN_ID, N1_MODE_MAX_NOTIFIES,
};
use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, decode_ike_auth_cleartext_payloads,
    Ikev2IkeAuthPayloadBuild, Ikev2NotifyPayload, PayloadType,
};

// TS 24.302 V18.7.0 Figures/Tables 8.2.9.15-1 through 8.2.9.17-1.
// Literal type octets and length fields are independent of the encoder.
const CAPABILITY: &[u8] = &[0, 0, 0xc7, 0x47, 1, 7];
const INFORMATION: &[u8] = &[0, 0, 0xc7, 0xab, 4, 1, 0x12, 0x34, 0x56];
const PLMN: &[u8] = &[0, 0, 0xcb, 0xf8, 3, 0x00, 0xf1, 0x10];

fn generic(body: &[u8]) -> Ikev2NotifyPayload<'_> {
    Ikev2NotifyPayload::decode_body(body).unwrap()
}

#[test]
fn three_notify_types_match_independent_wire_vectors() {
    assert_eq!(IKEV2_NOTIFY_N1_MODE_CAPABILITY, 51015);
    assert_eq!(IKEV2_NOTIFY_N1_MODE_INFORMATION, 51115);
    assert_eq!(IKEV2_NOTIFY_N1_MODE_S_NSSAI_PLMN_ID, 52216);
    let cases = [
        (
            Ikev2N1ModeNotify::Capability(PduSessionId::new(7).unwrap()),
            CAPABILITY,
        ),
        (
            Ikev2N1ModeNotify::Information(
                SnssaiValue::from_bytes(&[1, 0x12, 0x34, 0x56]).unwrap(),
            ),
            INFORMATION,
        ),
        (
            Ikev2N1ModeNotify::SnssaiPlmnId(PlmnIdentity::from_bytes([0x00, 0xf1, 0x10]).unwrap()),
            PLMN,
        ),
    ];
    for (typed, wire) in cases {
        assert_eq!(build_ikev2_n1_mode_notify(typed).unwrap(), wire);
        assert_eq!(decode_ikev2_n1_mode_notify(generic(wire)), Ok(Some(typed)));
        let build = typed.to_notify_build();
        assert_eq!(build.protocol_id, 0);
        assert!(build.spi.is_empty());
        assert_eq!(build.notification_data, wire[4..]);
    }
}

#[test]
fn unrelated_malformed_recognized_and_valid_are_distinct() {
    assert_eq!(
        decode_ikev2_n1_mode_notify(generic(&[0, 0, 0x40, 0x04])),
        Ok(None)
    );
    assert_eq!(
        decode_ikev2_n1_mode_notify(generic(&[0, 0, 0xc7, 0x47])),
        Err(Ikev2N1ModeNotifyError::LengthMismatch)
    );
    assert!(decode_ikev2_n1_mode_notify(generic(CAPABILITY))
        .unwrap()
        .is_some());
}

#[test]
fn receiver_ignores_protocol_id_for_empty_spi() {
    for fixture in [CAPABILITY, INFORMATION, PLMN] {
        for protocol in 0..=255 {
            let mut wire = fixture.to_vec();
            wire[0] = protocol;
            assert_eq!(
                decode_ikev2_n1_mode_notify(generic(&wire)),
                decode_ikev2_n1_mode_notify(generic(fixture))
            );
        }
    }
}

#[test]
fn nonempty_and_inconsistent_spi_views_are_rejected() {
    for fixture in [CAPABILITY, INFORMATION, PLMN] {
        let mut view = generic(fixture);
        view.spi_size = 1;
        assert_eq!(
            decode_ikev2_n1_mode_notify(view),
            Err(Ikev2N1ModeNotifyError::SpiNotEmpty)
        );
        view.spi_size = 0;
        view.spi = &[0x55];
        assert_eq!(
            decode_ikev2_n1_mode_notify(view),
            Err(Ikev2N1ModeNotifyError::SpiNotEmpty)
        );
        let mut wire = fixture.to_vec();
        wire[1] = 1;
        wire.insert(4, 0x55);
        assert_eq!(
            decode_ikev2_n1_mode_notify(generic(&wire)),
            Err(Ikev2N1ModeNotifyError::SpiNotEmpty)
        );
    }
}

#[test]
fn inner_length_must_match_and_values_must_be_complete() {
    for fixture in [CAPABILITY, INFORMATION, PLMN] {
        for length in 0..=255 {
            if length == fixture[4] {
                continue;
            }
            let mut wire = fixture.to_vec();
            wire[4] = length;
            assert_eq!(
                decode_ikev2_n1_mode_notify(generic(&wire)),
                Err(Ikev2N1ModeNotifyError::LengthMismatch)
            );
        }
        for end in 4..fixture.len() {
            assert!(decode_ikev2_n1_mode_notify(generic(&fixture[..end])).is_err());
        }
        let mut trailing = fixture.to_vec();
        trailing.push(0);
        assert_eq!(
            decode_ikev2_n1_mode_notify(generic(&trailing)),
            Err(Ikev2N1ModeNotifyError::LengthMismatch)
        );
    }
    for bad in [16, 255] {
        assert_eq!(
            decode_ikev2_n1_mode_notify(generic(&[0, 0, 0xc7, 0x47, 1, bad])),
            Err(Ikev2N1ModeNotifyError::InvalidPduSessionId)
        );
    }
    assert_eq!(
        decode_ikev2_n1_mode_notify(generic(&[0, 0, 0xcb, 0xf8, 3, 0xfa, 0xff, 0xff])),
        Err(Ikev2N1ModeNotifyError::InvalidPlmnIdentity)
    );
    for len in [0, 3, 6, 7, 9] {
        let mut wire = vec![0, 0, 0xc7, 0xab, len];
        wire.extend(std::iter::repeat_n(1, usize::from(len)));
        assert_eq!(
            decode_ikev2_n1_mode_notify(generic(&wire)),
            Err(Ikev2N1ModeNotifyError::InvalidSnssai)
        );
    }
}

#[test]
fn all_slice_forms_and_unassigned_pdu_identity_round_trip() {
    for value in [
        &[1][..],
        &[1, 2],
        &[1, 2, 3, 4],
        &[1, 2, 3, 4, 5],
        &[1, 2, 3, 4, 5, 6, 7, 8],
    ] {
        let typed = Ikev2N1ModeNotify::Information(SnssaiValue::from_bytes(value).unwrap());
        let wire = build_ikev2_n1_mode_notify(typed).unwrap();
        assert_eq!(&wire[5..], value);
        assert_eq!(usize::from(wire[4]), value.len());
        assert_eq!(decode_ikev2_n1_mode_notify(generic(&wire)), Ok(Some(typed)));
    }
    let wire = [0, 0, 0xc7, 0x47, 1, 0];
    assert_eq!(
        decode_ikev2_n1_mode_notify(generic(&wire)),
        Ok(Some(Ikev2N1ModeNotify::Capability(
            PduSessionId::UNASSIGNED
        )))
    );
}

#[test]
fn opened_chain_collects_complete_values_and_preserves_unrelated_notify() {
    let unrelated = [0, 0, 0x40, 0x04];
    let bodies = [CAPABILITY, &unrelated, INFORMATION, PLMN];
    let builds: Vec<_> = bodies
        .iter()
        .map(|body| Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: body.to_vec(),
        })
        .collect();
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&builds).unwrap();
    let opened = decode_ike_auth_cleartext_payloads(first, &bytes).unwrap();
    let values = Ikev2N1ModeNotifications::decode(&opened.notifies).unwrap();
    assert_eq!(values.capability(), Some(PduSessionId::new(7).unwrap()));
    assert_eq!(values.information().unwrap().as_bytes(), &INFORMATION[5..]);
    assert_eq!(values.plmn_id().unwrap().as_bytes(), &[0x00, 0xf1, 0x10]);
    assert_eq!(opened.notifies.len(), 4);
    assert_eq!(opened.notifies[1].notify_message_type, 0x4004);
}

#[test]
fn collector_rejects_identical_and_conflicting_duplicates_without_partial_result() {
    for fixture in [CAPABILITY, INFORMATION, PLMN] {
        assert_eq!(
            Ikev2N1ModeNotifications::decode(&[generic(fixture), generic(fixture)]),
            Err(Ikev2N1ModeNotifyError::DuplicateNotify)
        );
    }
    let other_id = [0, 0, 0xc7, 0x47, 1, 8];
    assert_eq!(
        Ikev2N1ModeNotifications::decode(&[generic(CAPABILITY), generic(&other_id)]),
        Err(Ikev2N1ModeNotifyError::DuplicateNotify)
    );
    let malformed = [0, 0, 0xc7, 0xab, 2, 1];
    assert_eq!(
        Ikev2N1ModeNotifications::decode(&[generic(CAPABILITY), generic(&malformed)]),
        Err(Ikev2N1ModeNotifyError::LengthMismatch)
    );
}

#[test]
fn collector_bounds_total_work_including_unrelated_notifies() {
    let unrelated = generic(&[0, 0, 0x40, 0x04]);
    assert!(Ikev2N1ModeNotifications::decode(&vec![unrelated; N1_MODE_MAX_NOTIFIES]).is_ok());
    assert_eq!(
        Ikev2N1ModeNotifications::decode(&vec![unrelated; N1_MODE_MAX_NOTIFIES + 1]),
        Err(Ikev2N1ModeNotifyError::TooManyNotifies)
    );
}

#[test]
fn diagnostics_never_include_values_or_wire_bytes() {
    let a = decode_ikev2_n1_mode_notify(generic(CAPABILITY))
        .unwrap()
        .unwrap();
    let b = Ikev2N1ModeNotify::Capability(PduSessionId::new(15).unwrap());
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
    for error in [
        Ikev2N1ModeNotifyError::InvalidPduSessionId,
        Ikev2N1ModeNotifyError::InvalidSnssai,
        Ikev2N1ModeNotifyError::InvalidPlmnIdentity,
    ] {
        let text = format!("{error} {error:?}");
        assert!(!text.contains("123456"));
        assert!(!text.contains("0xf1"));
    }
}
