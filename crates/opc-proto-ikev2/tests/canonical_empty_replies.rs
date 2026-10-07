//! Frozen V1 wire contract, immutable binding, restart and public refusal tests.

use std::process::Command;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    canonical::{
        Ikev2CanonicalEmptyReplies as Canonical, Ikev2CanonicalError as Error,
        Ikev2CanonicalPolicy as Policy,
    },
    recovery::{
        Ikev2CommittedExchangeRecord as ExchangeRecord, Ikev2CommittedWindow as Window,
        Ikev2CommittedWindowDomain as Domain, Ikev2CommittedWindowRecord as WindowRecord,
        Ikev2WindowError as WindowError,
    },
    Ikev2AesGcmIvAllocator as Allocator, Ikev2AesGcmIvPurpose as Purpose,
    Ikev2AesGcmIvRecord as IvRecord, Ikev2AesGcmIvReservationError as IvError, Ikev2ExchangeKind,
    PayloadChain, PayloadType, IKEV2_AES_GCM_NORMAL_IV_END,
};
use sha2::{Digest, Sha256};

#[path = "support/canonical.rs"]
mod fixtures;
mod support;
use fixtures::*;

const VECTORS: &str = include_str!("../src/canonical/v1.txt");

fn independently_open(
    algorithm: usize,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let nonce: &[u8; 12] = nonce.try_into().unwrap();
    let payload = Payload { msg: body, aad };
    match algorithm {
        0 => Aes128Gcm::new_from_slice(key)
            .unwrap()
            .decrypt(nonce.into(), payload),
        1 => aes_gcm::AesGcm::<aes::Aes192, aes_gcm::aead::consts::U12>::new_from_slice(key)
            .unwrap()
            .decrypt(nonce.into(), payload),
        2 => Aes256Gcm::new_from_slice(key)
            .unwrap()
            .decrypt(nonce.into(), payload),
        _ => panic!("test algorithm"),
    }
}

#[test]
fn frozen_v1_vectors_and_every_associated_data_bit_are_a_compatibility_contract() {
    support::ensure_ike_crypto();
    assert_eq!(
        Sha256::digest(VECTORS)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "b3bc1bbb1bbea169f33d9aae457795265071c43c3dcbe74949c339b788c9f789"
    );
    let mut count = 0;
    for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
        for direction in DIRECTIONS {
            let fixture = Fixture::new(0, encryption, direction);
            let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
            for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields[0].parse::<usize>().unwrap() != 128 + algorithm * 64
                    || fields[1] != if direction == DIRECTIONS[0] { "I" } else { "R" }
                {
                    continue;
                }
                let id = u32::from_str_radix(fields[2], 16).unwrap();
                let key = hex(fields[3]);
                let expected = hex(fields[4]);
                let request = fixture.request(id);
                let reply = replies.reply(&request).unwrap();
                assert_eq!(reply.bytes(), expected);
                assert_eq!(reply.bytes().len(), 57);
                assert_eq!(
                    &expected[..16],
                    &[SPIS.0.to_be_bytes(), SPIS.1.to_be_bytes()].concat()
                );
                assert_eq!(&expected[16..19], &[46, 0x20, 37]);
                assert_eq!(
                    expected[19],
                    if direction == DIRECTIONS[0] {
                        0x28
                    } else {
                        0x20
                    }
                );
                assert_eq!(&expected[20..24], &id.to_be_bytes());
                assert_eq!(&expected[24..32], &[0, 0, 0, 57, 0, 0, 0, 29]);
                assert_eq!(
                    &expected[32..40],
                    &(IKEV2_AES_GCM_NORMAL_IV_END + u64::from(id)).to_be_bytes()
                );
                let (key, salt) = key.split_at(key.len() - 4);
                let nonce = [salt, &expected[32..40]].concat();
                assert_eq!(
                    independently_open(algorithm, key, &nonce, &expected[..32], &expected[40..])
                        .unwrap(),
                    [0]
                );
                for end in [28, 40] {
                    assert!(independently_open(
                        algorithm,
                        key,
                        &nonce,
                        &expected[..end],
                        &expected[40..]
                    )
                    .is_err());
                }
                for bit in 0..256 {
                    let mut wrong = expected[..32].to_vec();
                    wrong[bit / 8] ^= 1 << (bit % 8);
                    assert!(
                        independently_open(algorithm, key, &nonce, &wrong, &expected[40..])
                            .is_err()
                    );
                }
                count += 1;
            }
        }
    }
    assert_eq!(count, 24);
}

#[test]
fn repeated_ids_reuse_bytes_despite_request_padding_without_advancing_durable_state() {
    support::ensure_ike_crypto();
    for direction in DIRECTIONS {
        let fixture = Fixture::new(100, ALGORITHMS[0], direction);
        let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
        let request = fixture.request(7);
        let first = replies.reply(&request).unwrap().bytes().to_vec();
        for padding in [0, 1, 31, 255] {
            let wire = fixture.peer(7, false, 37, empty(), padding, 5000 + u64::from(padding));
            let request = fixture
                .window
                .open_peer(fixture.profile, &fixture.keys, &wire)
                .unwrap();
            assert_eq!(replies.reply(&request).unwrap().bytes(), first);
        }
        assert_ne!(replies.reply(&fixture.request(8)).unwrap().bytes(), first);
        assert_eq!(fixture.window.record().next_receive(), Some(0));
        assert_eq!(fixture.iv.exclusive_end(), 64);
        assert_eq!(
            fixture.window.request_disposition(&request),
            Err(WindowError::NoDurableWork)
        );
    }
}

#[test]
fn activation_marker_and_restored_binding_are_the_only_capability_sources() {
    support::ensure_ike_crypto();
    let fixture = Fixture::new(101, ALGORITHMS[0], DIRECTIONS[0]);
    let mut fresh = Allocator::fresh(fixture.inputs(), fixture.iv.limits()).unwrap();
    assert_eq!(
        fresh.canonical_replies(Policy::default()).unwrap_err(),
        Error::NotCommitted
    );
    assert_eq!(
        fresh.allocate(Purpose::Ordinary).unwrap_err(),
        IvError::ReservationRequired
    );
    let prepared = fresh.prepare(1, Purpose::Ordinary).unwrap();
    assert_eq!(prepared.record().canonical_format(), Some(1));
    let durable = prepared.record().clone();
    prepared.activate_after_commit(&durable).unwrap();
    let capability = fresh.canonical_replies(Policy::default()).unwrap();
    assert_eq!(
        capability.reply(&fixture.request(0)).unwrap().bytes().len(),
        57
    );
    drop(capability);
    let restored = Allocator::restore(durable.domain(), &durable).unwrap();
    assert_eq!(
        restored.canonical_replies(Policy::default()).unwrap_err(),
        Error::NotCommitted
    );
    let restored_window = fixture.restore(&durable);
    let capability = restored_window
        .canonical_replies(Policy::default())
        .unwrap();
    assert_eq!(
        capability.reply(&fixture.request(0)).unwrap_err(),
        Error::AlreadyReleased
    );

    for (tag, marker) in [
        (102, None),
        (103, Some(0)),
        (104, Some(2)),
        (105, Some(255)),
    ] {
        let fixture = Fixture::new(tag, ALGORITHMS[0], DIRECTIONS[1]);
        let record = fixture.stored(marker, 64);
        assert_eq!(record.canonical_format(), marker);
        let window = fixture.restore(&record);
        assert_eq!(
            window.canonical_replies(Policy::default()).unwrap_err(),
            Error::FormatUnavailable
        );
        let mut allocator = Allocator::restore(record.domain(), &record).unwrap();
        let prepared = allocator.prepare(1, Purpose::Ordinary).unwrap();
        assert_eq!(
            prepared.record().canonical_format(),
            marker,
            "no retrofit during reservation"
        );
        assert_eq!(
            IvRecord::from_persisted(fixture.inputs(), fixture.iv.limits(), u64::MAX, marker)
                .unwrap_err(),
            IvError::InvalidRecord
        );
    }
}

#[test]
fn trust_loss_discards_cache_and_recreation_or_binding_changes_cannot_reset_release_history() {
    support::ensure_ike_crypto();
    let fixture = Fixture::new(110, ALGORITHMS[0], DIRECTIONS[0]);
    let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
    let request = fixture.request(3);
    let expected = replies.reply(&request).unwrap().bytes().to_vec();
    assert_eq!(
        fixture
            .window
            .canonical_replies(Policy::default())
            .unwrap_err(),
        Error::CapabilityActive
    );
    replies.retire(3).unwrap();
    assert_eq!(replies.reply(&request).unwrap_err(), Error::AlreadyReleased);
    drop(replies);
    let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
    assert_eq!(replies.reply(&request).unwrap_err(), Error::AlreadyReleased);
    assert_ne!(
        replies.reply(&fixture.request(4)).unwrap().bytes(),
        expected
    );
    replies.invalidate();
    assert_eq!(
        replies.reply(&fixture.request(4)).unwrap_err(),
        Error::Invalidated
    );
    drop(replies);
    assert_eq!(
        fixture
            .window
            .canonical_replies(Policy::default())
            .unwrap_err(),
        Error::Invalidated
    );

    let fixture = Fixture::new(111, ALGORITHMS[0], DIRECTIONS[0]);
    let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
    let request = fixture.request(9);
    let _verified = replies.reply(&request).unwrap().bytes().to_vec();
    let mut changed = fixture.inputs();
    changed.initiator_spi ^= 1;
    let forged = IvRecord::from_persisted(changed, fixture.iv.limits(), 64, Some(1)).unwrap();
    let forged_window = fixture.restore(&forged);
    assert_eq!(
        forged_window
            .canonical_replies(Policy::default())
            .unwrap_err(),
        Error::BindingMismatch
    );
    assert_eq!(replies.reply(&request).unwrap_err(), Error::Invalidated);
}

#[test]
fn mixed_record_restore_invalidates_live_canonical_cache() {
    support::ensure_ike_crypto();
    let fixture = Fixture::new(112, ALGORITHMS[0], DIRECTIONS[1]);
    let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
    let request = fixture.request(6);
    let _verified = replies.reply(&request).unwrap().bytes().to_vec();
    let wrong = fixture.stored(None, 64);
    let domain = fixture.window.record().domain();
    assert_eq!(
        Window::restore(
            domain,
            fixture.profile,
            &fixture.keys,
            fixture.window.record(),
            &wrong
        )
        .unwrap_err(),
        WindowError::DomainMismatch
    );
    assert_eq!(replies.reply(&request).unwrap_err(), Error::Invalidated);
}

#[test]
fn output_can_only_answer_authenticated_same_domain_empty_informational_requests() {
    support::ensure_ike_crypto();
    for direction in DIRECTIONS {
        let fixture = Fixture::new(120, ALGORITHMS[0], direction);
        let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
        for (index, (response, exchange, payload)) in [
            (true, 37, empty()),
            (false, 35, empty()),
            (false, 36, empty()),
            (false, 37, delete()),
        ]
        .into_iter()
        .enumerate()
        {
            let wire = fixture.peer(
                0,
                response,
                exchange,
                payload,
                0,
                100 + u64::try_from(index).unwrap(),
            );
            let request = fixture
                .window
                .open_peer(fixture.profile, &fixture.keys, &wire)
                .unwrap();
            assert_eq!(replies.reply(&request).unwrap_err(), Error::InvalidRequest);
        }
        let sync = [
            0, 0, 0, 20, 0, 0, 0x40, 0x26, 1, 2, 3, 4, 0, 0, 0, 7, 0, 0, 0, 9,
        ];
        let wire = fixture.peer(
            0,
            false,
            37,
            PayloadChain::new(PayloadType::Notify, &sync),
            0,
            200,
        );
        assert_eq!(
            fixture
                .window
                .open_peer(fixture.profile, &fixture.keys, &wire)
                .unwrap_err(),
            WindowError::Drop
        );
        let foreign = Fixture::new(121, ALGORITHMS[0], direction);
        assert_eq!(
            replies.reply(&foreign.request(0)).unwrap_err(),
            Error::BindingMismatch
        );
        // The class at zero is positive, independent of nonempty RFC 6311 sync.
        assert_eq!(
            &replies.reply(&fixture.request(0)).unwrap().bytes()[20..24],
            &[0; 4]
        );
        let mut corrupt = fixture.peer(1, false, 37, empty(), 0, 300).to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            fixture
                .window
                .open_peer(fixture.profile, &fixture.keys, &corrupt)
                .unwrap_err(),
            WindowError::Drop
        );
    }
}

#[test]
fn canonical_header_matches_the_ordinary_empty_acknowledgement_encoder() {
    support::ensure_ike_crypto();
    for algorithm in ALGORITHMS {
        for direction in DIRECTIONS {
            let mut fixture = Fixture::new(130, algorithm, direction);
            let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
            let canonical = replies.reply(&fixture.request(0)).unwrap().bytes().to_vec();
            let wire = fixture.peer(0, false, 37, delete(), 0, 900);
            let request = fixture
                .window
                .open_peer(fixture.profile, &fixture.keys, &wire)
                .unwrap();
            let prepared = fixture
                .window
                .prepare_response(
                    fixture.profile,
                    &fixture.keys,
                    fixture.allocator.allocate(Purpose::Ordinary).unwrap(),
                    &request,
                    empty(),
                    Bytes::new(),
                )
                .unwrap();
            let ordinary = prepared.record().inbound().unwrap().response().unwrap();
            assert_eq!(&canonical[..32], &ordinary[..32]);
            assert_ne!(&canonical[32..], &ordinary[32..]);
        }
    }
}

#[test]
fn canonical_ciphertext_never_qualifies_committed_cache_or_ordinary_iv_floor() {
    support::ensure_ike_crypto();
    for direction in DIRECTIONS {
        for (tag, id) in [(140, 7), (141, u32::MAX)] {
            let fixture = Fixture::new(tag, ALGORITHMS[0], direction);
            let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
            let canonical = replies
                .reply(&fixture.request(id))
                .unwrap()
                .bytes()
                .to_vec();
            let request = fixture.peer(id, false, 37, delete(), 0, 400 + u64::from(id));
            let entry =
                ExchangeRecord::from_persisted(request, Some(canonical.into()), Some(Bytes::new()))
                    .unwrap();
            let domain = Domain::from_iv_record(&fixture.iv);
            let record = WindowRecord::from_persisted(
                domain.clone(),
                1,
                Some(0),
                id.checked_add(1),
                None,
                Some(entry),
            )
            .unwrap();
            assert_eq!(
                Window::restore(
                    &domain,
                    fixture.profile,
                    &fixture.keys,
                    &record,
                    &fixture.iv
                )
                .unwrap_err(),
                WindowError::InvalidRecord
            );
        }
    }
}

#[test]
fn new_ike_key_epoch_and_direction_separate_nonces_without_resetting_an_old_epoch() {
    support::ensure_ike_crypto();
    let mut packets = Vec::new();
    for tag in [150, 151] {
        for direction in DIRECTIONS {
            let fixture = Fixture::new(tag, ALGORITHMS[0], direction);
            let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
            packets.push(replies.reply(&fixture.request(0)).unwrap().bytes().to_vec());
            let wire = fixture.peer(
                0,
                false,
                Ikev2ExchangeKind::CreateChildSa.as_u8(),
                delete(),
                0,
                501,
            );
            let rekey = fixture
                .window
                .open_peer(fixture.profile, &fixture.keys, &wire)
                .unwrap();
            assert_eq!(replies.reply(&rekey).unwrap_err(), Error::InvalidRequest);
            assert_eq!(
                replies.reply(&fixture.request(0)).unwrap().bytes(),
                packets.last().unwrap()
            );
        }
    }
    for index in 0..packets.len() {
        assert!(packets[index + 1..]
            .iter()
            .all(|other| other != &packets[index]));
    }
}

#[test]
fn restart_regenerates_identical_bytes_after_every_send_crash_boundary() {
    if let Ok(stage) = std::env::var("OPC_CANONICAL_RESTART_STAGE") {
        support::ensure_ike_crypto();
        let fixture = if stage == "restored" {
            let profile = profile(ALGORITHMS[0]);
            Fixture::from_persisted_keys(
                profile,
                key_material(profile, 160),
                DIRECTIONS[1],
                SPIS,
                64,
            )
        } else {
            Fixture::new(160, ALGORITHMS[0], DIRECTIONS[1])
        };
        let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
        if stage == "before-seal" {
            std::process::exit(0); // Process loss does not run capability destructors.
        }
        let verified = replies.reply(&fixture.request(0)).unwrap();
        let packet = verified.bytes();
        // Transport is outside this primitive. Model handing verified bytes to
        // it without creating a live peer/lab or implying transmit authority.
        if stage == "after-send" {
            let (send, receive) = std::sync::mpsc::channel();
            send.send(packet.to_vec()).unwrap();
            assert_eq!(receive.recv().unwrap(), packet);
        }
        println!(
            "VERIFIED_V1={}",
            packet
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        // Only verified public-fixture bytes cross this test evidence boundary.
        // Abrupt exit leaves the owned reply, cache and capability undropped.
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        std::process::exit(0);
    }
    let mut packets = Vec::new();
    for stage in [
        "before-seal",
        // After seal and before send are the same boundary for this primitive.
        "before-send",
        "after-send",
        "restored",
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restart_regenerates_identical_bytes_after_every_send_crash_boundary",
                "--nocapture",
            ])
            .env("OPC_CANONICAL_RESTART_STAGE", stage)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if stage != "before-seal" {
            let stdout = String::from_utf8(output.stdout).unwrap();
            packets.push(
                stdout
                    .lines()
                    .find(|line| line.starts_with("VERIFIED_V1="))
                    .unwrap()
                    .to_owned(),
            );
        }
    }
    assert_eq!(packets.len(), 3);
    assert!(packets.iter().all(|packet| packet == &packets[0]));
}

#[test]
fn canonical_capability_and_verified_reply_debug_are_redacted() {
    support::ensure_ike_crypto();
    let fixture = Fixture::new(170, ALGORITHMS[0], DIRECTIONS[0]);
    let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
    let packet = replies.reply(&fixture.request(5)).unwrap();
    assert_eq!(format!("{replies:?}"), "Ikev2CanonicalEmptyReplies { .. }");
    assert_eq!(format!("{packet:?}"), "Ikev2CanonicalReply { .. }");
    assert_eq!(format!("{:?}", Error::InvalidOutput), "InvalidOutput");
    assert_eq!(
        std::error::Error::source(&Error::InvalidOutput).map(ToString::to_string),
        None
    );
    assert!(!Error::InvalidOutput.to_string().contains("57"));
    // Provider-fault tests separately check withheld output never reaches either path.
    Canonical::preflight(ALGORITHMS[0], Policy::default()).unwrap();
}

#[test]
fn every_mixed_binding_is_terminal_even_before_a_capability_exists() {
    support::ensure_ike_crypto();
    for live in [false, true] {
        for field in 0..8 {
            let fixture = Fixture::new(
                500 + field + u64::from(live) * 10,
                ALGORITHMS[0],
                DIRECTIONS[0],
            );
            let request = fixture.request(0);
            let replies =
                live.then(|| fixture.window.canonical_replies(Policy::default()).unwrap());
            if let Some(replies) = &replies {
                assert_eq!(replies.reply(&request).unwrap().bytes().len(), 57);
            }
            let mut inputs = fixture.inputs();
            let mut marker = Some(1);
            let mut ei = fixture.keys.sk_ei().to_vec();
            let mut er = fixture.keys.sk_er().to_vec();
            match field {
                0 => inputs.initiator_spi ^= 1,
                1 => inputs.responder_spi ^= 1,
                2 => inputs.sending_direction = DIRECTIONS[1],
                3 => inputs.profile = profile(ALGORITHMS[1]),
                4 => ei[0] ^= 1,
                5 => ei[19] ^= 1,
                6 => er[0] ^= 1,
                7 => marker = Some(2),
                _ => unreachable!(),
            }
            let keys = if field == 3 {
                key_material(inputs.profile, 700)
            } else {
                opc_proto_ikev2::Ikev2SaInitKeyMaterial::from_established_keys(
                    fixture.profile,
                    false,
                    fixture.keys.sk_d(),
                    &[],
                    &[],
                    &ei,
                    &er,
                    fixture.keys.sk_pi(),
                    fixture.keys.sk_pr(),
                )
                .unwrap()
            };
            inputs.keys = &keys;
            let wrong = IvRecord::from_persisted(inputs, fixture.iv.limits(), 64, marker).unwrap();
            assert_eq!(
                Window::restore(
                    fixture.window.record().domain(),
                    fixture.profile,
                    &fixture.keys,
                    fixture.window.record(),
                    &wrong,
                )
                .unwrap_err(),
                WindowError::DomainMismatch
            );
            if let Some(replies) = &replies {
                assert_eq!(replies.reply(&request).unwrap_err(), Error::Invalidated);
            }
            drop(replies);
            assert_eq!(
                fixture
                    .window
                    .canonical_replies(Policy::default())
                    .unwrap_err(),
                Error::Invalidated
            );
        }
    }
}

#[test]
fn mutable_high_water_reconciliation_discards_cache_without_resetting_release_history() {
    support::ensure_ike_crypto();
    let mut fixture = Fixture::new(530, ALGORITHMS[0], DIRECTIONS[0]);
    assert_eq!(fixture.window.ready(), Ok(()));
    let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
    let request = fixture.request(1);
    assert_eq!(replies.reply(&request).unwrap().bytes().len(), 57);
    let prepared = fixture
        .window
        .prepare_request(
            fixture.profile,
            &fixture.keys,
            fixture.allocator.allocate(Purpose::Ordinary).unwrap(),
            Ikev2ExchangeKind::Informational,
            delete(),
        )
        .unwrap();
    let record = prepared.record().clone();
    drop(prepared);
    assert_eq!(fixture.window.ready(), Err(WindowError::CommitUncertain));
    assert_eq!(
        fixture
            .window
            .canonical_replies(Policy::default())
            .unwrap_err(),
        Error::LifecycleBlocked
    );
    let behind = fixture.stored(Some(1), 0);
    assert_eq!(
        Window::restore(
            record.domain(),
            fixture.profile,
            &fixture.keys,
            &record,
            &behind
        )
        .unwrap_err(),
        WindowError::InvalidRecord
    );
    assert_eq!(replies.reply(&request).unwrap_err(), Error::Invalidated);
    drop(replies);
    let window = Window::restore(
        record.domain(),
        fixture.profile,
        &fixture.keys,
        &record,
        &fixture.iv,
    )
    .unwrap();
    let replies = window.canonical_replies(Policy::default()).unwrap();
    assert_eq!(replies.reply(&request).unwrap_err(), Error::AlreadyReleased);
    assert_eq!(
        replies.reply(&fixture.request(2)).unwrap().bytes().len(),
        57
    );
}

#[test]
fn sampled_message_ids_are_injective_and_never_wrap_the_reserved_range() {
    support::ensure_ike_crypto();
    let fixture = Fixture::new(540, ALGORITHMS[0], DIRECTIONS[0]);
    let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
    let mut ids = std::collections::BTreeSet::from([0, 1, u32::MAX - 1, u32::MAX]);
    let mut next = 0x5a17_1234_u32;
    for _ in 0..256 {
        // Fixed-seed test sampling only; production never uses an RNG here.
        next ^= next << 13;
        next ^= next >> 17;
        next ^= next << 5;
        ids.insert(next);
    }
    let mut nonces = std::collections::BTreeSet::new();
    for id in ids {
        let reply = replies.reply(&fixture.request(id)).unwrap();
        let iv = u64::from_be_bytes(reply.bytes()[32..40].try_into().unwrap());
        assert_eq!(
            iv,
            IKEV2_AES_GCM_NORMAL_IV_END
                .checked_add(u64::from(id))
                .unwrap()
        );
        assert!(nonces.insert(iv));
    }
}

#[test]
fn every_sync_terminal_or_waiting_state_withholds_canonical_capability() {
    use opc_proto_ikev2::{
        recovery::{Ikev2SyncDisposition as Disposition, Ikev2SyncResponderRecord as SyncRecord},
        Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
        Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa,
    };
    support::ensure_ike_crypto();
    for (disposition, blocked) in [
        (Disposition::AwaitLocalSync, WindowError::SyncInProgress),
        (Disposition::OutcomeUncertain, WindowError::OutcomeUncertain),
        (Disposition::CloseIkeSa, WindowError::SyncClosed),
    ] {
        let fixture = Fixture::new(550, ALGORITHMS[0], DIRECTIONS[0]);
        let domain = Domain::from_iv_record(&fixture.iv);
        let agreement = Agreement::from_persisted(
            Sa::new(fixture.spis.0, fixture.spis.1, Role::Initiator).unwrap(),
            Mode::Negotiated,
        );
        let record = WindowRecord::from_persisted(domain.clone(), 1, Some(2), Some(0), None, None)
            .unwrap()
            .with_sync_state(
                SyncRecord::from_persisted(agreement, None, None, Some(1), None, disposition, 0)
                    .unwrap(),
            )
            .unwrap();
        let window = Window::restore(
            &domain,
            fixture.profile,
            &fixture.keys,
            &record,
            &fixture.iv,
        )
        .unwrap();
        assert_eq!(window.ready(), Err(blocked));
        assert_eq!(
            window.canonical_replies(Policy::default()).unwrap_err(),
            Error::LifecycleBlocked
        );
        assert_eq!(window.record(), &record);
    }
}

#[test]
fn compacted_floor_and_deleted_epoch_cannot_reset_release_history() {
    support::ensure_ike_crypto();
    let fixture = Fixture::new(600, ALGORITHMS[0], DIRECTIONS[0]);
    let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
    let held = replies.reply(&fixture.request(7)).unwrap();
    let packet = held.bytes().to_vec();
    replies.retire_through(7).unwrap();
    for id in [0, 1, 6, 7] {
        assert_eq!(
            replies.reply(&fixture.request(id)).unwrap_err(),
            Error::AlreadyReleased
        );
    }
    let above = replies.reply(&fixture.request(9)).unwrap();
    replies.retire_through(3).unwrap();
    assert_eq!(
        replies.reply(&fixture.request(9)).unwrap().bytes(),
        above.bytes()
    );
    drop(replies);
    assert_eq!(held.bytes(), packet); // Owned ciphertext; caller controls its lifetime.
    let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
    for id in [0, 7, 9] {
        assert_eq!(
            replies.reply(&fixture.request(id)).unwrap_err(),
            Error::AlreadyReleased
        );
    }
    assert_eq!(
        replies.reply(&fixture.request(10)).unwrap().bytes().len(),
        57
    );
    replies.retire_through(u32::MAX).unwrap();
    assert_eq!(
        replies.reply(&fixture.request(u32::MAX)).unwrap_err(),
        Error::AlreadyReleased
    );
    replies.delete();
    assert_eq!(
        fixture
            .window
            .canonical_replies(Policy::default())
            .unwrap_err(),
        Error::Invalidated
    );
}

#[test]
fn owned_reply_is_send_and_same_thread_followup_operations_do_not_deadlock() {
    fn assert_send<T: Send + 'static>() {}
    assert_send::<opc_proto_ikev2::canonical::Ikev2CanonicalReply>();
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        support::ensure_ike_crypto();
        let fixture = Fixture::new(601, ALGORITHMS[0], DIRECTIONS[0]);
        let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
        let first = replies.reply(&fixture.request(0)).unwrap();
        let second = replies.reply(&fixture.request(0)).unwrap();
        assert_eq!(first.bytes(), second.bytes());
        replies.retire(0).unwrap();
        let _third = replies.reply(&fixture.request(1)).unwrap();
        let wrong = fixture.stored(None, 64);
        assert_eq!(
            Window::restore(
                fixture.window.record().domain(),
                fixture.profile,
                &fixture.keys,
                fixture.window.record(),
                &wrong
            )
            .unwrap_err(),
            WindowError::DomainMismatch
        );
        replies.invalidate();
        drop(replies);
        send.send(first).unwrap();
    });
    // Functional deadlock watchdog only; lookup scaling is tested structurally.
    assert_eq!(
        receive
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .bytes()
            .len(),
        57
    );
}

#[test]
fn epoch_deletion_works_before_during_and_after_capability_ownership() {
    support::ensure_ike_crypto();
    for (tag, create, drop_first) in [(602, false, false), (603, true, false), (604, true, true)] {
        let fixture = Fixture::new(tag, ALGORITHMS[0], DIRECTIONS[0]);
        let mut replies =
            create.then(|| fixture.window.canonical_replies(Policy::default()).unwrap());
        if let Some(replies) = &replies {
            assert_eq!(
                replies.reply(&fixture.request(0)).unwrap().bytes().len(),
                57
            );
        }
        if drop_first {
            drop(replies.take());
        }
        Canonical::delete_epoch(&fixture.iv);
        if let Some(replies) = &replies {
            assert_eq!(
                replies.reply(&fixture.request(1)).unwrap_err(),
                Error::Invalidated
            );
        }
        Canonical::delete_epoch(&fixture.iv); // Permanent deletion is idempotent.
        assert_eq!(
            fixture
                .window
                .canonical_replies(Policy::default())
                .unwrap_err(),
            Error::Invalidated
        );
    }
}
