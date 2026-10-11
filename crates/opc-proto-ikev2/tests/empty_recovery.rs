//! RFC 7296 §§1.4, 2.1–2.4: authenticated, zero-write empty exchanges.

use bytes::Bytes;
use opc_proto_ikev2::{
    canonical::{
        Ikev2CanonicalEmptyReplies as Canonical, Ikev2CanonicalError as CanonicalError,
        Ikev2CanonicalPolicy as Policy,
    },
    recovery::{
        Ikev2AuthenticatedOrdinary as Request, Ikev2CommittedWindow as Window,
        Ikev2CommittedWindowDomain as Domain, Ikev2CommittedWindowRecord as Record,
        Ikev2EmptyReplyObservation as Observation, Ikev2OrdinaryRequestDisposition as Disposition,
        Ikev2SyncClock as Clock, Ikev2SyncDisposition as SyncDisposition,
        Ikev2SyncInitiatorAction as SyncAction, Ikev2SyncRecoveryPolicy as RecoveryPolicy,
        Ikev2SyncResponderRecord as SyncRecord, Ikev2WindowError as Error,
    },
    Ikev2AesGcmIvPurpose as Purpose, Ikev2ExchangeKind as Exchange,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa, PayloadChain, PayloadType,
};

#[path = "support/canonical.rs"]
mod canonical_fixtures;
mod support;
use canonical_fixtures::{delete, empty, Fixture, ALGORITHMS, DIRECTIONS};

#[test]
fn production_cbc_canonical_replies_match_frozen_packets_without_fixture() {
    // Frozen traffic keys are reused across PRFs. Isolate each PRF and policy in
    // a real process; the production ledger must refuse a changed key binding.
    if let Ok(prf) = std::env::var("OPC_CBC_PRODUCTION_PRF") {
        let policy = match std::env::var("OPC_CBC_PRODUCTION_POLICY").unwrap().as_str() {
            "default" => Policy::default(),
            "allow-declared" => Policy::explicitly_allow_declared_validated(),
            _ => panic!("unknown test policy"),
        };
        cbc_production_frozen_packets(prf.parse().unwrap(), policy);
        return;
    }
    for prf in [2, 5, 6, 7] {
        for policy in ["default", "allow-declared"] {
            use std::io::Read;
            use std::process::{Command, Stdio};
            use std::time::{Duration, Instant};
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "production_cbc_canonical_replies_match_frozen_packets_without_fixture",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("OPC_CBC_PRODUCTION_PRF", prf.to_string())
                .env("OPC_CBC_PRODUCTION_POLICY", policy)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdout = child.stdout.take().unwrap();
            let out = std::thread::spawn(move || {
                let mut text = String::new();
                stdout.read_to_string(&mut text).unwrap();
                text
            });
            let mut stderr = child.stderr.take().unwrap();
            let err = std::thread::spawn(move || {
                let mut text = String::new();
                stderr.read_to_string(&mut text).unwrap();
                text
            });
            let deadline = Instant::now() + Duration::from_secs(30);
            let (status, timed_out) = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break (status, false);
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    break (child.wait().unwrap(), true);
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let stdout = out.join().unwrap();
            let stderr = err.join().unwrap();
            assert!(
                !timed_out && status.success(),
                "PRF {prf}, {policy}: {status}, timed out={timed_out}\n{stdout}\n{stderr}"
            );
            assert!(stdout.contains("CBC_PRODUCTION_VECTORS:96"));
        }
    }
}

fn cbc_production_frozen_packets(prf_id: u16, policy: Policy) {
    use canonical_fixtures::{hex, opposite, SPIS};
    use opc_proto_ikev2::{
        recovery::{Ikev2CbcEpochInputs, Ikev2CbcEpochRecord as Epoch},
        seal_ikev2_sa_init_aes_cbc_protected_payload, Ikev2DhGroup,
        Ikev2EncryptionAlgorithm as Encryption, Ikev2IntegrityAlgorithm as Integrity,
        Ikev2PrfAlgorithm as Prf, Ikev2SaInitCryptoProfile as Profile,
        Ikev2SaInitKeyMaterial as Keys, ProtectedPayloadKind, ProtectedPayloadSealContext,
    };
    support::ensure_ike_crypto();
    assert!([2, 5, 6, 7].contains(&prf_id));
    // This target links the library without cfg(test), under both default and
    // all features. Expected bytes come from the independent frozen vectors.
    let vectors: Vec<Vec<&str>> = include_str!("../src/canonical/cbc_v1.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split_ascii_whitespace().collect())
        .collect();
    assert_eq!(vectors.len(), 384);
    let mut profiles_and_roles = 0;
    let mut packets = 0;
    for rows in vectors.as_chunks::<4>().0 {
        let fields = &rows[0];
        if fields[2].parse::<u16>().unwrap() != prf_id {
            continue;
        }
        let peer = vectors
            .iter()
            .find(|row| row[..3] == fields[..3] && row[3] != fields[3] && row[4] == "00000000")
            .unwrap();
        let direction = match fields[3] {
            "I" => DIRECTIONS[0],
            "R" => DIRECTIONS[1],
            _ => panic!("frozen original role"),
        };
        let (initiator, responder) = if direction == DIRECTIONS[0] {
            (fields, peer)
        } else {
            (peer, fields)
        };
        let encryption = match fields[0] {
            "128" => Encryption::AesCbc128,
            "192" => Encryption::AesCbc192,
            "256" => Encryption::AesCbc256,
            _ => panic!("frozen AES key size"),
        };
        let profile = Profile::new_encrypt_then_mac(
            Prf::from_transform_id(prf_id).unwrap(),
            Ikev2DhGroup::Modp2048,
            encryption,
            Integrity::from_transform_id(fields[1].parse().unwrap()).unwrap(),
        )
        .unwrap();
        let n = profile.prf().output_len();
        let keys = Keys::from_established_keys(
            profile,
            false,
            &hex(fields[5]),
            &hex(initiator[7]),
            &hex(responder[7]),
            &hex(initiator[6]),
            &hex(responder[6]),
            &vec![0x11; n],
            &vec![0x22; n],
        )
        .unwrap();
        Canonical::preflight_cbc(profile, policy).unwrap();
        let epoch = Epoch::fresh(Ikev2CbcEpochInputs {
            initiator_spi: SPIS.0,
            responder_spi: SPIS.1,
            sending_direction: direction,
            profile,
            keys: &keys,
        })
        .unwrap();
        let domain = Domain::from_cbc_epoch(&epoch);
        let record = Record::initial(domain.clone(), 1, 0);
        let mut window = Window::restore(&domain, profile, &keys, &record, &epoch).unwrap();
        window.enable_empty_replies(policy).unwrap();
        assert_eq!(window.ready(), Ok(()));
        assert_eq!(window.record(), &record);
        drop(window);
        let mut window = Window::restore(&domain, profile, &keys, &record, &epoch).unwrap();
        window.enable_empty_replies(policy).unwrap();
        for row in rows {
            let id = u32::from_str_radix(row[4], 16).unwrap();
            let expected = hex(row[10]);
            let mut request = expected[..32].to_vec();
            request[19] = if direction == DIRECTIONS[0] { 0 } else { 8 };
            let body = seal_ikev2_sa_init_aes_cbc_protected_payload(
                profile,
                &keys,
                opposite(direction),
                ProtectedPayloadSealContext {
                    kind: ProtectedPayloadKind::Encrypted,
                    message_prefix: &request,
                },
                &[],
            )
            .unwrap();
            request.extend_from_slice(&body);
            let request = window.open_peer(profile, &keys, &request).unwrap();
            let reply = window.reply_empty(&request).unwrap();
            assert_eq!(reply.observation(), Observation::Uncertain);
            assert_eq!(reply.bytes(), expected, "frozen CBC packet {row:?}");
            drop(reply);
            assert_eq!(window.next_receive(), id.checked_add(1));
            window.reconcile(profile, &keys, &record, &epoch).unwrap();
            let replay = window.reply_empty(&request).unwrap();
            assert_eq!(replay.observation(), Observation::Replayed);
            assert_eq!(replay.bytes(), expected);
            drop(replay);
            assert_eq!(window.record(), &record);
            packets += 1;
        }
        window.delete();
        profiles_and_roles += 1;
    }
    assert_eq!(profiles_and_roles, 24);
    assert_eq!(packets, 96);
    println!("CBC_PRODUCTION_VECTORS:{packets}");
}

fn fixture(tag: u64) -> Fixture {
    support::ensure_ike_crypto();
    Fixture::new(tag, ALGORITHMS[0], DIRECTIONS[0])
}

#[test]
fn close_commit_never_lowers_the_live_empty_receive_floor() {
    support::ensure_ike_crypto();
    for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::new(
                22_000 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            let mut window = start(&f, &record(&f, 0, true));
            for id in 0..4 {
                drop(window.reply_empty(&f.request(id)).unwrap());
            }
            let policy = RecoveryPolicy::new(1, Clock::new(100, 7), 200, 3, 10).unwrap();
            assert_eq!(
                window
                    .begin_sync(policy, Clock::new(200, 7), None)
                    .unwrap_err(),
                Error::SyncClosed
            );
            let prepared = window.close_sync().unwrap();
            let closed = prepared.record().clone();
            assert_eq!(closed.next_receive(), Some(0));
            let token = prepared
                .commit_after_durable(&closed, Clock::new(200, 7))
                .unwrap();
            assert_eq!(
                window.next_receive(),
                Some(4),
                "CloseIkeSa must preserve the live floor"
            );
            assert_eq!(window.ready(), Err(Error::SyncClosed));
            assert!(matches!(
                window
                    .release_sync_action(token, Clock::new(200, 7))
                    .unwrap(),
                SyncAction::CloseIkeSa
            ));
            window.delete();
        }
    }
}

fn record(f: &Fixture, receive: u32, negotiated: bool) -> Record {
    let record = Record::initial(Domain::from_iv_record(&f.iv), 0, receive);
    if !negotiated {
        return record;
    }
    record
        .with_sync_state(
            SyncRecord::from_persisted(
                Agreement::from_persisted(
                    Sa::new(
                        f.spis.0,
                        f.spis.1,
                        if f.direction == DIRECTIONS[0] {
                            Role::Initiator
                        } else {
                            Role::Responder
                        },
                    )
                    .unwrap(),
                    Mode::Negotiated,
                ),
                None,
                receive.checked_sub(1),
                None,
                None,
                SyncDisposition::Continue,
                0,
            )
            .unwrap(),
        )
        .unwrap()
}

fn start(f: &Fixture, record: &Record) -> Window {
    let mut window = Window::restore(record.domain(), f.profile, &f.keys, record, &f.iv).unwrap();
    window.enable_empty_replies(Policy::default()).unwrap();
    window
}

fn start_current(f: &mut Fixture, next: u32) -> Window {
    let initial = record(f, next.checked_sub(1).unwrap(), false);
    let mut window =
        Window::restore(initial.domain(), f.profile, &f.keys, &initial, &f.iv).unwrap();
    let request = work(f, next - 1);
    let prepared = window
        .prepare_response(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            &request,
            empty(),
            Bytes::from_static(b"current-boundary"),
        )
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    assert_eq!(
        window.apply_committed(token).unwrap(),
        Some(Bytes::from_static(b"current-boundary"))
    );
    window.enable_empty_replies(Policy::default()).unwrap();
    assert!(!window.is_reconstructing());
    assert_eq!(window.next_receive(), Some(next));
    window
}

fn work(f: &Fixture, id: u32) -> Request {
    let wire = f.peer(
        id,
        false,
        Exchange::Informational.as_u8(),
        delete(),
        0,
        0x1000 + u64::from(id),
    );
    f.window.open_peer(f.profile, &f.keys, &wire).unwrap()
}

fn peer_sync(f: &Fixture, sending: u32, receiving: u32) -> Bytes {
    let mut payload = vec![0, 0, 0, 20, 0, 0, 0x40, 0x26, 1, 2, 3, 4];
    payload.extend_from_slice(&sending.to_be_bytes());
    payload.extend_from_slice(&receiving.to_be_bytes());
    f.peer(
        0,
        false,
        Exchange::Informational.as_u8(),
        PayloadChain::new(PayloadType::Notify, &payload),
        0,
        400,
    )
}

#[test]
fn empty_then_nonempty_repairs_the_floor_without_a_dpd_write() {
    support::ensure_ike_crypto();
    for (algorithm_index, algorithm) in ALGORITHMS.into_iter().enumerate() {
        for (direction_index, direction) in DIRECTIONS.into_iter().enumerate() {
            for current in [false, true] {
                let tag = 10_000
                    + algorithm_index as u64 * 4
                    + direction_index as u64 * 2
                    + u64::from(current);
                let mut f = Fixture::new(tag, algorithm, direction);
                let mut window = if current {
                    start_current(&mut f, 4)
                } else {
                    start(&f, &record(&f, 4, false))
                };
                assert_eq!(window.is_reconstructing(), !current);
                let original = window.record().clone();
                let request = f.request(4);
                let iv_before = f.iv.clone();
                let first = window.reply_empty(&request).unwrap();
                assert_eq!(
                    first.observation(),
                    if current {
                        Observation::Fresh
                    } else {
                        Observation::Uncertain
                    }
                );
                assert_eq!(first.bytes().len(), 57);
                assert_eq!(&first.bytes()[20..24], &4_u32.to_be_bytes());
                let bytes = first.bytes().to_vec();
                drop(first);
                assert_eq!(window.record(), &original);
                assert_eq!(&f.iv, &iv_before);
                assert_eq!(window.next_receive(), Some(5));
                let duplicate = window.reply_empty(&request).unwrap();
                assert_eq!(duplicate.observation(), Observation::Replayed);
                assert_eq!(duplicate.bytes(), bytes);
                drop(duplicate);
                if current {
                    // G3 / PC: an empty reply advances the strict floor to 5,
                    // but it must not admit the nonempty gap at 6.
                    assert_eq!(window.request_disposition(&work(&f, 6)), Err(Error::Drop));
                }
                let request = work(&f, 5);
                assert_eq!(window.request_disposition(&request), Ok(Disposition::New));
                // RFC 7296 §1.4.1: an empty acknowledgement of a Delete is
                // still ordinary durable work; it must never take the V1 path.
                assert!(matches!(window.reply_empty(&request), Err(Error::Drop)));
                let prepared = window
                    .prepare_response(
                        f.profile,
                        &f.keys,
                        f.allocator.allocate(Purpose::Ordinary).unwrap(),
                        &request,
                        empty(),
                        Bytes::from_static(b"delete-once"),
                    )
                    .unwrap();
                let committed = prepared.record().clone();
                assert_eq!(committed.next_receive(), Some(6));
                assert_eq!(
                    &committed.inbound().unwrap().response().unwrap()[32..40],
                    &u64::from(current).to_be_bytes()
                );
                let token = prepared.commit_after_durable(&committed).unwrap();
                assert_eq!(
                    window.apply_committed(token).unwrap(),
                    Some(Bytes::from_static(b"delete-once"))
                );
                assert!(!window.is_reconstructing());
                assert_eq!(window.next_receive(), Some(6));
                assert_eq!(
                    window.request_disposition(&request),
                    Ok(Disposition::CachedResponse)
                );
                assert_eq!(
                    window.replay_response(&request).unwrap().bytes(),
                    committed.inbound().unwrap().response().unwrap()
                );
                assert_eq!(
                    window.reply_empty(&f.request(6)).unwrap().observation(),
                    Observation::Fresh
                );
                assert_eq!(window.request_disposition(&request), Err(Error::Drop));
                window.delete();
            }
        }
    }
}

#[test]
fn strict_empty_admission_rejects_gaps_changed_retransmissions_and_retired_ids() {
    let mut f = fixture(10_100);
    let mut window = start_current(&mut f, 4);
    let original = window.record().clone();
    for id in [0, 3, 5, u32::MAX] {
        assert!(matches!(
            window.reply_empty(&f.request(id)),
            Err(Error::Drop)
        ));
    }
    let request = f.request(4);
    let first = window.reply_empty(&request).unwrap().bytes().to_vec();
    // Same authenticated class/ID, different IV or padding: not a legal retry (§2.1).
    for (padding, iv) in [(1, 0x1004), (0, 0x2004)] {
        let wire = f.peer(4, false, 37, empty(), padding, iv);
        let changed = window.open_peer(f.profile, &f.keys, &wire).unwrap();
        assert!(matches!(window.reply_empty(&changed), Err(Error::Drop)));
    }
    assert_eq!(window.reply_empty(&request).unwrap().bytes(), first);
    let next = f.request(5);
    assert_eq!(
        window.reply_empty(&next).unwrap().observation(),
        Observation::Fresh
    );
    assert!(matches!(window.reply_empty(&request), Err(Error::Drop)));
    assert_eq!(window.next_receive(), Some(6));
    assert_eq!(window.record(), &original);
    window.delete();
}

#[test]
fn reconstruction_ignores_older_replays_and_commits_the_first_nonempty_error_once() {
    let mut f = fixture(10_101);
    let original = record(&f, 10, false);
    let mut window = start(&f, &original);
    for id in [10, 20, 40] {
        let request = f.request(id);
        let bytes = window.reply_empty(&request).unwrap().bytes().to_vec();
        assert_eq!(
            window.reply_empty(&request).unwrap().observation(),
            Observation::Replayed
        );
        assert_eq!(window.reply_empty(&request).unwrap().bytes(), bytes);
    }
    for id in [0, 9, 10, 20, 39] {
        assert!(matches!(
            window.reply_empty(&f.request(id)),
            Err(Error::Drop)
        ));
        assert!(matches!(
            window.request_disposition(&work(&f, id)),
            Err(Error::Drop)
        ));
    }
    assert_eq!(window.next_receive(), Some(41));
    assert_eq!(window.record(), &original);
    // A legitimate higher stateful request can follow an old replay received
    // first after restart. Neither replay gets to pin the recovery floor.
    let request = work(&f, 50);
    assert_eq!(window.request_disposition(&request), Ok(Disposition::New));
    let error_payload = [0, 0, 0, 8, 0, 0, 0, 43]; // TEMPORARY_FAILURE
    let prepared = window
        .prepare_response(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            &request,
            PayloadChain::new(PayloadType::Notify, &error_payload),
            Bytes::from_static(b"rejected-once"),
        )
        .unwrap();
    let committed = prepared.record().clone();
    let token = prepared.commit_after_durable(&committed).unwrap();
    assert_eq!(
        window.apply_committed(token).unwrap(),
        Some(Bytes::from_static(b"rejected-once"))
    );
    assert_eq!(window.next_receive(), Some(51));
    assert!(!window.is_reconstructing());
    assert!(matches!(
        window.reply_empty(&f.request(52)),
        Err(Error::Drop)
    ));
    assert_eq!(
        window.reply_empty(&f.request(51)).unwrap().observation(),
        Observation::Fresh
    );
    assert_eq!(window.request_disposition(&request), Err(Error::Drop));
    let restored =
        Window::restore(committed.domain(), f.profile, &f.keys, &committed, &f.iv).unwrap();
    assert_eq!(
        restored.request_disposition(&request),
        Ok(Disposition::CachedResponse)
    );
    assert_eq!(
        restored.replay_response(&request).unwrap().bytes(),
        committed.inbound().unwrap().response().unwrap()
    );
    window.delete();
}

#[test]
fn admitted_nonempty_work_blocks_empty_reconstruction_and_changed_work() {
    let mut f = fixture(10_102);
    let original = record(&f, 3, true);
    let mut window = start(&f, &original);
    let request = work(&f, 10);
    assert_eq!(window.request_disposition(&request), Ok(Disposition::New));
    for id in [3, 10, 11, 30] {
        assert!(matches!(
            window.reply_empty(&f.request(id)),
            Err(Error::Drop)
        ));
    }
    assert_eq!(window.request_disposition(&work(&f, 11)), Err(Error::Drop));
    let different = f.peer(10, false, 37, delete(), 0, 999);
    let different = window.open_peer(f.profile, &f.keys, &different).unwrap();
    assert_eq!(window.request_disposition(&different), Err(Error::Drop));
    let clock = Clock::new(100, 1);
    let policy = RecoveryPolicy::new(1, clock, 1000, 3, 10).unwrap();
    assert!(matches!(
        window.begin_sync(policy, clock, None),
        Err(Error::RequestOutstanding)
    ));
    // Pending work is remembered by the SDK even if the caller omits the old
    // explicit pending-inbound argument when a peer sync interrupts it.
    let sync = peer_sync(&f, 11, 0);
    let prepared = window
        .begin_sync_response(f.profile, &f.keys, &sync, None, None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    assert_eq!(
        prepared.record().sync_state().unwrap().disposition(),
        SyncDisposition::OutcomeUncertain
    );
    drop(prepared);
    assert!(matches!(
        window.reply_empty(&f.request(12)),
        Err(Error::CommitUncertain)
    ));
    window.delete();
}

#[test]
fn empty_max_is_cached_but_the_receive_counter_never_wraps() {
    for current in [false, true] {
        let mut f = fixture(10_110 + u64::from(current));
        let mut window = if current {
            start_current(&mut f, u32::MAX)
        } else {
            start(&f, &record(&f, u32::MAX, false))
        };
        assert_eq!(window.is_reconstructing(), !current);
        let original = window.record().clone();
        let request = f.request(u32::MAX);
        let bytes = window.reply_empty(&request).unwrap().bytes().to_vec();
        assert_eq!(window.next_receive(), None);
        assert_eq!(window.reply_empty(&request).unwrap().bytes(), bytes);
        assert!(matches!(
            window.reply_empty(&f.request(0)),
            Err(Error::Drop)
        ));
        assert_eq!(
            window.request_disposition(&work(&f, u32::MAX)),
            Err(Error::Drop)
        );
        assert_eq!(window.record(), &original);
        window.delete();
    }
}

#[test]
fn local_outstanding_request_and_its_commit_do_not_erase_the_empty_receive_floor() {
    let mut f = fixture(10_120);
    let original = record(&f, 0, false);
    let mut window = start(&f, &original);
    let request = f.request(0);
    let response = window.reply_empty(&request).unwrap().bytes().to_vec();
    let prepared = window
        .prepare_request(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            delete(),
        )
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    assert_eq!(window.apply_committed(token).unwrap(), None);
    assert_eq!(window.next_receive(), Some(1));
    assert_eq!(window.reply_empty(&request).unwrap().bytes(), response);
    assert_eq!(
        window.reply_empty(&f.request(1)).unwrap().observation(),
        Observation::Uncertain
    );
    // The two directions are independent, including when our request is pending (§2.3).
    assert!(window.record().outbound().unwrap().response().is_none());
    assert_eq!(window.record().next_receive(), Some(0));
    assert_eq!(window.next_receive(), Some(2));
    let reply = f.peer(0, true, 37, empty(), 0, 300);
    let reply = window.open_peer(f.profile, &f.keys, &reply).unwrap();
    let prepared = window
        .prepare_completion(&reply, Bytes::from_static(b"local-done"))
        .unwrap();
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    assert_eq!(
        window.apply_committed(token).unwrap(),
        Some(Bytes::from_static(b"local-done"))
    );
    assert_eq!(window.next_receive(), Some(2));
    assert_eq!(
        window.reply_empty(&f.request(1)).unwrap().observation(),
        Observation::Replayed
    );
    window.delete();
}

#[test]
fn reconstruction_observations_feed_sync_drop_knowledge_and_cutover_retires_cache() {
    let mut f = fixture(10_130);
    let original = record(&f, 3, true);
    let mut window = start(&f, &original);
    let request = f.request(10);
    assert_eq!(
        window.reply_empty(&request).unwrap().observation(),
        Observation::Uncertain
    );
    assert_eq!(window.record(), &original);
    let replay = peer_sync(&f, 10, 0);
    assert!(matches!(
        window.begin_sync_response(f.profile, &f.keys, &replay, None, None),
        Err(Error::Drop)
    ));
    let fresh = peer_sync(&f, 11, 0);
    let prepared = window
        .begin_sync_response(f.profile, &f.keys, &fresh, None, None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let committed = prepared.record().clone();
    assert_eq!(committed.next_receive(), Some(11));
    assert_eq!(
        committed.sync_state().unwrap().highest_peer_request(),
        Some(10)
    );
    let token = prepared.commit_after_durable(&committed).unwrap();
    let _response = window.release_sync_response(token).unwrap();
    assert!(!window.is_reconstructing());
    assert_eq!(window.next_receive(), Some(11));
    assert!(matches!(window.reply_empty(&request), Err(Error::Drop)));
    assert!(matches!(
        window.reply_empty(&f.request(12)),
        Err(Error::Drop)
    ));
    assert_eq!(
        window.reply_empty(&f.request(11)).unwrap().observation(),
        Observation::Fresh
    );
    window.delete();
}

#[test]
fn cached_replies_recheck_quiescence_sync_wait_and_terminal_dispositions() {
    for case in 0..4 {
        let mut f = fixture(10_140 + case);
        let original = record(&f, 0, true);
        let mut window = start(&f, &original);
        let request = f.request(0);
        window.reply_empty(&request).unwrap();
        let expected = match case {
            0 => {
                let prepared = window
                    .prepare_request(
                        f.profile,
                        &f.keys,
                        f.allocator.allocate(Purpose::Ordinary).unwrap(),
                        Exchange::Informational,
                        delete(),
                    )
                    .unwrap();
                drop(prepared);
                None
            }
            1 | 2 => {
                let clock = Clock::new(100, 1);
                let policy = RecoveryPolicy::new(1, clock, 1000, 3, 10).unwrap();
                let admitted = window.begin_sync(policy, clock, None).unwrap();
                let prepared = admitted
                    .prepare(
                        f.profile,
                        &f.keys,
                        f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    )
                    .unwrap();
                let committed = prepared.record().clone();
                let _token = prepared.commit_after_durable(&committed, clock).unwrap();
                if case == 2 {
                    let close = window.close_sync().unwrap();
                    let closed = close.record().clone();
                    let _token = close.commit_after_durable(&closed, clock).unwrap();
                    Some(Error::SyncClosed)
                } else {
                    Some(Error::SyncInProgress)
                }
            }
            _ => {
                let prepared = window
                    .prepare_request(
                        f.profile,
                        &f.keys,
                        f.allocator.allocate(Purpose::Ordinary).unwrap(),
                        Exchange::Informational,
                        delete(),
                    )
                    .unwrap();
                let committed = prepared.record().clone();
                let _token = prepared.commit_after_durable(&committed).unwrap();
                let sync = peer_sync(&f, 2, 1);
                let prepared = window
                    .begin_sync_response(f.profile, &f.keys, &sync, None, None)
                    .unwrap()
                    .prepare(
                        f.profile,
                        &f.keys,
                        f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    )
                    .unwrap();
                let committed = prepared.record().clone();
                let _token = prepared.commit_after_durable(&committed).unwrap();
                Some(Error::OutcomeUncertain)
            }
        };
        let before = window.record().clone();
        for request in [&request, &f.request(20)] {
            if let Some(expected) = expected {
                assert_eq!(window.reply_empty(request).unwrap_err(), expected);
            } else {
                assert_eq!(window.ready(), Err(Error::CommitUncertain));
                assert!(window.reply_empty(request).is_ok());
            }
        }
        assert_eq!(window.record(), &before);
        window.delete();
        // Terminal sync, uncertain writes and pending-sync teardown all retire
        // the registry entry, not just the runtime's owned capability.
        assert_eq!(
            f.window.enable_empty_replies(Policy::default()),
            Err(Error::Canonical(CanonicalError::Invalidated))
        );
    }
}

#[test]
fn canonical_configuration_refusal_never_enables_an_ordinary_fallback() {
    let mut f = fixture(10_150);
    let request = f.request(0);
    assert!(matches!(
        f.window.reply_empty(&request),
        Err(Error::EmptyRepliesDisabled)
    ));
    let unsupported = f.stored(None, 64);
    let domain = Domain::from_iv_record(&unsupported);
    let record = Record::initial(domain.clone(), 0, 0);
    let mut window = Window::restore(&domain, f.profile, &f.keys, &record, &unsupported).unwrap();
    assert_eq!(
        window.enable_empty_replies(Policy::default()),
        Err(Error::Canonical(CanonicalError::FormatUnavailable))
    );
    assert_eq!(window.record(), &record);
    assert!(matches!(
        window.prepare_response(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            &request,
            empty(),
            Bytes::new()
        ),
        Err(Error::Drop | Error::NoDurableWork)
    ));
    window.delete();
}

#[test]
fn same_process_replacement_cannot_reseal_a_discarded_canonical_reply() {
    let f = fixture(10_151);
    let original = record(&f, 0, false);
    let mut window = start(&f, &original);
    let request = f.request(0);
    window.reply_empty(&request).unwrap();
    drop(window); // Readback/reconciliation is not permanent SA deletion.
    let mut replacement = start(&f, &original);
    assert!(matches!(
        replacement.reply_empty(&request),
        Err(Error::Canonical(CanonicalError::AlreadyReleased))
    ));
    replacement.delete();
}

#[test]
fn authentication_direction_and_exchange_class_precede_empty_admission() {
    let f = fixture(10_152);
    let original = record(&f, 0, false);
    let mut window = start(&f, &original);
    for (response, exchange, payload) in [
        (true, 37, empty()),
        (false, 35, empty()),
        (false, 36, empty()),
        (false, 37, delete()),
    ] {
        let wire = f.peer(0, response, exchange, payload, 0, 800 + u64::from(exchange));
        let request = window.open_peer(f.profile, &f.keys, &wire).unwrap();
        assert!(matches!(window.reply_empty(&request), Err(Error::Drop)));
    }
    let other = fixture(10_153);
    assert!(matches!(
        window.reply_empty(&other.request(0)),
        Err(Error::Drop)
    ));
    let local = f.packet(f.direction, 0, false, 37, empty(), 0, 900);
    let good = f.peer(0, false, 37, empty(), 0, 901);
    let mut corrupt = good.to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    for wire in [local.as_ref(), corrupt.as_slice(), &[0xff]] {
        assert!(window.open_peer(f.profile, &f.keys, wire).is_err());
    }
    assert_eq!(window.record(), &original);
    assert_eq!(window.next_receive(), Some(0));
    window.reply_empty(&f.request(0)).unwrap();
    window.delete();
}

#[test]
fn cancelled_nonempty_commit_withholds_cached_empty_send_authority() {
    let mut f = fixture(10_160);
    let original = record(&f, 4, false);
    let mut window = start(&f, &original);
    let empty_request = f.request(20);
    window.reply_empty(&empty_request).unwrap();
    let request = work(&f, 30);
    let prepared = window
        .prepare_response(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            &request,
            empty(),
            Bytes::from_static(b"planned"),
        )
        .unwrap();
    let landed = prepared.record().clone();
    drop(prepared);
    assert_eq!(
        window.reply_empty(&empty_request).unwrap_err(),
        Error::CommitUncertain
    );
    assert_eq!(window.record(), &original);
    drop(window);
    let latest = Window::restore(landed.domain(), f.profile, &f.keys, &landed, &f.iv).unwrap();
    assert_eq!(
        latest.request_disposition(&request),
        Ok(Disposition::CachedResponse)
    );
    assert_eq!(latest.next_receive(), Some(31));
    latest.delete();
}

#[test]
fn newer_empty_request_retires_the_old_ordinary_response_from_the_live_window() {
    let mut f = fixture(10_161);
    let original = record(&f, 0, false);
    let mut window = start(&f, &original);
    let request = work(&f, 0);
    let prepared = window
        .prepare_response(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            &request,
            empty(),
            Bytes::from_static(b"once"),
        )
        .unwrap();
    let committed = prepared.record().clone();
    let _token = prepared.commit_after_durable(&committed).unwrap();
    assert_eq!(
        window.request_disposition(&request),
        Ok(Disposition::CachedResponse)
    );
    window.reply_empty(&f.request(1)).unwrap();
    assert_eq!(window.request_disposition(&request), Err(Error::Drop));
    // Durable outcome history stays unchanged. A restart can only know its
    // saved window, so the exact stored response remains usable after restore.
    assert_eq!(window.record(), &committed);
    let restored =
        Window::restore(committed.domain(), f.profile, &f.keys, &committed, &f.iv).unwrap();
    assert_eq!(
        restored.request_disposition(&request),
        Ok(Disposition::CachedResponse)
    );
    assert_eq!(
        restored.request_disposition(&work(&f, 1)),
        Ok(Disposition::New)
    );
    assert_eq!(restored.request_disposition(&request), Err(Error::Drop));
    window.delete();
}

#[test]
fn every_consumer_teardown_uses_delete_and_rekey_retains_the_old_epoch_until_deleted() {
    // The SDK does not own timers/transport. These exercise the common consuming
    // teardown hook after peer Delete, local expiry, DPD timeout and rekey cleanup.
    for cause in 0..4 {
        let mut f = fixture(10_170 + cause);
        let original = record(&f, 0, false);
        let mut window = start(&f, &original);
        let request = f.request(0);
        let bytes = window.reply_empty(&request).unwrap().bytes().to_vec();
        if cause == 0 {
            let request = work(&f, 1);
            let prepared = window
                .prepare_response(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    &request,
                    empty(),
                    Bytes::from_static(b"peer-delete"),
                )
                .unwrap();
            let committed = prepared.record().clone();
            let token = prepared.commit_after_durable(&committed).unwrap();
            assert_eq!(
                window.apply_committed(token).unwrap(),
                Some(Bytes::from_static(b"peer-delete"))
            );
        } else if cause == 1 || cause == 2 {
            let prepared = window
                .prepare_request(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    Exchange::Informational,
                    delete(),
                )
                .unwrap();
            if cause == 1 {
                // Expiry while an uncertain write requires fenced readback.
                drop(prepared);
                assert_eq!(window.ready(), Err(Error::CommitUncertain));
            } else {
                // DPD timeout with a durable outstanding local request.
                let committed = prepared.record().clone();
                let _commit = prepared.commit_after_durable(&committed).unwrap();
                assert!(window.record().outbound().unwrap().response().is_none());
                assert_eq!(window.ready(), Ok(()));
            }
        }
        let newer = fixture(10_180 + cause);
        let mut new_window = start(&newer, &record(&newer, 0, false));
        if cause == 3 {
            // New keys do not retire the old SA's permitted retransmissions.
            assert_eq!(window.reply_empty(&request).unwrap().bytes(), bytes);
        }
        window.delete();
        let mut old =
            Window::restore(original.domain(), f.profile, &f.keys, &original, &f.iv).unwrap();
        assert!(matches!(
            old.enable_empty_replies(Policy::default()),
            Err(Error::Canonical(CanonicalError::Invalidated))
        ));
        new_window.reply_empty(&newer.request(0)).unwrap();
        new_window.delete();
    }
}

#[test]
fn replay_lookup_does_not_admit_pending_work_or_change_sync_history() {
    // Review P1: a speculative replay query must not force scoped SA closure.
    let mut f = fixture(11_001);
    let original = record(&f, 4, true);
    let mut window = start(&f, &original);
    assert_eq!(
        window.replay_response(&work(&f, 4)).unwrap_err(),
        Error::Drop
    );
    let sync = peer_sync(&f, 4, 0);
    let prepared = window
        .begin_sync_response(f.profile, &f.keys, &sync, None, None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    assert_eq!(
        prepared.record().sync_state().unwrap().disposition(),
        SyncDisposition::Continue
    );
    assert_eq!(
        prepared
            .record()
            .sync_state()
            .unwrap()
            .highest_peer_request(),
        Some(3)
    );
    drop(prepared);
    window.delete();

    let f = fixture(11_002);
    let original = record(&f, 4, true);
    let mut window = start(&f, &original);
    assert_eq!(
        window.replay_response(&work(&f, 4)).unwrap_err(),
        Error::Drop
    );
    window.reply_empty(&f.request(4)).unwrap();
    let clock = Clock::new(100, 1);
    let policy = RecoveryPolicy::new(1, clock, 1000, 3, 10).unwrap();
    drop(window.begin_sync(policy, clock, None).unwrap());
    window.delete();
}

#[test]
fn failed_record_rebuild_requires_the_explicit_epoch_teardown_hook() {
    // Review P2: discriminate delete_epoch itself, without a Window::restore
    // failure that already retired the key. Consumer decoding can fail first.
    let mut f = fixture(11_010);
    let original = f.window.record().clone();
    let mut window = start(&f, &original);
    window.reply_empty(&f.request(0)).unwrap();
    drop(window);
    assert_eq!(
        Record::from_persisted(Domain::from_iv_record(&f.iv), 1, None, Some(0), None, None)
            .unwrap_err(),
        Error::InvalidRecord
    );
    let still_live = start(&f, &original);
    drop(still_live);
    Canonical::delete_epoch(&f.iv);
    assert_eq!(
        f.window.enable_empty_replies(Policy::default()),
        Err(Error::Canonical(CanonicalError::Invalidated))
    );
}

#[test]
fn invalid_window_restore_retires_the_epoch_without_consumer_cleanup() {
    // Review P3, strengthened by the required automatic failed-restore cleanup.
    for has_capability in [false, true] {
        let mut f = fixture(11_020 + u64::from(has_capability));
        let mut window = start(&f, f.window.record());
        window.reply_empty(&f.request(1)).unwrap();
        let mut retained = if has_capability {
            Some(window)
        } else {
            drop(window);
            None
        };
        let prepared = f
            .window
            .prepare_request(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                delete(),
            )
            .unwrap();
        let committed = prepared.record().clone();
        let _commit = prepared.commit_after_durable(&committed).unwrap();
        let behind = f.stored(Some(1), 0);
        assert_eq!(
            Window::restore(committed.domain(), f.profile, &f.keys, &committed, &behind)
                .unwrap_err(),
            Error::InvalidRecord
        );
        if let Some(window) = &mut retained {
            assert_eq!(
                window.reply_empty(&f.request(1)).unwrap_err(),
                Error::Canonical(CanonicalError::Invalidated)
            );
        }
        // No delete_epoch: a corrected record cannot resurrect a failed epoch.
        let mut restored =
            Window::restore(committed.domain(), f.profile, &f.keys, &committed, &f.iv).unwrap();
        assert_eq!(
            restored.enable_empty_replies(Policy::default()),
            Err(Error::Canonical(CanonicalError::Invalidated))
        );
    }
}

#[test]
fn enabling_empty_replies_after_restore_always_recovers_the_lost_prefix() {
    for next_is_empty in [false, true] {
        let f = fixture(11_030 + u64::from(next_is_empty));
        let original = record(&f, 4, false);
        let mut window = start(&f, &original);
        for id in 4..=6 {
            window.reply_empty(&f.request(id)).unwrap();
        }
        assert_eq!(window.record(), &original);
        drop(window);
        let mut restored =
            Window::restore(original.domain(), f.profile, &f.keys, &original, &f.iv).unwrap();
        // G1 / PD: a not-yet-enabled window admits no empty reply or lost prefix.
        // Those refusals leave the same runtime usable once enable succeeds.
        assert_eq!(
            restored.reply_empty(&f.request(7)).unwrap_err(),
            Error::EmptyRepliesDisabled
        );
        assert_eq!(restored.request_disposition(&work(&f, 7)), Err(Error::Drop));
        restored.enable_empty_replies(Policy::default()).unwrap();
        assert!(restored.is_reconstructing());
        if next_is_empty {
            assert_eq!(
                restored.reply_empty(&f.request(7)).unwrap().observation(),
                Observation::Uncertain
            );
            assert_eq!(restored.next_receive(), Some(8));
        } else {
            assert_eq!(
                restored.request_disposition(&work(&f, 7)),
                Ok(Disposition::New)
            );
        }
        restored.delete();
    }
}

#[test]
fn refused_empty_evaluation_still_blocks_changed_work_and_stale_sync() {
    // Review P5 / N4: in-process readback retains the ledger release flag.
    // Refusal still admits the identity and raises the RFC 6311 drop history.
    let mut f = fixture(11_040);
    let original = record(&f, 4, true);
    let mut window = start(&f, &original);
    let request = f.request(10);
    window.reply_empty(&request).unwrap();
    drop(window);
    let mut restored = start(&f, &original);
    assert_eq!(
        restored.reply_empty(&request).unwrap_err(),
        Error::Canonical(CanonicalError::AlreadyReleased)
    );
    assert_eq!(restored.next_receive(), Some(4));
    assert_eq!(
        restored.request_disposition(&work(&f, 10)),
        Err(Error::Drop)
    );
    assert!(matches!(
        restored.begin_sync_response(f.profile, &f.keys, &peer_sync(&f, 10, 0), None, None),
        Err(Error::Drop)
    ));
    let sync = peer_sync(&f, 11, 0);
    let prepared = restored
        .begin_sync_response(f.profile, &f.keys, &sync, None, None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    assert_eq!(
        prepared
            .record()
            .sync_state()
            .unwrap()
            .highest_peer_request(),
        Some(10)
    );
    assert_eq!(
        prepared.record().sync_state().unwrap().disposition(),
        SyncDisposition::Continue
    );
    drop(prepared);
    restored.delete();
}

#[test]
fn deleting_a_window_without_an_owned_capability_removes_the_live_epoch() {
    // Review P6: exercise the None arm of Window::delete on a retained ledger.
    let mut f = fixture(11_050);
    let mut window = start(&f, f.window.record());
    window.reply_empty(&f.request(0)).unwrap();
    drop(window);
    let record = f.window.record().clone();
    let restored = Window::restore(record.domain(), f.profile, &f.keys, &record, &f.iv).unwrap();
    restored.delete();
    assert_eq!(
        f.window.enable_empty_replies(Policy::default()),
        Err(Error::Canonical(CanonicalError::Invalidated))
    );
}

#[test]
fn empty_enable_is_once_only_without_revoking_the_owned_capability() {
    let f = fixture(11_060);
    let original = record(&f, 4, true);
    let mut window = start(&f, &original);
    assert_eq!(
        window.enable_empty_replies(Policy::default()),
        Err(Error::Canonical(CanonicalError::CapabilityActive))
    );
    window.reply_empty(&f.request(4)).unwrap();
    window.delete();
}

#[test]
fn refused_empty_enable_keeps_the_old_capability_and_succeeds_after_it_drops() {
    // G1 / PA: restoring before dropping the old runtime must not revoke it.
    let f = fixture(12_000);
    let original = record(&f, 4, false);
    let mut old = start(&f, &original);
    let request = f.request(4);
    let bytes = old.reply_empty(&request).unwrap().bytes().to_vec();
    let mut replacement =
        Window::restore(original.domain(), f.profile, &f.keys, &original, &f.iv).unwrap();
    assert_eq!(
        replacement.enable_empty_replies(Policy::default()),
        Err(Error::Canonical(CanonicalError::CapabilityActive))
    );
    assert_eq!(replacement.record(), &original);
    assert_eq!(replacement.ready(), Ok(()));
    assert_eq!(old.reply_empty(&request).unwrap().bytes(), bytes);
    drop(old);
    replacement.enable_empty_replies(Policy::default()).unwrap();
    assert!(replacement.is_reconstructing());
    replacement.reply_empty(&f.request(5)).unwrap();
    assert_eq!(replacement.next_receive(), Some(6));
    assert_eq!(replacement.record(), &original);
    replacement.delete();
}

#[test]
fn refused_empty_enable_succeeds_after_restored_sync_completes() {
    // G1 / PB: run the full restored initiator lifecycle, not a stand-in record.
    let mut f = fixture(12_001);
    let original = record(&f, 4, true);
    let mut window = start(&f, &original);
    let clock = Clock::new(100, 1);
    let policy = RecoveryPolicy::new(1, clock, 1000, 3, 10).unwrap();
    let prepared = window
        .begin_sync(policy, clock, None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let waiting = prepared.record().clone();
    let token = prepared.commit_after_durable(&waiting, clock).unwrap();
    assert!(matches!(
        window.release_sync_action(token, clock).unwrap(),
        SyncAction::SendRequest(_)
    ));
    drop(window);
    let mut restored =
        Window::restore(waiting.domain(), f.profile, &f.keys, &waiting, &f.iv).unwrap();
    assert_eq!(
        restored.enable_empty_replies(Policy::default()),
        Err(Error::SyncInProgress)
    );
    assert_eq!(
        restored.reply_empty(&f.request(4)).unwrap_err(),
        Error::SyncInProgress
    );
    assert_eq!(restored.record(), &waiting);

    let retry_clock = Clock::new(110, 1);
    let prepared = restored
        .retry_sync(retry_clock)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let retry = prepared.record().clone();
    let token = prepared.commit_after_durable(&retry, retry_clock).unwrap();
    assert!(matches!(
        restored.release_sync_action(token, retry_clock).unwrap(),
        SyncAction::SendRequest(_)
    ));
    let proposal = retry
        .sync_recovery()
        .unwrap()
        .pending()
        .unwrap()
        .notification();
    let mut payload = vec![0, 0, 0, 20, 0, 0, 0x40, 0x26];
    payload.extend_from_slice(&proposal.nonce());
    payload.extend_from_slice(&proposal.expected_recv_req_message_id().to_be_bytes());
    payload.extend_from_slice(&proposal.expected_send_req_message_id().to_be_bytes());
    let response = f.peer(
        0,
        true,
        37,
        PayloadChain::new(PayloadType::Notify, &payload),
        0,
        600,
    );
    let complete_clock = Clock::new(111, 1);
    let prepared = restored
        .complete_sync(f.profile, &f.keys, &response, complete_clock)
        .unwrap();
    let recovered = prepared.record().clone();
    let token = prepared
        .commit_after_durable(&recovered, complete_clock)
        .unwrap();
    assert!(matches!(
        restored.release_sync_action(token, complete_clock).unwrap(),
        SyncAction::Recovered
    ));
    assert_eq!(restored.ready(), Ok(()));
    restored.enable_empty_replies(Policy::default()).unwrap();
    assert!(!restored.is_reconstructing());
    let next = restored.next_receive().unwrap();
    assert_eq!(
        restored
            .reply_empty(&f.request(next))
            .unwrap()
            .observation(),
        Observation::Fresh
    );
    assert_eq!(restored.record(), &recovered);
    restored.delete();
}

#[test]
fn replay_lookup_drops_foreign_and_response_packets_before_work_classification() {
    let f = fixture(12_010);
    let foreign = fixture(12_011);
    let original = record(&f, 4, true);
    let window = Window::restore(original.domain(), f.profile, &f.keys, &original, &f.iv).unwrap();
    for request in [foreign.request(4), work(&foreign, 4)] {
        assert_eq!(window.replay_response(&request).unwrap_err(), Error::Drop);
    }
    for (index, payload) in [empty(), delete()].into_iter().enumerate() {
        let wire = f.peer(4, true, 37, payload, 0, 601 + index as u64);
        let response = window.open_peer(f.profile, &f.keys, &wire).unwrap();
        assert_eq!(window.replay_response(&response).unwrap_err(), Error::Drop);
    }
    assert_eq!(window.record(), &original);
    assert_eq!(
        window.request_disposition(&work(&f, 4)),
        Ok(Disposition::New)
    );
    window.delete();
}

#[test]
fn newer_admitted_work_retires_an_ordinary_cached_reply_without_a_write() {
    // Review P8: a newer pending request closes the prior response's live window.
    let mut f = fixture(11_070);
    let original = record(&f, 0, false);
    let mut window = start(&f, &original);
    let request = work(&f, 0);
    let prepared = window
        .prepare_response(
            f.profile,
            &f.keys,
            f.allocator.allocate(Purpose::Ordinary).unwrap(),
            &request,
            empty(),
            Bytes::from_static(b"once"),
        )
        .unwrap();
    let committed = prepared.record().clone();
    let _commit = prepared.commit_after_durable(&committed).unwrap();
    assert_eq!(
        window.replay_response(&request).unwrap().bytes(),
        committed.inbound().unwrap().response().unwrap()
    );
    assert_eq!(
        window.request_disposition(&work(&f, 1)),
        Ok(Disposition::New)
    );
    assert_eq!(window.replay_response(&request).unwrap_err(), Error::Drop);
    assert_eq!(window.record(), &committed);
    window.delete();
}

#[test]
fn repeated_empty_traffic_retires_old_ids_without_spending_ordinary_ivs() {
    let mut f = fixture(10_200);
    let original = record(&f, 0, false);
    let mut window = start(&f, &original);
    let iv_before = f.iv.clone();
    for id in 0..256 {
        let request = f.request(id);
        let bytes = window.reply_empty(&request).unwrap().bytes().to_vec();
        assert_eq!(window.reply_empty(&request).unwrap().bytes(), bytes);
        if id > 0 {
            assert!(matches!(
                window.reply_empty(&f.request(id - 1)),
                Err(Error::Drop)
            ));
        }
    }
    assert_eq!(window.record(), &original);
    assert_eq!(&f.iv, &iv_before);
    assert_eq!(window.next_receive(), Some(256));
    drop(window);
    f.window.enable_empty_replies(Policy::default()).unwrap();
    let retired = f.request(254);
    // Reconstruction cannot reopen an ID closed by the retained compacted ledger.
    assert!(matches!(
        f.window.reply_empty(&retired),
        Err(Error::Canonical(CanonicalError::AlreadyReleased))
    ));
    f.window.delete();
}

#[test]
fn real_process_restart_preserves_empty_bytes_without_durable_window_writes() {
    let mut first = None;
    for stage in ["before", "after"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "empty_restart_child", "--nocapture"])
            .env("OPC_EMPTY_RESTART_STAGE", stage)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{stage}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        let packets: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("EMPTY_BYTES:"))
            .map(str::to_owned)
            .collect();
        assert_eq!(packets.len(), 6);
        if let Some(first) = &first {
            assert_eq!(&packets, first);
        } else {
            first = Some(packets);
        }
    }
}

#[test]
fn empty_restart_child() {
    let Ok(stage) = std::env::var("OPC_EMPTY_RESTART_STAGE") else {
        return;
    };
    support::ensure_ike_crypto();
    for algorithm in ALGORITHMS {
        for direction in DIRECTIONS {
            let profile = canonical_fixtures::profile(algorithm);
            let keys = canonical_fixtures::key_material(profile, 10_300);
            let f = if stage == "before" {
                Fixture::from_keys(profile, keys, direction, canonical_fixtures::SPIS)
            } else {
                Fixture::from_persisted_keys(profile, keys, direction, canonical_fixtures::SPIS, 64)
            };
            let original = record(&f, 0, false);
            let mut window = start(&f, &original);
            let reply = window.reply_empty(&f.request(0)).unwrap();
            assert_eq!(reply.observation(), Observation::Uncertain);
            println!("EMPTY_BYTES:{:?}", reply.bytes());
            drop(reply);
            assert_eq!(window.record(), &original);
        }
    }
}
