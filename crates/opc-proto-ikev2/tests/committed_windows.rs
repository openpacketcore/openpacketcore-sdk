use bytes::Bytes;
use opc_proto_ikev2::{
    open_protected_payloads,
    recovery::{
        Ikev2CommittedExchangeRecord as ExchangeRecord, Ikev2CommittedWindow as Window,
        Ikev2CommittedWindowDomain as Domain, Ikev2CommittedWindowRecord as Record,
        Ikev2OrdinaryRequestDisposition as Disposition, Ikev2PreparedWindow as Prepared,
        Ikev2SyncDisposition as SyncDisposition, Ikev2SyncResponderRecord as SyncRecord,
        Ikev2WindowCommit as Commit, Ikev2WindowError as Error,
    },
    seal_ikev2_sa_init_protected_payload, Ikev2AesGcmIvAllocator as Allocator,
    Ikev2AesGcmIvLimits as Limits, Ikev2AesGcmIvPurpose as Purpose,
    Ikev2AesGcmIvRecord as IvRecord, Ikev2DhGroup, Ikev2EncryptionAlgorithm as Encryption,
    Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncAgreement as Agreement,
    Ikev2MessageIdSyncMode as Mode, Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa,
    Ikev2PrfAlgorithm, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys,
    Ikev2SaInitProtectedPayloadProvider as Provider, Message, PayloadChain, PayloadType,
    ProtectedPayloadKind, ProtectedPayloadSealContext,
};
use opc_protocol::{BorrowDecode, DecodeContext};

mod support;

const DIRECTIONS: [Direction; 2] = [
    Direction::InitiatorToResponder,
    Direction::ResponderToInitiator,
];
const ENCRYPTIONS: [Encryption; 3] = [
    Encryption::AesGcm16_128,
    Encryption::AesGcm16_192,
    Encryption::AesGcm16_256,
];
// A nonempty INFORMATIONAL Delete for the IKE SA, followed by an empty reply.
const DELETE: &[u8] = &[0, 0, 0, 8, 1, 0, 0, 0];
const TEMPORARY_FAILURE: &[u8] = &[0, 0, 0, 8, 0, 0, 0, 43];

fn profile(algorithm: Encryption) -> Profile {
    Profile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        algorithm,
    )
    .unwrap()
}

fn keys(profile: Profile, change: u8) -> Keys {
    let length = profile.encryption().key_material_len();
    Keys::from_established_keys(
        profile,
        false,
        &[0x11; 32],
        &[],
        &[],
        &vec![0x41 ^ change; length],
        &vec![0x62 ^ change; length],
        &[0x22; 32],
        &[0x33; 32],
    )
    .unwrap()
}

fn opposite(direction: Direction) -> Direction {
    if direction == DIRECTIONS[0] {
        DIRECTIONS[1]
    } else {
        DIRECTIONS[0]
    }
}

struct Fixture {
    profile: Profile,
    keys: Keys,
    direction: Direction,
    domain: Domain,
}

impl Fixture {
    fn new(algorithm: Encryption, direction: Direction) -> Self {
        support::ensure_ike_crypto();
        let profile = profile(algorithm);
        let keys = keys(profile, 0);
        let domain = Domain::new(0x101, 0x202, direction, profile, &keys).unwrap();
        Self {
            profile,
            keys,
            direction,
            domain,
        }
    }

    fn window(&self, send: u32, receive: u32) -> Window {
        self.restore(&Record::initial(self.domain.clone(), send, receive))
    }

    fn restore(&self, record: &Record) -> Window {
        // All ordinary fixture allocations come from the committed 32-position block.
        Window::restore(
            &self.domain,
            self.profile,
            &self.keys,
            record,
            &self.iv_record(32),
        )
        .unwrap()
    }

    fn iv_record(&self, exclusive_end: u64) -> IvRecord {
        IvRecord::from_persisted(
            self.domain.send_iv_domain().clone(),
            Limits::new(128, 2, 1, 2).unwrap(),
            exclusive_end,
        )
        .unwrap()
    }

    fn allocator(&self) -> Allocator {
        let mut allocator = Allocator::fresh(
            self.domain.send_iv_domain().clone(),
            Limits::new(128, 2, 1, 2).unwrap(),
        );
        let prepared = allocator.prepare(32, Purpose::Ordinary).unwrap();
        let durable = prepared.record().clone();
        prepared.activate_after_commit(&durable).unwrap();
        allocator
    }

    fn peer(
        &self,
        id: u32,
        response: bool,
        exchange: Exchange,
        payload: PayloadChain<'_>,
        iv: u64,
    ) -> Bytes {
        self.packet(
            opposite(self.direction),
            id,
            response,
            exchange,
            payload,
            iv,
        )
    }

    fn packet(
        &self,
        direction: Direction,
        id: u32,
        response: bool,
        exchange: Exchange,
        payload: PayloadChain<'_>,
        iv: u64,
    ) -> Bytes {
        self.packet_in_class(
            direction,
            id,
            response,
            (exchange.as_u8(), ProtectedPayloadKind::Encrypted),
            payload,
            iv,
        )
    }

    fn packet_in_class(
        &self,
        direction: Direction,
        id: u32,
        response: bool,
        class: (u8, ProtectedPayloadKind),
        payload: PayloadChain<'_>,
        iv: u64,
    ) -> Bytes {
        // Independent SK/SKF framing; the implementation must generate these
        // same authenticated header fields rather than trust a caller's header.
        let (exchange, kind) = class;
        let fragmented = kind == ProtectedPayloadKind::EncryptedFragment;
        let sk_length = 4 + 8 + payload.bytes().len() + 1 + 16 + if fragmented { 4 } else { 0 };
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&0x101_u64.to_be_bytes());
        prefix.extend_from_slice(&0x202_u64.to_be_bytes());
        prefix.extend_from_slice(&[
            if fragmented { 53 } else { 46 },
            0x20,
            exchange,
            (if direction == DIRECTIONS[0] { 8 } else { 0 }) | (if response { 32 } else { 0 }),
        ]);
        prefix.extend_from_slice(&id.to_be_bytes());
        prefix.extend_from_slice(&u32::try_from(28 + sk_length).unwrap().to_be_bytes());
        prefix.extend_from_slice(&[payload.first_payload().as_u8(), 0]);
        prefix.extend_from_slice(&u16::try_from(sk_length).unwrap().to_be_bytes());
        if fragmented {
            prefix.extend_from_slice(&[0, 1, 0, 2]);
        }
        let body = seal_ikev2_sa_init_protected_payload(
            self.profile,
            &self.keys,
            direction,
            ProtectedPayloadSealContext {
                kind,
                message_prefix: &prefix,
            },
            payload.bytes(),
            0,
            iv.to_be_bytes(),
        )
        .unwrap();
        prefix.extend_from_slice(&body);
        prefix.into()
    }
}

fn delete() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::Delete, DELETE)
}
fn empty() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::NoNext, &[])
}
fn temporary_failure() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::Notify, TEMPORARY_FAILURE)
}
fn commit(prepared: Prepared<'_>) -> (Record, Commit) {
    let record = prepared.record().clone();
    let effect = prepared.commit_after_durable(&record).unwrap();
    (record, effect)
}
fn iv(packet: &[u8]) -> u64 {
    u64::from_be_bytes(packet[32..40].try_into().unwrap())
}

fn window_agreement(fixture: &Fixture, mode: Mode) -> Agreement {
    let role = if fixture.direction == DIRECTIONS[0] {
        Role::Initiator
    } else {
        Role::Responder
    };
    Agreement::from_persisted(Sa::new(0x101, 0x202, role).unwrap(), mode)
}

#[test]
fn sync_metadata_round_trips_and_ordinary_commits_retain_request_history() {
    for direction in DIRECTIONS {
        let fixture = Fixture::new(ENCRYPTIONS[0], direction);
        let metadata = SyncRecord::from_persisted(
            window_agreement(&fixture, Mode::Negotiated),
            None,
            None,
            None,
            None,
            SyncDisposition::Continue,
            0,
        )
        .unwrap();
        let initial = Record::initial(fixture.domain.clone(), 0, 0)
            .with_sync_state(metadata)
            .unwrap();
        let mut window = fixture.restore(&initial);
        let mut allocator = fixture.allocator();
        let (record, _) = commit(
            window
                .prepare_request(
                    fixture.profile,
                    &fixture.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    Exchange::CreateChildSa,
                    delete(),
                )
                .unwrap(),
        );
        assert_eq!(
            record.sync_state().unwrap().highest_local_request(),
            Some(0)
        );
        assert_eq!(record.sync_state().unwrap().highest_peer_request(), None);
        let peer = fixture.peer(0, false, Exchange::Informational, delete(), 100);
        let peer = window
            .open_peer(fixture.profile, &fixture.keys, &peer)
            .unwrap();
        let (record, _) = commit(
            window
                .prepare_response(
                    fixture.profile,
                    &fixture.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    &peer,
                    empty(),
                    Bytes::from_static(b"committed"),
                )
                .unwrap(),
        );
        let state = record.sync_state().unwrap();
        assert_eq!(state.highest_local_request(), Some(0));
        assert_eq!(state.highest_peer_request(), Some(0));
        let rebuilt_state = SyncRecord::from_persisted(
            Agreement::from_persisted(state.agreement().sa(), state.agreement().mode()),
            state.highest_local_request(),
            state.highest_peer_request(),
            state.highest_local_proposal(),
            state.highest_peer_proposal(),
            state.disposition(),
            state.minimum_send_iv_end(),
        )
        .unwrap();
        let rebuilt = Record::from_persisted(
            record.domain().clone(),
            record.generation(),
            record.next_send(),
            record.next_receive(),
            record.outbound().cloned(),
            record.inbound().cloned(),
        )
        .unwrap()
        .with_sync_state(rebuilt_state)
        .unwrap();
        assert_eq!(fixture.restore(&rebuilt).record(), &record);
        assert!(record.clone().with_sync_state(rebuilt_state).is_err());
        let missing_history = SyncRecord::from_persisted(
            state.agreement(),
            None,
            None,
            None,
            None,
            SyncDisposition::Continue,
            0,
        )
        .unwrap();
        assert!(Record::from_persisted(
            record.domain().clone(),
            record.generation(),
            record.next_send(),
            record.next_receive(),
            record.outbound().cloned(),
            record.inbound().cloned(),
        )
        .unwrap()
        .with_sync_state(missing_history)
        .is_err());
    }
}

#[test]
fn sync_metadata_refuses_foreign_agreements_and_impossible_history() {
    let fixture = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[0]);
    for foreign in [
        Sa::new(0x999, 0x202, Role::Initiator).unwrap(),
        Sa::new(0x101, 0x202, Role::Responder).unwrap(),
    ] {
        let state = SyncRecord::from_persisted(
            Agreement::from_persisted(foreign, Mode::Negotiated),
            None,
            None,
            None,
            None,
            SyncDisposition::Continue,
            0,
        )
        .unwrap();
        assert!(matches!(
            Record::initial(fixture.domain.clone(), 0, 0).with_sync_state(state),
            Err(Error::DomainMismatch)
        ));
    }
    let agreement = window_agreement(&fixture, Mode::Negotiated);
    for (local, peer, local_proposal, peer_proposal) in [
        (Some(5), None, None, None),
        (None, Some(5), None, None),
        (None, None, Some(6), None),
        (None, None, None, Some(6)),
    ] {
        let state = SyncRecord::from_persisted(
            agreement,
            local,
            peer,
            local_proposal,
            peer_proposal,
            SyncDisposition::Continue,
            0,
        )
        .unwrap();
        let record =
            Record::from_persisted(fixture.domain.clone(), 1, Some(5), Some(5), None, None)
                .unwrap();
        assert!(matches!(
            record.with_sync_state(state),
            Err(Error::InvalidRecord)
        ));
    }
    assert!(SyncRecord::from_persisted(
        agreement,
        None,
        None,
        Some(u32::MAX),
        None,
        SyncDisposition::Continue,
        0,
    )
    .is_err());
    assert!(SyncRecord::from_persisted(
        agreement,
        None,
        None,
        None,
        Some(u32::MAX),
        SyncDisposition::Continue,
        0,
    )
    .is_err());
    assert!(SyncRecord::from_persisted(
        agreement,
        None,
        None,
        None,
        None,
        SyncDisposition::AwaitLocalSync,
        0,
    )
    .is_err());
    let fallback = window_agreement(&fixture, Mode::BaseFallback);
    assert!(SyncRecord::from_persisted(
        fallback,
        None,
        None,
        None,
        Some(1),
        SyncDisposition::Continue,
        0,
    )
    .is_err());
}

#[test]
fn restoring_sync_disposition_keeps_ordinary_work_and_replay_blocked() {
    let fixture = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[0]);
    for (disposition, expected) in [
        (SyncDisposition::AwaitLocalSync, Error::SyncInProgress),
        (SyncDisposition::OutcomeUncertain, Error::OutcomeUncertain),
    ] {
        let state = SyncRecord::from_persisted(
            window_agreement(&fixture, Mode::Negotiated),
            Some(1),
            Some(2),
            Some(3),
            Some(4),
            disposition,
            0,
        )
        .unwrap();
        let record =
            Record::from_persisted(fixture.domain.clone(), 1, Some(3), Some(4), None, None)
                .unwrap()
                .with_sync_state(state)
                .unwrap();
        let mut window = fixture.restore(&record);
        assert!(matches!(window.replay_request(), Err(error) if error == expected));
        let peer = fixture.peer(4, false, Exchange::Informational, delete(), 100);
        let peer = window
            .open_peer(fixture.profile, &fixture.keys, &peer)
            .unwrap();
        assert_eq!(window.request_disposition(&peer), Err(expected));
        let mut allocator = fixture.allocator();
        assert!(matches!(window.prepare_request(
            fixture.profile, &fixture.keys, allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational, delete(),
        ), Err(error) if error == expected));
        assert_eq!(window.record(), &record);
    }
}

#[test]
fn first_request_is_committed_before_replay_for_every_gcm_size_and_original_role() {
    for algorithm in ENCRYPTIONS {
        for direction in DIRECTIONS {
            let fixture = Fixture::new(algorithm, direction);
            let mut window = fixture.window(0, 0);
            let mut allocator = fixture.allocator();
            assert!(window.replay_request().unwrap().is_none());
            assert_eq!(window.record().next_send(), Some(0));
            let (record, effect) = commit(
                window
                    .prepare_request(
                        fixture.profile,
                        &fixture.keys,
                        allocator.allocate(Purpose::Ordinary).unwrap(),
                        Exchange::Informational,
                        delete(),
                    )
                    .unwrap(),
            );
            let expected =
                fixture.packet(direction, 0, false, Exchange::Informational, delete(), 0);
            assert_eq!(record.outbound().unwrap().request(), expected.as_ref());
            assert_eq!(
                window.replay_request().unwrap().unwrap().bytes(),
                expected.as_ref()
            );
            assert_eq!(window.record().next_send(), Some(1));
            assert_eq!(window.record().next_receive(), Some(0));
            assert_eq!(window.apply_committed(effect).unwrap(), None);
            for _ in 0..10 {
                assert_eq!(
                    window.replay_request().unwrap().unwrap().bytes(),
                    expected.as_ref()
                );
            }
            assert_eq!(
                fixture
                    .restore(&record)
                    .replay_request()
                    .unwrap()
                    .unwrap()
                    .bytes(),
                expected.as_ref()
            );
            assert!(matches!(
                window.prepare_request(
                    fixture.profile,
                    &fixture.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    Exchange::Informational,
                    delete(),
                ),
                Err(Error::RequestOutstanding)
            ));
        }
    }
}

#[test]
fn matching_authenticated_response_settles_once_and_probe_replay_never_repeats_an_outcome() {
    for direction in DIRECTIONS {
        let fixture = Fixture::new(ENCRYPTIONS[0], direction);
        let mut window = fixture.window(0, 0);
        let mut allocator = fixture.allocator();
        let (pending, _) = commit(
            window
                .prepare_request(
                    fixture.profile,
                    &fixture.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    Exchange::Informational,
                    delete(),
                )
                .unwrap(),
        );
        let request_bytes = pending.outbound().unwrap().request().to_vec();
        window = fixture.restore(&pending);
        for (id, exchange) in [(1, Exchange::Informational), (0, Exchange::CreateChildSa)] {
            let packet = fixture.peer(id, true, exchange, empty(), 50 + u64::from(id));
            let opened = window
                .open_peer(fixture.profile, &fixture.keys, &packet)
                .unwrap();
            assert!(matches!(
                window.prepare_completion(&opened, Bytes::from_static(b"wrong")),
                Err(Error::Drop)
            ));
        }
        let packet = fixture.peer(0, true, Exchange::Informational, empty(), 60);
        let opened = window
            .open_peer(fixture.profile, &fixture.keys, &packet)
            .unwrap();
        let (settled, effect) = commit(
            window
                .prepare_completion(&opened, Bytes::from_static(b"deleted"))
                .unwrap(),
        );
        assert_eq!(
            settled.outbound().unwrap().response(),
            Some(packet.as_ref())
        );
        assert_eq!(
            window.apply_committed(effect).unwrap().as_deref(),
            Some(b"deleted".as_slice())
        );
        assert!(matches!(
            window.prepare_completion(&opened, Bytes::from_static(b"again")),
            Err(Error::Drop)
        ));
        for _ in 0..10 {
            assert_eq!(
                window.replay_request().unwrap().unwrap().bytes(),
                request_bytes
            );
        }
        window = fixture.restore(&settled);
        let opened = window
            .open_peer(fixture.profile, &fixture.keys, &packet)
            .unwrap();
        assert!(matches!(
            window.prepare_completion(&opened, Bytes::new()),
            Err(Error::Drop)
        ));
        let (next, _) = commit(
            window
                .prepare_request(
                    fixture.profile,
                    &fixture.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    Exchange::Informational,
                    delete(),
                )
                .unwrap(),
        );
        assert_eq!(
            &next.outbound().unwrap().request()[20..24],
            &1_u32.to_be_bytes()
        );
        assert_eq!(iv(next.outbound().unwrap().request()), 1); // Replays allocated nothing.
    }
}

#[test]
fn dropped_or_mismatched_commit_quiesces_until_readback_without_sending_new_bytes() {
    let fixture = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[0]);
    let mut window = fixture.window(0, 0);
    let mut allocator = fixture.allocator();
    let old = window.record().clone();
    let prepared = window
        .prepare_request(
            fixture.profile,
            &fixture.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            delete(),
        )
        .unwrap();
    let candidate = prepared.record().clone();
    assert!(matches!(
        prepared.commit_after_durable(&old),
        Err(Error::CommitMismatch)
    ));
    assert!(matches!(
        window.replay_request(),
        Err(Error::CommitUncertain)
    ));
    assert_eq!(window.record(), &old);
    // Readback finds the write landed: exact replay, without constructing new bytes.
    window = fixture.restore(&candidate);
    assert_eq!(
        window.replay_request().unwrap().unwrap().bytes(),
        candidate.outbound().unwrap().request()
    );
    // Alternatively it did not land, and older writes have been fenced out.
    window = fixture.restore(&old);
    assert!(window.replay_request().unwrap().is_none());
    let prepared = window
        .prepare_request(
            fixture.profile,
            &fixture.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            delete(),
        )
        .unwrap();
    assert_eq!(iv(prepared.record().outbound().unwrap().request()), 1);
    drop(prepared); // Cancellation is uncertain, not an implicit abort acknowledgement.
    assert!(matches!(
        window.replay_request(),
        Err(Error::CommitUncertain)
    ));
    assert!(matches!(
        window.prepare_request(
            fixture.profile,
            &fixture.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            delete()
        ),
        Err(Error::CommitUncertain)
    ));
}

#[test]
fn inbound_window_is_strict_and_only_the_last_exact_authenticated_request_replays() {
    for direction in DIRECTIONS {
        let fixture = Fixture::new(ENCRYPTIONS[0], direction);
        let mut window = fixture.window(0, 5);
        let mut allocator = fixture.allocator();
        for id in [0, 4, 6, u32::MAX] {
            let packet = fixture.peer(id, false, Exchange::Informational, delete(), u64::from(id));
            let opened = window
                .open_peer(fixture.profile, &fixture.keys, &packet)
                .unwrap();
            assert_eq!(window.request_disposition(&opened), Err(Error::Drop));
        }
        let packet = fixture.peer(5, false, Exchange::Informational, delete(), 50);
        let opened = window
            .open_peer(fixture.profile, &fixture.keys, &packet)
            .unwrap();
        assert_eq!(
            window.request_disposition(&opened).unwrap(),
            Disposition::New
        );
        let (record, effect) = commit(
            window
                .prepare_response(
                    fixture.profile,
                    &fixture.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    &opened,
                    empty(),
                    Bytes::from_static(b"removed"),
                )
                .unwrap(),
        );
        assert_eq!(window.record().next_receive(), Some(6));
        assert_eq!(
            window.apply_committed(effect).unwrap().as_deref(),
            Some(b"removed".as_slice())
        );
        let expected = fixture.packet(direction, 5, true, Exchange::Informational, empty(), 0);
        window = fixture.restore(&record);
        let opened = window
            .open_peer(fixture.profile, &fixture.keys, &packet)
            .unwrap();
        assert_eq!(
            window.request_disposition(&opened).unwrap(),
            Disposition::CachedResponse
        );
        assert_eq!(
            window.replay_response(&opened).unwrap().bytes(),
            expected.as_ref()
        );
        let changed = fixture.peer(5, false, Exchange::Informational, delete(), 51);
        let changed = window
            .open_peer(fixture.profile, &fixture.keys, &changed)
            .unwrap();
        assert_eq!(window.request_disposition(&changed), Err(Error::Drop));
        assert!(matches!(window.replay_response(&changed), Err(Error::Drop)));
        let next = fixture.peer(6, false, Exchange::Informational, delete(), 52);
        let next = window
            .open_peer(fixture.profile, &fixture.keys, &next)
            .unwrap();
        let _ = commit(
            window
                .prepare_response(
                    fixture.profile,
                    &fixture.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    &next,
                    empty(),
                    Bytes::new(),
                )
                .unwrap(),
        );
        assert_eq!(window.request_disposition(&opened), Err(Error::Drop));
        assert_eq!(iv(window.replay_response(&next).unwrap().bytes()), 1);
    }
}

#[test]
fn neither_success_nor_error_response_is_released_before_its_outcome_commit() {
    for payload in [empty(), temporary_failure()] {
        let fixture = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[1]);
        let mut window = fixture.window(0, 0);
        let mut allocator = fixture.allocator();
        let old = window.record().clone();
        let packet = fixture.peer(0, false, Exchange::Informational, delete(), 90);
        let opened = window
            .open_peer(fixture.profile, &fixture.keys, &packet)
            .unwrap();
        let prepared = window
            .prepare_response(
                fixture.profile,
                &fixture.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
                &opened,
                payload,
                Bytes::from_static(b"planned"),
            )
            .unwrap();
        let landed = prepared.record().clone();
        drop(prepared);
        assert!(matches!(
            window.replay_response(&opened),
            Err(Error::CommitUncertain)
        ));
        assert_eq!(window.record().next_receive(), Some(0));
        window = fixture.restore(&old);
        assert_eq!(
            window.request_disposition(&opened).unwrap(),
            Disposition::New
        );
        window = fixture.restore(&landed);
        assert_eq!(
            window.request_disposition(&opened).unwrap(),
            Disposition::CachedResponse
        );
        assert_eq!(
            window.replay_response(&opened).unwrap().bytes(),
            landed.inbound().unwrap().response().unwrap()
        );
    }
}

#[test]
fn authentication_sa_direction_framing_and_sync_class_precede_window_admission() {
    let fixture = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[0]);
    let window = fixture.window(0, 0);
    let good = fixture.peer(0, false, Exchange::Informational, delete(), 100);
    for offset in [0, 8, 17, 19, 24, 28, 32, good.len() - 1] {
        let mut corrupt = good.to_vec();
        corrupt[offset] ^= 1;
        assert!(window
            .open_peer(fixture.profile, &fixture.keys, &corrupt)
            .is_err());
    }
    let wrong_direction = fixture.packet(
        fixture.direction,
        0,
        false,
        Exchange::Informational,
        delete(),
        100,
    );
    assert!(window
        .open_peer(fixture.profile, &fixture.keys, &wrong_direction)
        .is_err());
    let mut trailing = good.to_vec();
    trailing.push(0);
    assert!(window
        .open_peer(fixture.profile, &fixture.keys, &trailing)
        .is_err());
    let foreign = keys(fixture.profile, 1);
    assert!(window.open_peer(fixture.profile, &foreign, &good).is_err());
    for response in [false, true] {
        // Include malformed and non-sole sync Notifies: no ambiguous ordinary ID 0.
        for data in [
            vec![
                0, 0, 0, 20, 0, 0, 0x40, 0x26, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            vec![0, 0, 0, 8, 0, 0, 0x40, 0x26],
            vec![42, 0, 0, 8, 0, 0, 0x40, 0x26, 0, 0, 0, 8, 1, 0, 0, 0],
        ] {
            let packet = fixture.peer(
                0,
                response,
                Exchange::Informational,
                PayloadChain::new(PayloadType::Notify, &data),
                101,
            );
            assert!(matches!(
                window.open_peer(fixture.profile, &fixture.keys, &packet),
                Err(Error::Drop)
            ));
        }
    }
    assert_eq!(window.record().next_receive(), Some(0));
}

#[test]
fn stateless_empty_requests_cannot_create_a_durable_probe_or_reservation() {
    let fixture = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[0]);
    let mut window = fixture.window(0, 0);
    let mut allocator = fixture.allocator();
    assert!(matches!(
        window.prepare_request(
            fixture.profile,
            &fixture.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            empty()
        ),
        Err(Error::NoDurableWork)
    ));
    assert!(window.replay_request().unwrap().is_none());
    let packet = fixture.peer(0, false, Exchange::Informational, empty(), 110);
    let opened = window
        .open_peer(fixture.profile, &fixture.keys, &packet)
        .unwrap();
    assert_eq!(
        window.request_disposition(&opened),
        Err(Error::NoDurableWork)
    );
    assert_eq!(window.record().next_send(), Some(0));
    assert_eq!(window.record().next_receive(), Some(0));
}

#[test]
fn exhausted_message_id_directions_remain_explicit_and_cached_max_can_replay() {
    for direction in DIRECTIONS {
        let fixture = Fixture::new(ENCRYPTIONS[0], direction);
        let mut window = fixture.window(u32::MAX, u32::MAX);
        let mut allocator = fixture.allocator();
        let _ = commit(
            window
                .prepare_request(
                    fixture.profile,
                    &fixture.keys,
                    allocator.allocate(Purpose::Control).unwrap(),
                    Exchange::Informational,
                    delete(),
                )
                .unwrap(),
        );
        let answer = fixture.peer(u32::MAX, true, Exchange::Informational, empty(), 120);
        let answer = window
            .open_peer(fixture.profile, &fixture.keys, &answer)
            .unwrap();
        let _ = commit(window.prepare_completion(&answer, Bytes::new()).unwrap());
        assert_eq!(window.record().next_send(), None);
        assert!(matches!(
            window.prepare_request(
                fixture.profile,
                &fixture.keys,
                allocator.allocate(Purpose::Control).unwrap(),
                Exchange::Informational,
                delete()
            ),
            Err(Error::Exhausted)
        ));
        let request = fixture.peer(u32::MAX, false, Exchange::Informational, delete(), 121);
        let request = window
            .open_peer(fixture.profile, &fixture.keys, &request)
            .unwrap();
        let (record, _) = commit(
            window
                .prepare_response(
                    fixture.profile,
                    &fixture.keys,
                    allocator.allocate(Purpose::Control).unwrap(),
                    &request,
                    empty(),
                    Bytes::new(),
                )
                .unwrap(),
        );
        window = fixture.restore(&record);
        assert_eq!(window.record().next_receive(), None);
        assert_eq!(
            window.request_disposition(&request).unwrap(),
            Disposition::CachedResponse
        );
        let zero = fixture.peer(0, false, Exchange::Informational, delete(), 122);
        let zero = window
            .open_peer(fixture.profile, &fixture.keys, &zero)
            .unwrap();
        assert_eq!(window.request_disposition(&zero), Err(Error::Drop));
    }
}

#[test]
fn restore_checks_both_key_domains_counters_and_exact_response_identity() {
    let fixture = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[0]);
    let mut window = fixture.window(0, 0);
    let mut allocator = fixture.allocator();
    let (record, _) = commit(
        window
            .prepare_request(
                fixture.profile,
                &fixture.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                delete(),
            )
            .unwrap(),
    );
    for domain in [
        Domain::new(0x999, 0x202, DIRECTIONS[0], fixture.profile, &fixture.keys).unwrap(),
        Domain::new(0x101, 0x202, DIRECTIONS[1], fixture.profile, &fixture.keys).unwrap(),
        Domain::new(
            0x101,
            0x202,
            DIRECTIONS[0],
            fixture.profile,
            &keys(fixture.profile, 1),
        )
        .unwrap(),
    ] {
        assert!(Window::restore(
            &domain,
            fixture.profile,
            &fixture.keys,
            &record,
            &fixture.iv_record(32)
        )
        .is_err());
    }
    let invalid = Record::from_persisted(
        fixture.domain.clone(),
        record.generation(),
        Some(0),
        Some(0),
        record.outbound().cloned(),
        None,
    )
    .unwrap();
    assert!(Window::restore(
        &fixture.domain,
        fixture.profile,
        &fixture.keys,
        &invalid,
        &fixture.iv_record(32)
    )
    .is_err());
    let wrong_response = fixture.peer(1, true, Exchange::Informational, empty(), 130);
    let exchange = ExchangeRecord::from_persisted(
        Bytes::copy_from_slice(record.outbound().unwrap().request()),
        Some(wrong_response),
        Some(Bytes::new()),
    )
    .unwrap();
    let invalid = Record::from_persisted(
        fixture.domain.clone(),
        record.generation(),
        Some(1),
        Some(0),
        Some(exchange),
        None,
    )
    .unwrap();
    assert!(Window::restore(
        &fixture.domain,
        fixture.profile,
        &fixture.keys,
        &invalid,
        &fixture.iv_record(32)
    )
    .is_err());
    assert!(ExchangeRecord::from_persisted(Bytes::new(), Some(Bytes::new()), None).is_err());
    let exhausted_generation = Record::from_persisted(
        fixture.domain.clone(),
        u64::MAX,
        Some(0),
        Some(0),
        None,
        None,
    )
    .unwrap();
    let mut window = fixture.restore(&exhausted_generation);
    assert!(matches!(
        window.prepare_request(
            fixture.profile,
            &fixture.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            delete()
        ),
        Err(Error::Exhausted)
    ));
}

#[test]
fn restore_requires_iv_high_water_above_every_locally_sent_cached_iv() {
    for algorithm in ENCRYPTIONS {
        for direction in DIRECTIONS {
            let fixture = Fixture::new(algorithm, direction);
            // Include pending/settled requests, IV zero, either cache alone, and
            // both possible orders of the two local IVs. Peer IVs are independent.
            for (request_iv, response_iv, settled) in [
                (Some(0), None, false),
                (Some(7), None, true),
                (None, Some(0), false),
                (None, Some(7), false),
                (Some(7), Some(3), true),
                (Some(3), Some(7), true),
            ] {
                let outbound = request_iv.map(|iv| {
                    ExchangeRecord::from_persisted(
                        fixture.packet(direction, 0, false, Exchange::Informational, delete(), iv),
                        settled
                            .then(|| fixture.peer(0, true, Exchange::Informational, empty(), 1000)),
                        settled.then(Bytes::new),
                    )
                    .unwrap()
                });
                let inbound = response_iv.map(|iv| {
                    ExchangeRecord::from_persisted(
                        fixture.peer(0, false, Exchange::Informational, delete(), 1001),
                        Some(fixture.packet(
                            direction,
                            0,
                            true,
                            Exchange::Informational,
                            empty(),
                            iv,
                        )),
                        Some(Bytes::new()),
                    )
                    .unwrap()
                });
                let record = Record::from_persisted(
                    fixture.domain.clone(),
                    1,
                    Some(u32::from(outbound.is_some())),
                    Some(u32::from(inbound.is_some())),
                    outbound,
                    inbound,
                )
                .unwrap();
                let highest = request_iv.into_iter().chain(response_iv).max().unwrap();
                for end in [0, highest.saturating_sub(1), highest] {
                    assert!(
                        matches!(
                            Window::restore(
                                &fixture.domain,
                                fixture.profile,
                                &fixture.keys,
                                &record,
                                &fixture.iv_record(end),
                            ),
                            Err(Error::InvalidRecord)
                        ),
                        "cached IV {highest} is not covered by exclusive end {end}"
                    );
                }
                let restored = Window::restore(
                    &fixture.domain,
                    fixture.profile,
                    &fixture.keys,
                    &record,
                    &fixture.iv_record(highest + 1),
                )
                .unwrap();
                assert_eq!(restored.record(), &record);
            }
        }
    }
}

#[test]
fn restore_accepts_unused_epoch_but_rejects_foreign_iv_records() {
    for direction in DIRECTIONS {
        let fixture = Fixture::new(ENCRYPTIONS[0], direction);
        let record = Record::initial(fixture.domain.clone(), 0, 0);
        assert!(Window::restore(
            &fixture.domain,
            fixture.profile,
            &fixture.keys,
            &record,
            &fixture.iv_record(0),
        )
        .is_ok());
        for foreign in [
            Domain::new(0x999, 0x202, direction, fixture.profile, &fixture.keys).unwrap(),
            Domain::new(
                0x101,
                0x202,
                opposite(direction),
                fixture.profile,
                &fixture.keys,
            )
            .unwrap(),
            Domain::new(
                0x101,
                0x202,
                direction,
                fixture.profile,
                &keys(fixture.profile, 1),
            )
            .unwrap(),
        ] {
            let iv_record = IvRecord::from_persisted(
                foreign.send_iv_domain().clone(),
                fixture.iv_record(0).limits(),
                32,
            )
            .unwrap();
            assert!(matches!(
                Window::restore(
                    &fixture.domain,
                    fixture.profile,
                    &fixture.keys,
                    &record,
                    &iv_record,
                ),
                Err(Error::DomainMismatch)
            ));
        }
    }
}

#[test]
fn open_peer_refuses_authenticated_skf_and_every_nonordinary_exchange_type() {
    for direction in DIRECTIONS {
        let fixture = Fixture::new(ENCRYPTIONS[0], direction);
        let window = fixture.window(0, 7);
        for kind in [
            ProtectedPayloadKind::Encrypted,
            ProtectedPayloadKind::EncryptedFragment,
        ] {
            for exchange in 0..=u8::MAX {
                let wire = fixture.packet_in_class(
                    opposite(direction),
                    7,
                    false,
                    (exchange, kind),
                    delete(),
                    100,
                );
                // Authenticate each fixture first: refusal must discriminate packet
                // class, not a bad tag or inconsistent SKF framing. Unsupported
                // exchange headers deliberately make no handshake-semantic claim.
                let (tail, message) = Message::decode(&wire, DecodeContext::default()).unwrap();
                assert!(tail.is_empty());
                let provider = Provider::new(fixture.profile, &fixture.keys, opposite(direction));
                let opened =
                    open_protected_payloads(&message, &wire, DecodeContext::default(), &provider)
                        .unwrap();
                assert_eq!(opened.len(), 1);
                assert_eq!(opened[0].kind, kind);
                assert_eq!(opened[0].cleartext.as_ref(), DELETE);
                let result = window.open_peer(fixture.profile, &fixture.keys, &wire);
                if kind == ProtectedPayloadKind::Encrypted && matches!(exchange, 35..=37) {
                    assert!(result.is_ok());
                } else {
                    assert!(
                        matches!(result, Err(Error::Drop)),
                        "accepted {kind:?}, exchange {exchange}"
                    );
                }
                assert_eq!(window.record().next_receive(), Some(7));
            }
        }
    }
}

#[test]
fn completion_tokens_are_fenced_by_runtime_instance_and_later_commit_generation() {
    let fixture = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[0]);
    let mut window = fixture.window(0, 0);
    let mut allocator = fixture.allocator();
    let packet = fixture.peer(0, false, Exchange::Informational, delete(), 140);
    let opened = window
        .open_peer(fixture.profile, &fixture.keys, &packet)
        .unwrap();
    let (record, old_runtime) = commit(
        window
            .prepare_response(
                fixture.profile,
                &fixture.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
                &opened,
                empty(),
                Bytes::from_static(b"secret-outcome"),
            )
            .unwrap(),
    );
    let mut restored = fixture.restore(&record);
    assert!(matches!(
        restored.apply_committed(old_runtime),
        Err(Error::StaleCompletion)
    ));
    let packet = fixture.peer(1, false, Exchange::Informational, delete(), 141);
    let opened = window
        .open_peer(fixture.profile, &fixture.keys, &packet)
        .unwrap();
    let (_, old_generation) = commit(
        window
            .prepare_response(
                fixture.profile,
                &fixture.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
                &opened,
                empty(),
                Bytes::from_static(b"secret-outcome"),
            )
            .unwrap(),
    );
    let _ = commit(
        window
            .prepare_request(
                fixture.profile,
                &fixture.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                delete(),
            )
            .unwrap(),
    );
    assert!(matches!(
        window.apply_committed(old_generation),
        Err(Error::StaleCompletion)
    ));
    for diagnostic in [
        format!("{window:?}"),
        format!("{record:?}"),
        format!("{opened:?}"),
    ] {
        assert!(!diagnostic.contains("secret-outcome"));
        assert!(!diagnostic.contains("257"));
        assert!(!diagnostic.contains("[65"));
    }
}

#[test]
fn changing_only_the_peer_key_still_invalidates_the_window_domain() {
    for direction in DIRECTIONS {
        let fixture = Fixture::new(ENCRYPTIONS[0], direction);
        let record = Record::initial(fixture.domain.clone(), 0, 0);
        let ei = [if direction == DIRECTIONS[1] {
            0x42
        } else {
            0x41
        }; 20];
        let er = [if direction == DIRECTIONS[0] {
            0x63
        } else {
            0x62
        }; 20];
        let changed = Keys::from_established_keys(
            fixture.profile,
            false,
            &[0x11; 32],
            &[],
            &[],
            &ei,
            &er,
            &[0x22; 32],
            &[0x33; 32],
        )
        .unwrap();
        let changed_domain =
            Domain::new(0x101, 0x202, direction, fixture.profile, &changed).unwrap();
        assert_eq!(
            fixture.domain.send_iv_domain(),
            changed_domain.send_iv_domain()
        );
        assert_ne!(fixture.domain, changed_domain);
        assert!(matches!(
            Window::restore(
                &fixture.domain,
                fixture.profile,
                &changed,
                &record,
                &fixture.iv_record(32)
            ),
            Err(Error::DomainMismatch)
        ));
    }
}

#[test]
fn foreign_allocations_and_outbound_sync_or_malformed_payloads_create_no_window_state() {
    let fixture = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[0]);
    let foreign = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[1]);
    let mut wrong_allocator = foreign.allocator();
    let mut window = fixture.window(0, 0);
    let original = window.record().clone();
    assert!(matches!(
        window.prepare_request(
            fixture.profile,
            &fixture.keys,
            wrong_allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::Informational,
            delete()
        ),
        Err(Error::Iv(_))
    ));
    let mut allocator = fixture.allocator();
    let sync = [
        0, 0, 0, 20, 0, 0, 0x40, 0x26, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    for payload in [
        PayloadChain::new(PayloadType::Notify, &sync),
        PayloadChain::new(PayloadType::Delete, &[0, 0, 0, 100]),
        PayloadChain::new(PayloadType::NoNext, DELETE),
    ] {
        assert!(matches!(
            window.prepare_request(
                fixture.profile,
                &fixture.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                payload
            ),
            Err(Error::Drop)
        ));
        assert_eq!(window.record(), &original);
        assert!(window.replay_request().unwrap().is_none());
    }
    let packet = fixture.peer(0, false, Exchange::Informational, delete(), 150);
    let opened = window
        .open_peer(fixture.profile, &fixture.keys, &packet)
        .unwrap();
    assert!(matches!(
        window.prepare_response(
            fixture.profile,
            &fixture.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
            &opened,
            PayloadChain::new(PayloadType::Notify, &sync),
            Bytes::new()
        ),
        Err(Error::Drop)
    ));
    assert_eq!(window.record(), &original);
}

#[test]
fn unacknowledged_response_settlement_is_pending_until_readback_and_never_repeats_success() {
    let fixture = Fixture::new(ENCRYPTIONS[0], DIRECTIONS[0]);
    let mut window = fixture.window(0, 0);
    let mut allocator = fixture.allocator();
    let (pending, _) = commit(
        window
            .prepare_request(
                fixture.profile,
                &fixture.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::Informational,
                delete(),
            )
            .unwrap(),
    );
    let packet = fixture.peer(0, true, Exchange::Informational, empty(), 160);
    let response = window
        .open_peer(fixture.profile, &fixture.keys, &packet)
        .unwrap();
    let prepared = window
        .prepare_completion(&response, Bytes::from_static(b"success"))
        .unwrap();
    let settled = prepared.record().clone();
    drop(prepared);
    assert!(window.record().outbound().unwrap().response().is_none());
    assert!(matches!(
        window.replay_request(),
        Err(Error::CommitUncertain)
    ));
    // Definitive absence leaves pending work; a subsequent committed result is once-only.
    window = fixture.restore(&pending);
    let (_, completion) = commit(
        window
            .prepare_completion(&response, Bytes::from_static(b"success"))
            .unwrap(),
    );
    assert_eq!(
        window.apply_committed(completion).unwrap().as_deref(),
        Some(b"success".as_slice())
    );
    // A landed but unacknowledged result is restored history, never a new completion.
    window = fixture.restore(&settled);
    assert!(matches!(
        window.prepare_completion(&response, Bytes::from_static(b"success")),
        Err(Error::Drop)
    ));
    assert_eq!(
        window.replay_request().unwrap().unwrap().bytes(),
        pending.outbound().unwrap().request()
    );
}
