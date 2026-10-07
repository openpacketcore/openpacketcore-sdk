use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{
        Ikev2CommittedWindow as Window, Ikev2CommittedWindowDomain as Domain,
        Ikev2CommittedWindowRecord as Record, Ikev2PreparedSyncInitiation as Prepared,
        Ikev2SyncAttemptRecord as Attempt, Ikev2SyncClock as Clock,
        Ikev2SyncDisposition as Disposition, Ikev2SyncInitiatorAction as Action,
        Ikev2SyncInitiatorCommit as Commit, Ikev2SyncRecoveryPolicy as Policy,
        Ikev2SyncRecoveryRecord as Recovery, Ikev2SyncRecoveryStatus as Status,
        Ikev2SyncResponderRecord as SyncRecord, Ikev2WindowError as Error,
    },
    seal_ikev2_sa_init_protected_payload, Header, HeaderFlags, Ikev2AesGcmIvAllocator as Allocator,
    Ikev2AesGcmIvLimits as Limits, Ikev2AesGcmIvPurpose as Purpose,
    Ikev2AesGcmIvRecord as IvRecord, Ikev2DhGroup, Ikev2EncryptionAlgorithm as Encryption,
    Ikev2ExchangeKind as Exchange, Ikev2MessageIdSync as Sync,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncPending as Pending, Ikev2MessageIdSyncRole as Role,
    Ikev2MessageIdSyncSa as Sa, Ikev2PrfAlgorithm, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys, PayloadChain, PayloadType,
    ProtectedPayloadKind as Kind, ProtectedPayloadSealContext,
};

mod support;

const ROLES: [Role; 2] = [Role::Initiator, Role::Responder];
const ENCRYPTIONS: [Encryption; 3] = [
    Encryption::AesGcm16_128,
    Encryption::AesGcm16_192,
    Encryption::AesGcm16_256,
];

fn clock(time: u64) -> Clock {
    Clock::new(time, 7)
}
fn policy() -> Policy {
    Policy::new(42, clock(100), 200, 3, 10).unwrap()
}
fn sync_payload(value: Sync) -> Bytes {
    let mut bytes = vec![0, 0, 0, 20, 0, 0, 0x40, 0x26];
    bytes.extend_from_slice(&value.nonce());
    bytes.extend_from_slice(&value.expected_send_req_message_id().to_be_bytes());
    bytes.extend_from_slice(&value.expected_recv_req_message_id().to_be_bytes());
    bytes.into()
}

struct Fixture {
    profile: Profile,
    keys: Keys,
    domain: Domain,
    agreement: Agreement,
    role: Role,
}
impl Fixture {
    fn new(algorithm: Encryption, role: Role) -> Self {
        support::ensure_ike_crypto();
        let profile = Profile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2DhGroup::Ecp256,
            algorithm,
        )
        .unwrap();
        let length = profile.encryption().key_material_len();
        let keys = Keys::from_established_keys(
            profile,
            false,
            &[0x11; 32],
            &[],
            &[],
            &vec![0x41; length],
            &vec![0x62; length],
            &[0x22; 32],
            &[0x33; 32],
        )
        .unwrap();
        let direction = if role == Role::Initiator {
            Direction::InitiatorToResponder
        } else {
            Direction::ResponderToInitiator
        };
        Self {
            domain: Domain::new(0x101, 0x202, direction, profile, &keys).unwrap(),
            agreement: Agreement::from_persisted(
                Sa::new(0x101, 0x202, role).unwrap(),
                Mode::Negotiated,
            ),
            profile,
            keys,
            role,
        }
    }
    fn record(
        &self,
        send: u32,
        receive: u32,
        proposed: Option<u32>,
        disposition: Disposition,
    ) -> Record {
        Record::from_persisted(
            self.domain.clone(),
            1,
            Some(send),
            Some(receive),
            None,
            None,
        )
        .unwrap()
        .with_sync_state(
            SyncRecord::from_persisted(self.agreement, None, None, proposed, None, disposition, 0)
                .unwrap(),
        )
        .unwrap()
    }
    fn iv_record(&self, end: u64) -> IvRecord {
        IvRecord::from_persisted(
            self.domain.send_iv_domain().clone(),
            Limits::new(128, 2, 1, 2).unwrap(),
            end,
        )
        .unwrap()
    }
    fn restore(&self, record: &Record, end: u64) -> Result<Window, Error> {
        Window::restore(
            &self.domain,
            self.profile,
            &self.keys,
            record,
            &self.iv_record(end),
        )
    }
    fn header(&self, peer: bool, exchange: Exchange, id: u32, response: bool) -> Header {
        Header::new(
            0x101,
            0x202,
            PayloadType::Encrypted,
            exchange.as_u8(),
            HeaderFlags::from_bits((self.role == Role::Initiator) != peer, response, false),
            id,
        )
    }
    fn wire(&self, header: Header, payloads: PayloadChain<'_>, kind: Kind, iv: u64) -> Bytes {
        let fragmented = kind == Kind::EncryptedFragment;
        let length = 4 + if fragmented { 4 } else { 0 } + 8 + payloads.bytes().len() + 1 + 16;
        let mut wire = Vec::new();
        wire.extend_from_slice(&header.initiator_spi.to_be_bytes());
        wire.extend_from_slice(&header.responder_spi.to_be_bytes());
        wire.extend_from_slice(&[
            if fragmented { 53 } else { 46 },
            0x20,
            header.exchange_type,
            header.flags.raw(),
        ]);
        wire.extend_from_slice(&header.message_id.to_be_bytes());
        wire.extend_from_slice(&u32::try_from(28 + length).unwrap().to_be_bytes());
        wire.extend_from_slice(&[payloads.first_payload().as_u8(), 0]);
        wire.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
        if fragmented {
            wire.extend_from_slice(&[0, 1, 0, 2]);
        }
        let direction = if header.flags.initiator() {
            Direction::InitiatorToResponder
        } else {
            Direction::ResponderToInitiator
        };
        let body = seal_ikev2_sa_init_protected_payload(
            self.profile,
            &self.keys,
            direction,
            ProtectedPayloadSealContext {
                kind,
                message_prefix: &wire,
            },
            payloads.bytes(),
            0,
            iv.to_be_bytes(),
        )
        .unwrap();
        wire.extend_from_slice(&body);
        wire.into()
    }
    fn attempt(&self, m1: u32, p1: u32, nonce: [u8; 4], iv: u64, time: u64) -> Attempt {
        let notification = Sync::new(nonce, m1, p1);
        let pending = Pending::from_persisted(self.agreement.sa(), notification).unwrap();
        let bytes = self.wire(
            self.header(false, Exchange::Informational, 0, false),
            PayloadChain::new(PayloadType::Notify, &sync_payload(notification)),
            Kind::Encrypted,
            iv,
        );
        Attempt::from_persisted(pending, time, bytes).unwrap()
    }
}

#[test]
fn persisted_policy_and_history_are_bounded_without_refunding_an_attempt() {
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Initiator);
    let first = f.attempt(3, 4, [1; 4], 0, 100);
    let second = f.attempt(5, 7, [2; 4], 2, 110);
    let recovery = Recovery::from_persisted(
        policy(),
        115,
        vec![first.clone(), second.clone()],
        Status::Pending,
    )
    .unwrap();
    assert_eq!(recovery.policy(), policy());
    assert_eq!(recovery.attempts(), &[first.clone(), second.clone()]);
    assert_eq!(recovery.pending(), Some(second.pending()));
    assert_eq!(recovery.last_observed_unix_ms(), 115);
    assert_eq!(recovery.status(), Status::Pending);
    assert_eq!(policy().operation(), 42);
    assert_eq!(policy().started(), clock(100));
    assert_eq!(policy().deadline_unix_ms(), 200);
    assert_eq!(policy().max_attempts(), 3);
    assert_eq!(policy().retry_delay_ms(), 10);
    assert_eq!(clock(100).unix_ms(), 100);
    assert_eq!(clock(100).epoch(), 7);
    for (deadline, count, delay) in [
        (100, 3, 10),
        (99, 3, 10),
        (200, 0, 10),
        (200, 4, 10),
        (200, 3, 0),
    ] {
        assert_eq!(
            Policy::new(42, clock(100), deadline, count, delay),
            Err(Error::InvalidRecord)
        );
    }
    for attempts in [
        vec![],
        vec![first.clone(), first.clone()],
        vec![first.clone(), f.attempt(5, 7, [1; 4], 2, 110)],
        vec![first.clone(), f.attempt(3, 7, [2; 4], 2, 110)],
        vec![first.clone(), f.attempt(5, 3, [2; 4], 2, 110)],
        vec![first.clone(), f.attempt(5, 7, [2; 4], 2, 109)],
        vec![f.attempt(3, 4, [1; 4], 0, 99)],
        vec![f.attempt(3, 4, [1; 4], 0, 200)],
        vec![
            first.clone(),
            second.clone(),
            f.attempt(6, 7, [3; 4], 3, 120),
            f.attempt(7, 7, [4; 4], 4, 130),
        ],
    ] {
        assert_eq!(
            Recovery::from_persisted(policy(), 150, attempts, Status::Pending),
            Err(Error::InvalidRecord)
        );
    }
    assert_eq!(
        Recovery::from_persisted(policy(), 109, vec![first, second], Status::Pending),
        Err(Error::InvalidRecord)
    );
    assert_eq!(
        Recovery::from_persisted(policy(), 200, recovery.attempts().to_vec(), Status::Pending),
        Err(Error::InvalidRecord)
    );
    let closed =
        Recovery::from_persisted(policy(), 200, recovery.attempts().to_vec(), Status::Closed)
            .unwrap();
    assert_eq!(closed.pending(), None);
    assert_eq!(format!("{recovery:?}"), "Ikev2SyncRecoveryRecord { .. }");
    assert_eq!(
        format!("{:?}", recovery.attempts()[0]),
        "Ikev2SyncAttemptRecord { .. }"
    );
}

#[test]
fn pending_restore_binds_history_floors_packet_nonce_and_reserved_iv() {
    for algorithm in ENCRYPTIONS {
        for role in ROLES {
            let f = Fixture::new(algorithm, role);
            let first = f.attempt(3, 4, [1; 4], 0, 100);
            let second = f.attempt(5, 7, [2; 4], 3, 110);
            let recovery = Recovery::from_persisted(
                policy(),
                110,
                vec![first.clone(), second.clone()],
                Status::Pending,
            )
            .unwrap();
            let base = f.record(5, 7, Some(5), Disposition::AwaitLocalSync);
            let record = base.clone().with_sync_recovery(recovery.clone()).unwrap();
            let window = f.restore(&record, 4).unwrap();
            assert_eq!(window.record().sync_recovery(), Some(&recovery));
            assert!(matches!(
                window.replay_request(),
                Err(Error::SyncInProgress)
            ));
            for end in [0, 1, 3] {
                assert!(matches!(f.restore(&record, end), Err(Error::InvalidRecord)));
            }
            assert_eq!(
                record.clone().with_sync_recovery(recovery.clone()),
                Err(Error::InvalidRecord)
            );
            for invalid in [
                f.record(5, 7, Some(5), Disposition::Continue),
                f.record(5, 6, Some(5), Disposition::AwaitLocalSync),
                f.record(6, 7, Some(6), Disposition::AwaitLocalSync),
            ] {
                assert_eq!(
                    invalid.with_sync_recovery(recovery.clone()),
                    Err(Error::InvalidRecord)
                );
            }
            for bad_attempt in [
                f.attempt(5, 7, [2; 4], 0, 110), // Reused IV despite a distinct proposal.
                Attempt::from_persisted(
                    second.pending(),
                    110,
                    first.request_bytes().to_vec().into(),
                )
                .unwrap(),
                Attempt::from_persisted(second.pending(), 110, {
                    let mut bytes = second.request_bytes().to_vec();
                    *bytes.last_mut().unwrap() ^= 1;
                    bytes.into()
                })
                .unwrap(),
            ] {
                let invalid = Recovery::from_persisted(
                    policy(),
                    110,
                    vec![first.clone(), bad_attempt],
                    Status::Pending,
                )
                .unwrap();
                let invalid = base.clone().with_sync_recovery(invalid).unwrap();
                assert!(matches!(f.restore(&invalid, 8), Err(Error::InvalidRecord)));
            }
            let other_sa = Sa::new(0x303, 0x202, role).unwrap();
            let foreign =
                Pending::from_persisted(other_sa, second.pending().notification()).unwrap();
            let foreign =
                Attempt::from_persisted(foreign, 110, second.request_bytes().to_vec().into())
                    .unwrap();
            let foreign =
                Recovery::from_persisted(policy(), 110, vec![foreign], Status::Pending).unwrap();
            assert!(base.clone().with_sync_recovery(foreign).is_err());
            let restored = Record::from_persisted(
                record.domain().clone(),
                record.generation(),
                record.next_send(),
                record.next_receive(),
                None,
                None,
            )
            .unwrap()
            .with_sync_state(*record.sync_state().unwrap())
            .unwrap()
            .with_sync_recovery(
                Recovery::from_persisted(
                    recovery.policy(),
                    recovery.last_observed_unix_ms(),
                    recovery.attempts().to_vec(),
                    recovery.status(),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(f.restore(&restored, 4).unwrap().record(), &record);
        }
    }
}

#[test]
fn completed_and_closed_restore_never_create_a_fresh_completion() {
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Responder);
    for (status, disposition) in [
        (Status::Recovered, Disposition::Continue),
        (Status::Closed, Disposition::CloseIkeSa),
    ] {
        let attempt = f.attempt(3, 4, [1; 4], 0, 100);
        let state = Recovery::from_persisted(policy(), 110, vec![attempt], status).unwrap();
        assert_eq!(state.pending(), None);
        let record = f
            .record(3, 4, Some(3), disposition)
            .with_sync_recovery(state)
            .unwrap();
        let window = f.restore(&record, 1).unwrap();
        if status == Status::Closed {
            assert!(matches!(window.replay_request(), Err(Error::SyncClosed)));
        } else {
            assert!(matches!(window.replay_request(), Ok(None)));
        }
    }
}

const DELETE: &[u8] = &[0, 0, 0, 8, 1, 0, 0, 0];
fn delete() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::Delete, DELETE)
}
fn commit(prepared: Prepared<'_>) -> (Record, Commit) {
    let record = prepared.record().clone();
    // The synthetic store acknowledges in the same clock tick unless a test
    // explicitly supplies a delayed/discontinuous acknowledgement below.
    let now = record
        .sync_recovery()
        .map(|recovery| {
            Clock::new(
                recovery.last_observed_unix_ms(),
                recovery.policy().started().epoch(),
            )
        })
        .unwrap_or(clock(100));
    let token = prepared.commit_after_durable(&record, now).unwrap();
    (record, token)
}
fn release(window: &mut Window, token: Commit, time: u64) -> Bytes {
    match window.release_sync_action(token, clock(time)).unwrap() {
        Action::SendRequest(bytes) => bytes,
        other => panic!("expected request, got {other:?}"),
    }
}
impl Fixture {
    fn start(&self, send: u32, receive: u32) -> (Window, Allocator) {
        let mut allocator = Allocator::fresh(
            self.domain.send_iv_domain().clone(),
            self.iv_record(0).limits(),
        );
        let prepared = allocator.prepare(8, Purpose::Ordinary).unwrap();
        let iv_record = prepared.record().clone();
        prepared.activate_after_commit(&iv_record).unwrap();
        (
            self.restore(&self.record(send, receive, None, Disposition::Continue), 8)
                .unwrap(),
            allocator,
        )
    }
    fn propose(&self, window: &mut Window, allocator: &mut Allocator, time: u64) -> Bytes {
        let admitted = if window.record().sync_recovery().is_none() {
            window.begin_sync(policy(), clock(time), None).unwrap()
        } else {
            window.retry_sync(clock(time)).unwrap()
        };
        let prepared = admitted
            .prepare(
                self.profile,
                &self.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
            )
            .unwrap();
        let (_, token) = commit(prepared);
        release(window, token, time)
    }
    fn response(&self, value: Sync) -> Bytes {
        self.wire(
            self.header(true, Exchange::Informational, 0, true),
            PayloadChain::new(PayloadType::Notify, &sync_payload(value)),
            Kind::Encrypted,
            100,
        )
    }
    fn ordinary(&self, id: u32) -> Bytes {
        self.wire(
            self.header(true, Exchange::Informational, id, false),
            delete(),
            Kind::Encrypted,
            101,
        )
    }
    fn respond(&self, window: &mut Window, allocator: &mut Allocator, wire: &[u8]) -> Bytes {
        let prepared = window
            .begin_sync_response(self.profile, &self.keys, wire, None, None)
            .unwrap()
            .prepare(
                self.profile,
                &self.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
            )
            .unwrap();
        let record = prepared.record().clone();
        let token = prepared.commit_after_durable(&record).unwrap();
        window.release_sync_response(token).unwrap().into_parts().0
    }
    fn complete(&self, window: &mut Window, wire: &[u8], time: u64) {
        let (_, token) = commit(
            window
                .complete_sync(self.profile, &self.keys, wire, clock(time))
                .unwrap(),
        );
        assert!(matches!(
            window.release_sync_action(token, clock(time)).unwrap(),
            Action::Recovered
        ));
    }
}

#[test]
fn admitted_entropy_proposals_commit_before_send_and_result_before_ordinary_resume() {
    for algorithm in ENCRYPTIONS {
        for role in ROLES {
            let f = Fixture::new(algorithm, role);
            let (mut window, mut allocator) = f.start(2, 3);
            let request = f.propose(&mut window, &mut allocator, 100);
            assert_eq!(
                window.record().sync_state().unwrap().minimum_send_iv_end(),
                1
            );
            let state = window.record().sync_recovery().unwrap();
            let proposal = state.pending().unwrap().notification();
            assert_eq!(
                (
                    proposal.expected_send_req_message_id(),
                    proposal.expected_recv_req_message_id()
                ),
                (2, 3)
            );
            assert_eq!(state.attempts().len(), 1);
            assert_eq!(state.attempts()[0].request_bytes(), request.as_ref());
            assert_eq!(
                request,
                f.wire(
                    f.header(false, Exchange::Informational, 0, false),
                    PayloadChain::new(PayloadType::Notify, &sync_payload(proposal)),
                    Kind::Encrypted,
                    0
                )
            );
            for id in [2, 3, 4] {
                let ordinary = window
                    .open_peer(f.profile, &f.keys, &f.ordinary(id))
                    .unwrap();
                assert_eq!(
                    window.request_disposition(&ordinary),
                    Err(Error::SyncInProgress)
                );
            }
            assert!(matches!(
                window.replay_request(),
                Err(Error::SyncInProgress)
            ));
            assert!(matches!(
                window.begin_sync(
                    Policy::new(43, clock(101), 300, 3, 10).unwrap(),
                    clock(101),
                    None
                ),
                Err(Error::SyncInProgress)
            ));
            let response = f.response(Sync::new(proposal.nonce(), 7, 8));
            let prepared = window
                .complete_sync(f.profile, &f.keys, &response, clock(102))
                .unwrap();
            assert_eq!(
                prepared.record().sync_recovery().unwrap().status(),
                Status::Recovered
            );
            let (record, token) = commit(prepared);
            assert_eq!(record.sync_state().unwrap().minimum_send_iv_end(), 1);
            assert_eq!(
                (record.next_send(), record.next_receive()),
                (Some(8), Some(7))
            );
            assert!(record.outbound().is_none() && record.inbound().is_none());
            assert!(matches!(
                window.release_sync_action(token, clock(102)).unwrap(),
                Action::Recovered
            ));
            assert!(matches!(
                window.complete_sync(f.profile, &f.keys, &response, clock(103)),
                Err(Error::Drop)
            ));
            let restored = f.restore(&record, 8).unwrap();
            for id in [6, 7, 8] {
                let ordinary = restored
                    .open_peer(f.profile, &f.keys, &f.ordinary(id))
                    .unwrap();
                assert_eq!(restored.request_disposition(&ordinary).is_ok(), id == 7);
            }
            assert!(matches!(
                window.begin_sync(policy(), clock(110), None),
                Err(Error::Drop)
            ));
            let next_event = Policy::new(43, clock(110), 200, 2, 10).unwrap();
            let admitted = window.begin_sync(next_event, clock(110), None).unwrap();
            let prepared = admitted
                .prepare(
                    f.profile,
                    &f.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap();
            assert_eq!(
                prepared
                    .record()
                    .sync_recovery()
                    .unwrap()
                    .policy()
                    .operation(),
                43
            );
            assert_eq!(
                prepared.record().sync_recovery().unwrap().attempts().len(),
                1
            );
        }
    }
}

#[test]
fn request_and_response_loss_require_higher_fresh_proposals_with_three_total_attempts() {
    for deliver_request in [false, true] {
        let f = Fixture::new(Encryption::AesGcm16_128, Role::Initiator);
        let peer = Fixture::new(Encryption::AesGcm16_128, Role::Responder);
        let (mut window, mut allocator) = f.start(2, 3);
        let (mut peer_window, mut peer_allocator) = peer.start(3, 2);
        let mut replies = Vec::new();
        let mut previous: Option<Sync> = None;
        for attempt in 0..3 {
            let time = 100 + attempt * 10;
            let wire = f.propose(&mut window, &mut allocator, time);
            let state = window.record().sync_recovery().unwrap();
            assert_eq!(
                state.attempts().len(),
                usize::try_from(attempt + 1).unwrap()
            );
            let value = state.pending().unwrap().notification();
            if let Some(old) = previous {
                assert!(value.expected_send_req_message_id() > old.expected_send_req_message_id());
                assert_ne!(value.nonce(), old.nonce());
            }
            previous = Some(value);
            assert!(matches!(
                window.retry_sync(clock(time + 9)),
                Err(Error::SyncBackoff)
            ));
            if deliver_request {
                replies.push(peer.respond(&mut peer_window, &mut peer_allocator, &wire));
                assert!(matches!(
                    peer_window.begin_sync_response(peer.profile, &peer.keys, &wire, None, None),
                    Err(Error::Drop)
                ));
            } else {
                replies.push(f.response(Sync::new(
                    value.nonce(),
                    3,
                    value.expected_send_req_message_id(),
                )));
            }
            for old in &replies[..replies.len() - 1] {
                assert!(matches!(
                    window.complete_sync(f.profile, &f.keys, old, clock(time + 9)),
                    Err(Error::Drop)
                ));
            }
        }
        assert!(matches!(
            window.retry_sync(clock(130)),
            Err(Error::SyncClosed)
        ));
        assert!(matches!(
            window.complete_sync(f.profile, &f.keys, &replies[2], clock(131)),
            Err(Error::SyncClosed)
        ));
        let (closed, token) = commit(window.close_sync().unwrap());
        assert!(matches!(
            window.release_sync_action(token, clock(132)).unwrap(),
            Action::CloseIkeSa
        ));
        assert_eq!(
            closed.sync_state().unwrap().agreement().mode(),
            Mode::Negotiated
        );
        assert_eq!(closed.sync_recovery().unwrap().attempts().len(), 3);
        let mut restored = f.restore(&closed, 8).unwrap();
        assert!(matches!(
            restored.retry_sync(clock(140)),
            Err(Error::SyncClosed)
        ));
        assert!(matches!(
            restored.begin_sync(policy(), clock(140), None),
            Err(Error::SyncClosed)
        ));
        let peer_request = f.wire(
            f.header(true, Exchange::Informational, 0, false),
            PayloadChain::new(
                PayloadType::Notify,
                &sync_payload(Sync::new([9; 4], 20, 20)),
            ),
            Kind::Encrypted,
            102,
        );
        assert!(matches!(
            restored.begin_sync_response(f.profile, &f.keys, &peer_request, None, None),
            Err(Error::SyncClosed)
        ));
    }
}

#[test]
fn uncertain_restore_discards_send_permission_and_preserves_every_consumed_attempt() {
    let f = Fixture::new(Encryption::AesGcm16_256, Role::Responder);
    let (mut window, mut allocator) = f.start(2, 3);
    let original = window.record().clone();
    let prepared = window
        .begin_sync(policy(), clock(100), None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let candidate = prepared.record().clone();
    drop(prepared);
    assert!(matches!(
        window.replay_request(),
        Err(Error::CommitUncertain)
    ));
    assert!(f
        .restore(&original, 8)
        .unwrap()
        .record()
        .sync_recovery()
        .is_none());
    let mut restored = f.restore(&candidate, 8).unwrap();
    let value = candidate
        .sync_recovery()
        .unwrap()
        .pending()
        .unwrap()
        .notification();
    let old_response = f.response(Sync::new(value.nonce(), 3, 2));
    assert!(matches!(
        restored.complete_sync(f.profile, &f.keys, &old_response, clock(101)),
        Err(Error::Drop)
    ));
    for (time, expected_count, end) in [(110, 2, 8), (120, 3, 16)] {
        let mut fresh_allocator =
            Allocator::restore(f.domain.send_iv_domain(), &f.iv_record(end)).unwrap();
        let block = fresh_allocator.prepare(8, Purpose::Ordinary).unwrap();
        let iv_record = block.record().clone();
        block.activate_after_commit(&iv_record).unwrap();
        let wire = f.propose(&mut restored, &mut fresh_allocator, time);
        let record = restored.record().clone();
        assert_eq!(
            record.sync_recovery().unwrap().attempts().len(),
            expected_count
        );
        assert!(
            record
                .sync_recovery()
                .unwrap()
                .pending()
                .unwrap()
                .notification()
                .expected_send_req_message_id()
                > value.expected_send_req_message_id()
        );
        assert_eq!(&wire[32..40], &end.to_be_bytes());
        restored = f.restore(&record, end + 8).unwrap();
    }
    assert!(matches!(
        restored.retry_sync(clock(130)),
        Err(Error::SyncClosed)
    ));
    let (mut window, mut allocator) = f.start(2, 3);
    let prepared = window
        .begin_sync(policy(), clock(100), None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let (record, token) = commit(prepared);
    let value = record
        .sync_recovery()
        .unwrap()
        .pending()
        .unwrap()
        .notification();
    let reply = f.response(Sync::new(value.nonce(), 3, 2));
    assert!(matches!(
        window.complete_sync(f.profile, &f.keys, &reply, clock(101)),
        Err(Error::Drop)
    ));
    let mut restored = f.restore(&record, 8).unwrap();
    assert!(matches!(
        restored.release_sync_action(token, clock(101)),
        Err(Error::StaleCompletion)
    ));
    let prepared = restored
        .retry_sync(clock(110))
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        prepared.commit_after_durable(&record, clock(110)),
        Err(Error::CommitMismatch)
    ));
    assert!(matches!(
        restored.retry_sync(clock(120)),
        Err(Error::CommitUncertain)
    ));
}

#[test]
fn authenticated_wrong_responses_do_not_mutate_history_or_reset_the_deadline() {
    for role in ROLES {
        let f = Fixture::new(Encryption::AesGcm16_128, role);
        let (mut window, mut allocator) = f.start(2, 3);
        f.propose(&mut window, &mut allocator, 100);
        let before = window.record().clone();
        let proposal = before
            .sync_recovery()
            .unwrap()
            .pending()
            .unwrap()
            .notification();
        let mut wrong_nonce = proposal.nonce();
        wrong_nonce[0] ^= 1;
        let mut invalid = vec![
            f.response(Sync::new(wrong_nonce, 3, 2)),
            f.response(Sync::new(proposal.nonce(), 2, 2)),
            f.response(Sync::new(proposal.nonce(), 3, 1)),
        ];
        let payload = sync_payload(Sync::new(proposal.nonce(), 3, 2));
        let correct_header = f.header(true, Exchange::Informational, 0, true);
        for (peer, exchange, id, response) in [
            (false, Exchange::Informational, 0, true),
            (true, Exchange::IkeAuth, 0, true),
            (true, Exchange::CreateChildSa, 0, true),
            (true, Exchange::Informational, 1, true),
            (true, Exchange::Informational, 0, false),
        ] {
            invalid.push(f.wire(
                f.header(peer, exchange, id, response),
                PayloadChain::new(PayloadType::Notify, &payload),
                Kind::Encrypted,
                100,
            ));
        }
        let mut foreign = correct_header.clone();
        foreign.responder_spi += 1;
        invalid.push(f.wire(
            foreign,
            PayloadChain::new(PayloadType::Notify, &payload),
            Kind::Encrypted,
            100,
        ));
        invalid.push(f.wire(
            correct_header.clone(),
            PayloadChain::new(PayloadType::Notify, &payload),
            Kind::EncryptedFragment,
            100,
        ));
        let mut extra = payload.to_vec();
        extra[0] = PayloadType::Notify.as_u8();
        extra.extend_from_slice(&payload);
        invalid.push(f.wire(
            correct_header.clone(),
            PayloadChain::new(PayloadType::Notify, &extra),
            Kind::Encrypted,
            100,
        ));
        let mut esp = payload.to_vec();
        esp[7] = 0x27;
        invalid.push(f.wire(
            correct_header.clone(),
            PayloadChain::new(PayloadType::Notify, &esp),
            Kind::Encrypted,
            100,
        ));
        invalid.push(f.wire(correct_header, delete(), Kind::Encrypted, 100));
        let correct = f.response(Sync::new(proposal.nonce(), 3, 2));
        let mut tail = correct.to_vec();
        tail.push(0);
        invalid.push(tail.into());
        let mut tag = correct.to_vec();
        *tag.last_mut().unwrap() ^= 1;
        invalid.push(tag.into());
        invalid.push(correct[..correct.len() - 1].to_vec().into());
        for packet in invalid {
            assert!(matches!(
                window.complete_sync(f.profile, &f.keys, &packet, clock(101)),
                Err(Error::Drop)
            ));
            assert_eq!(window.record(), &before);
        }
        f.complete(&mut window, &correct, 102);
    }
}

#[test]
fn clock_steps_rollback_deadline_and_backoff_overflow_close_without_extending_budget() {
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Initiator);
    for sample in [
        Clock::new(105, 8),
        Clock::new(99, 8),
        Clock::new(150, 8),
        clock(104),
        clock(200),
    ] {
        let (mut window, mut allocator) = f.start(2, 3);
        f.propose(&mut window, &mut allocator, 100);
        let pending = window.record().clone();
        window.check_sync_deadline(clock(105)).unwrap();
        assert_eq!(window.check_sync_deadline(sample), Err(Error::SyncClosed));
        assert!(matches!(
            window.retry_sync(clock(110)),
            Err(Error::SyncClosed)
        ));
        let (closed, token) = commit(window.close_sync().unwrap());
        assert_eq!(closed.sync_recovery().unwrap().policy(), policy());
        assert!(matches!(
            window.release_sync_action(token, clock(111)).unwrap(),
            Action::CloseIkeSa
        ));
        let mut restored = f.restore(&closed, 8).unwrap();
        assert_eq!(
            restored.check_sync_deadline(clock(110)),
            Err(Error::SyncClosed)
        );
        if sample.epoch() != 7 || sample.unix_ms() >= 200 {
            let mut old = f.restore(&pending, 8).unwrap();
            assert_eq!(old.check_sync_deadline(sample), Err(Error::SyncClosed));
        }
    }
    let (mut window, mut allocator) = f.start(2, 3);
    let prepared = window
        .begin_sync(policy(), clock(100), None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let (_, token) = commit(prepared);
    assert!(matches!(
        window.release_sync_action(token, clock(200)),
        Err(Error::SyncClosed)
    ));
    assert!(matches!(window.replay_request(), Err(Error::SyncClosed)));
    let (mut window, mut allocator) = f.start(2, 3);
    let late = Policy::new(42, clock(u64::MAX - 20), u64::MAX, 3, 30).unwrap();
    let prepared = window
        .begin_sync(late, clock(u64::MAX - 20), None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let (_, token) = commit(prepared);
    release(&mut window, token, u64::MAX - 20);
    assert!(matches!(
        window.retry_sync(clock(u64::MAX - 1)),
        Err(Error::SyncClosed)
    ));
}

#[test]
fn local_initiation_requires_resolved_mutations_and_never_revives_old_completions() {
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Initiator);
    let (mut window, mut allocator) = f.start(2, 3);
    let inbound = window
        .open_peer(f.profile, &f.keys, &f.ordinary(3))
        .unwrap();
    let before = window.record().clone();
    assert!(matches!(
        window.begin_sync(policy(), clock(100), Some(&inbound)),
        Err(Error::RequestOutstanding)
    ));
    assert_eq!(window.record(), &before);
    let prepared = window
        .prepare_request(
            f.profile,
            &f.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
            Exchange::CreateChildSa,
            delete(),
        )
        .unwrap();
    let ordinary = prepared.record().clone();
    let old_commit = prepared.commit_after_durable(&ordinary).unwrap();
    assert!(matches!(
        window.begin_sync(policy(), clock(100), None),
        Err(Error::RequestOutstanding)
    ));
    let response = f.wire(
        f.header(true, Exchange::CreateChildSa, 2, true),
        delete(),
        Kind::Encrypted,
        100,
    );
    let opened = window.open_peer(f.profile, &f.keys, &response).unwrap();
    let prepared = window
        .prepare_completion(&opened, Bytes::from_static(b"settled"))
        .unwrap();
    let settled = prepared.record().clone();
    let outcome = prepared.commit_after_durable(&settled).unwrap();
    f.propose(&mut window, &mut allocator, 100);
    assert!(matches!(
        window.apply_committed(old_commit),
        Err(Error::StaleCompletion)
    ));
    assert!(matches!(
        window.apply_committed(outcome),
        Err(Error::StaleCompletion)
    ));
    assert!(window.record().outbound().is_none() && window.record().inbound().is_none());
}

#[test]
fn simultaneous_runtime_cutovers_converge_in_both_response_orders() {
    for role in ROLES {
        for reverse in [false, true] {
            let other = if role == Role::Initiator {
                Role::Responder
            } else {
                Role::Initiator
            };
            let a = Fixture::new(Encryption::AesGcm16_192, role);
            let b = Fixture::new(Encryption::AesGcm16_192, other);
            let (mut aw, mut ai) = a.start(4, 4);
            let (mut bw, mut bi) = b.start(5, 5);
            let ar = a.propose(&mut aw, &mut ai, 100);
            let br = b.propose(&mut bw, &mut bi, 100);
            let response_to_a = b.respond(&mut bw, &mut bi, &ar);
            let response_to_b = a.respond(&mut aw, &mut ai, &br);
            for window in [&aw, &bw] {
                assert_eq!(
                    (window.record().next_send(), window.record().next_receive()),
                    (Some(5), Some(5))
                );
                assert_eq!(
                    window.record().sync_state().unwrap().disposition(),
                    Disposition::AwaitLocalSync
                );
                assert_eq!(window.record().sync_recovery().unwrap().policy(), policy());
                assert!(matches!(
                    window.replay_request(),
                    Err(Error::SyncInProgress)
                ));
            }
            if reverse {
                b.complete(&mut bw, &response_to_b, 101);
                a.complete(&mut aw, &response_to_a, 101);
            } else {
                a.complete(&mut aw, &response_to_a, 101);
                b.complete(&mut bw, &response_to_b, 101);
            }
            for window in [&aw, &bw] {
                assert_eq!(
                    (window.record().next_send(), window.record().next_receive()),
                    (Some(5), Some(5))
                );
                assert_eq!(
                    window.record().sync_recovery().unwrap().status(),
                    Status::Recovered
                );
            }
            for (f, window) in [(&a, &aw), (&b, &bw)] {
                for id in [4, 5, 6] {
                    let opened = window
                        .open_peer(f.profile, &f.keys, &f.ordinary(id))
                        .unwrap();
                    assert_eq!(window.request_disposition(&opened).is_ok(), id == 5);
                }
            }
        }
    }
}

#[test]
fn withheld_real_proposal_can_arrive_after_completion_without_rolling_back() {
    for declared in [5, 8] {
        // Equality M1=P2 and the reviewed M1<P2 window.
        let a = Fixture::new(Encryption::AesGcm16_128, Role::Initiator);
        let b = Fixture::new(Encryption::AesGcm16_128, Role::Responder);
        let (mut aw, mut ai) = a.start(4, declared);
        let (mut bw, mut bi) = b.start(5, 5);
        let ar = a.propose(&mut aw, &mut ai, 100);
        let br = b.propose(&mut bw, &mut bi, 100);
        let response_to_a = b.respond(&mut bw, &mut bi, &ar);
        a.complete(&mut aw, &response_to_a, 101);
        assert_eq!(aw.record().next_receive(), Some(declared));
        let response_to_b = a.respond(&mut aw, &mut ai, &br);
        assert_eq!(aw.record().next_receive(), Some(declared));
        b.complete(&mut bw, &response_to_b, 102);
        assert_eq!(
            (bw.record().next_send(), bw.record().next_receive()),
            (Some(declared), Some(5))
        );
        assert_eq!(
            aw.record().sync_recovery().unwrap().status(),
            Status::Recovered
        );
        assert!(matches!(
            aw.begin_sync_response(a.profile, &a.keys, &br, None, None),
            Err(Error::Drop)
        ));
    }
}

#[test]
fn result_write_uncertainty_and_cutover_generation_never_repeat_success_or_send() {
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Initiator);
    let (mut window, mut allocator) = f.start(2, 3);
    f.propose(&mut window, &mut allocator, 100);
    let before = window.record().clone();
    let value = before
        .sync_recovery()
        .unwrap()
        .pending()
        .unwrap()
        .notification();
    let reply = f.response(Sync::new(value.nonce(), 3, 2));
    let prepared = window
        .complete_sync(f.profile, &f.keys, &reply, clock(101))
        .unwrap();
    let landed = prepared.record().clone();
    assert!(matches!(
        prepared.commit_after_durable(&before, clock(101)),
        Err(Error::CommitMismatch)
    ));
    assert!(matches!(
        window.replay_request(),
        Err(Error::CommitUncertain)
    ));
    let mut absent = f.restore(&before, 8).unwrap();
    assert!(matches!(
        absent.complete_sync(f.profile, &f.keys, &reply, clock(102)),
        Err(Error::Drop)
    ));
    let mut landed = f.restore(&landed, 8).unwrap();
    assert!(matches!(landed.replay_request(), Ok(None)));
    assert!(matches!(
        landed.complete_sync(f.profile, &f.keys, &reply, clock(102)),
        Err(Error::Drop)
    ));
    let (mut window, mut allocator) = f.start(2, 3);
    let prepared = window
        .begin_sync(policy(), clock(100), None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let (_, token) = commit(prepared);
    let peer = f.wire(
        f.header(true, Exchange::Informational, 0, false),
        PayloadChain::new(PayloadType::Notify, &sync_payload(Sync::new([9; 4], 5, 6))),
        Kind::Encrypted,
        100,
    );
    f.respond(&mut window, &mut allocator, &peer);
    assert!(matches!(
        window.release_sync_action(token, clock(101)),
        Err(Error::StaleCompletion)
    ));
    assert!(matches!(
        window.replay_request(),
        Err(Error::SyncInProgress)
    ));
}

#[test]
fn storage_outage_keeps_the_same_durably_charged_block_budget() {
    use opc_proto_ikev2::recovery::{
        Ikev2ReservationRetry as Retry, Ikev2ReservationRetryError as RetryError,
        Ikev2ReservationRetryPolicy as RetryPolicy, Ikev2ReservationRetryRecord as RetryRecord,
    };
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Initiator);
    for landed in [false, true] {
        let mut record = f.record(2, 3, None, Disposition::Continue);
        let mut iv_record = f.iv_record(0);
        let retry_policy = RetryPolicy::new(100, 200, 3, 10).unwrap();
        let mut charge = RetryRecord::initial(
            f.domain.send_iv_domain().clone(),
            policy().operation(),
            retry_policy,
        );
        for index in 0..3 {
            let now = 100 + 10 * index;
            let mut window = f.restore(&record, iv_record.exclusive_end()).unwrap();
            let admitted = if record.sync_recovery().is_some() {
                window.retry_sync(clock(now)).unwrap()
            } else {
                window.begin_sync(policy(), clock(now), None).unwrap()
            };
            let mut allocator = Allocator::restore(f.domain.send_iv_domain(), &iv_record).unwrap();
            let mut retry =
                Retry::restore(f.domain.send_iv_domain(), policy().operation(), &charge).unwrap();
            let prepared = retry.prepare_attempt(&allocator, now, false).unwrap();
            charge = prepared.record().clone();
            let permit = prepared.commit_after_durable(&charge).unwrap();
            let block = permit
                .prepare(&mut allocator, 1, Purpose::Ordinary, now, false)
                .unwrap();
            iv_record = block.record().clone();
            block.activate_after_commit(&iv_record, now, false).unwrap();
            let prepared = admitted
                .prepare(
                    f.profile,
                    &f.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap();
            if landed {
                record = prepared.record().clone();
            }
            drop(prepared);
            assert!(matches!(
                window.replay_request(),
                Err(Error::CommitUncertain)
            ));
        }
        let allocator = Allocator::restore(f.domain.send_iv_domain(), &iv_record).unwrap();
        let mut retry =
            Retry::restore(f.domain.send_iv_domain(), policy().operation(), &charge).unwrap();
        assert!(matches!(
            retry.prepare_attempt(&allocator, 130, false),
            Err(RetryError::Closed)
        ));
        assert_eq!(charge.attempts(), 3);
        assert_eq!(charge.policy(), retry_policy);
        assert_eq!(iv_record.exclusive_end(), 3);
        assert_eq!(
            record.sync_state().unwrap().agreement().mode(),
            Mode::Negotiated
        );
        if landed {
            let mut window = f.restore(&record, 3).unwrap();
            assert_eq!(record.sync_recovery().unwrap().attempts().len(), 3);
            assert!(matches!(
                window.retry_sync(clock(130)),
                Err(Error::SyncClosed)
            ));
        }
    }
}

#[test]
fn counter_limits_fallback_and_one_attempt_policy_cannot_enable_another_proposal() {
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Responder);
    let (mut window, mut allocator) = f.start(0, 0);
    let single = Policy::new(42, clock(100), 200, 1, 10).unwrap();
    let prepared = window
        .begin_sync(single, clock(100), None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let (record, token) = commit(prepared);
    release(&mut window, token, 100);
    assert_eq!(
        record
            .sync_recovery()
            .unwrap()
            .pending()
            .unwrap()
            .notification()
            .expected_send_req_message_id(),
        0
    );
    assert!(matches!(
        window.retry_sync(clock(109)),
        Err(Error::SyncBackoff)
    ));
    assert!(matches!(
        window.retry_sync(clock(110)),
        Err(Error::SyncClosed)
    ));
    for (send, receive) in [(u32::MAX, 0), (0, u32::MAX)] {
        let (mut window, _) = f.start(send, receive);
        assert!(matches!(
            window.begin_sync(policy(), clock(100), None),
            Err(Error::SyncClosed)
        ));
    }
    let (mut window, mut allocator) = f.start(u32::MAX - 1, 0);
    f.propose(&mut window, &mut allocator, 100);
    assert!(matches!(
        window.retry_sync(clock(110)),
        Err(Error::SyncClosed)
    ));
    let fallback = Record::initial(f.domain.clone(), 0, 0)
        .with_sync_state(
            SyncRecord::from_persisted(
                Agreement::from_persisted(f.agreement.sa(), Mode::BaseFallback),
                None,
                None,
                None,
                None,
                Disposition::Continue,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    let mut window = f.restore(&fallback, 0).unwrap();
    assert!(matches!(
        window.begin_sync(policy(), clock(100), None),
        Err(Error::Drop)
    ));
    assert_eq!(window.record(), &fallback);
}

#[test]
fn a_genuine_later_event_uses_its_new_clock_epoch_without_resetting_counter_history() {
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Initiator);
    let (mut window, mut allocator) = f.start(2, 3);
    f.propose(&mut window, &mut allocator, 100);
    let value = window
        .record()
        .sync_recovery()
        .unwrap()
        .pending()
        .unwrap()
        .notification();
    f.complete(
        &mut window,
        &f.response(Sync::new(value.nonce(), 3, 2)),
        105,
    );
    let next_clock = Clock::new(90, 8);
    let next_policy = Policy::new(43, next_clock, 190, 3, 10).unwrap();
    let prepared = window
        .begin_sync(next_policy, next_clock, None)
        .unwrap()
        .prepare(
            f.profile,
            &f.keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    let next = prepared.record().sync_recovery().unwrap();
    assert_eq!(next.policy(), next_policy);
    assert!(
        next.pending()
            .unwrap()
            .notification()
            .expected_send_req_message_id()
            > value.expected_send_req_message_id()
    );
}

#[test]
fn ordinary_exhaustion_after_recovery_restores_history_and_latches_sync_closure() {
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Initiator);
    let (mut window, mut allocator) = f.start(2, 3);
    f.propose(&mut window, &mut allocator, 100);
    let value = window
        .record()
        .sync_recovery()
        .unwrap()
        .pending()
        .unwrap()
        .notification();
    f.complete(
        &mut window,
        &f.response(Sync::new(value.nonce(), 3, u32::MAX - 1)),
        101,
    );
    for id in [u32::MAX - 1, u32::MAX] {
        let prepared = window
            .prepare_request(
                f.profile,
                &f.keys,
                allocator.allocate(Purpose::Control).unwrap(),
                Exchange::Informational,
                delete(),
            )
            .unwrap();
        let record = prepared.record().clone();
        let _token = prepared.commit_after_durable(&record).unwrap();
        let response = f.wire(
            f.header(true, Exchange::Informational, id, true),
            delete(),
            Kind::Encrypted,
            100,
        );
        let opened = window.open_peer(f.profile, &f.keys, &response).unwrap();
        let prepared = window
            .prepare_completion(&opened, Bytes::from_static(b"settled"))
            .unwrap();
        let record = prepared.record().clone();
        let _token = prepared.commit_after_durable(&record).unwrap();
    }
    assert_eq!(window.record().next_send(), None);
    let mut restored = f.restore(window.record(), 8).unwrap();
    let later = Policy::new(43, clock(110), 200, 3, 10).unwrap();
    assert!(matches!(
        restored.begin_sync(later, clock(110), None),
        Err(Error::SyncClosed)
    ));
    assert!(matches!(restored.replay_request(), Err(Error::SyncClosed)));
    let (closed, token) = commit(restored.close_sync().unwrap());
    assert!(matches!(
        restored.release_sync_action(token, clock(111)).unwrap(),
        Action::CloseIkeSa
    ));
    let rebuilt = Record::from_persisted(
        closed.domain().clone(),
        closed.generation(),
        closed.next_send(),
        closed.next_receive(),
        closed.outbound().cloned(),
        closed.inbound().cloned(),
    )
    .unwrap()
    .with_sync_state(*closed.sync_state().unwrap())
    .unwrap()
    .with_sync_recovery(closed.sync_recovery().unwrap().clone())
    .unwrap();
    assert!(matches!(
        f.restore(&rebuilt, 8).unwrap().replay_request(),
        Err(Error::SyncClosed)
    ));
}

#[test]
fn production_advertisement_consumes_runtime_readiness_and_authenticated_offer_evidence() {
    for role in ROLES {
        let f = Fixture::new(Encryption::AesGcm16_128, role);
        let initial = Record::initial(f.domain.clone(), 1, 1);
        let window = f.restore(&initial, 0).unwrap();
        let readiness = window.sync_readiness(f.profile, &f.keys).unwrap();
        assert_eq!(format!("{readiness:?}"), "Ikev2SyncReadiness { .. }");
        let mut negotiation = readiness.negotiate();
        let offered = negotiation.local_offer().unwrap();
        assert_eq!(offered.is_some(), role == Role::Initiator);
        if let Some(offer) = offered {
            assert_eq!(offer.notify_message_type, 16420);
            assert_eq!(offer.protocol_id, 0);
            assert!(offer.spi.is_empty() && offer.notification_data.is_empty());
        }
        let response = role == Role::Initiator;
        let support = [0, 0, 0, 8, 0, 0, 0x40, 0x24];
        let malformed = [0, 0, 0, 9, 0, 0, 0x40, 0x24, 1];
        for (round, body) in [&malformed[..], &support[..], &support[..], &malformed[..]]
            .into_iter()
            .enumerate()
        {
            let wire = f.wire(
                f.header(true, Exchange::IkeAuth, 1, response),
                PayloadChain::new(PayloadType::Notify, body),
                Kind::Encrypted,
                100,
            );
            let packet = window.open_peer(f.profile, &f.keys, &wire).unwrap();
            negotiation.observe_peer(&packet).unwrap();
            if round == 0 && role == Role::Responder {
                assert!(negotiation.local_offer().unwrap().is_none());
            }
        }
        assert!(negotiation.local_offer().unwrap().is_some());
        assert_eq!(negotiation.finish(true).unwrap(), f.agreement);
        let unfinished = window
            .sync_readiness(f.profile, &f.keys)
            .unwrap()
            .negotiate();
        assert!(unfinished.finish(false).is_none());
        let fallback = window
            .sync_readiness(f.profile, &f.keys)
            .unwrap()
            .negotiate();
        assert_eq!(fallback.finish(true).unwrap().mode(), Mode::BaseFallback);
        let (active, _) = f.start(2, 3);
        assert!(matches!(
            active.sync_readiness(f.profile, &f.keys),
            Err(Error::Drop)
        ));
    }
}

#[test]
fn readiness_negotiation_rejects_foreign_authenticated_domain_and_wrong_handshake_class() {
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Responder);
    let initial = Record::initial(f.domain.clone(), 1, 1);
    let window = f.restore(&initial, 0).unwrap();
    let mut negotiation = window
        .sync_readiness(f.profile, &f.keys)
        .unwrap()
        .negotiate();
    let support = [0, 0, 0, 8, 0, 0, 0x40, 0x24];
    for (exchange, id, response) in [
        (Exchange::Informational, 1, false),
        (Exchange::IkeAuth, 0, false),
        (Exchange::IkeAuth, 1, true),
    ] {
        let wire = f.wire(
            f.header(true, exchange, id, response),
            PayloadChain::new(PayloadType::Notify, &support),
            Kind::Encrypted,
            100,
        );
        let packet = window.open_peer(f.profile, &f.keys, &wire).unwrap();
        assert_eq!(negotiation.observe_peer(&packet), Err(Error::Drop));
    }
    let mut foreign = Fixture::new(Encryption::AesGcm16_128, Role::Responder);
    foreign.domain = Domain::new(
        0x303,
        0x202,
        Direction::ResponderToInitiator,
        foreign.profile,
        &foreign.keys,
    )
    .unwrap();
    let foreign_window = foreign
        .restore(&Record::initial(foreign.domain.clone(), 1, 1), 0)
        .unwrap();
    let mut header = foreign.header(true, Exchange::IkeAuth, 1, false);
    header.initiator_spi = 0x303;
    let wire = foreign.wire(
        header,
        PayloadChain::new(PayloadType::Notify, &support),
        Kind::Encrypted,
        100,
    );
    let packet = foreign_window
        .open_peer(foreign.profile, &foreign.keys, &wire)
        .unwrap();
    assert_eq!(
        negotiation.observe_peer(&packet),
        Err(Error::DomainMismatch)
    );
    assert!(negotiation.local_offer().unwrap().is_none());
}

#[test]
fn delayed_or_discontinuous_request_acknowledgement_emits_no_request() {
    let f = Fixture::new(Encryption::AesGcm16_128, Role::Initiator);
    for now in [clock(200), clock(99), Clock::new(102, 8)] {
        let (mut window, mut allocator) = f.start(2, 3);
        let prepared = window
            .begin_sync(policy(), clock(100), None)
            .unwrap()
            .prepare(
                f.profile,
                &f.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
            )
            .unwrap();
        let landed = prepared.record().clone();
        assert!(matches!(
            prepared.commit_after_durable(&landed, now),
            Err(Error::SyncClosed)
        ));
        assert_eq!(window.record(), &landed);
        assert!(matches!(window.replay_request(), Err(Error::SyncClosed)));
        assert!(matches!(
            window.retry_sync(clock(110)),
            Err(Error::SyncClosed)
        ));
        let prepared = window.close_sync().unwrap();
        let closed = prepared.record().clone();
        let token = prepared.commit_after_durable(&closed, now).unwrap();
        assert!(matches!(
            window.release_sync_action(token, now).unwrap(),
            Action::CloseIkeSa
        ));
        assert!(matches!(
            f.restore(&closed, 8).unwrap().replay_request(),
            Err(Error::SyncClosed)
        ));
    }
}

#[test]
fn an_in_time_result_stays_recovered_after_late_or_stepped_acknowledgement_and_restore() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        for now in [clock(200), clock(99), Clock::new(102, 8)] {
            let (mut window, mut allocator) = f.start(2, 3);
            f.propose(&mut window, &mut allocator, 100);
            let pending = window.record().sync_recovery().unwrap().pending().unwrap();
            let response = f.response(Sync::new(pending.notification().nonce(), 3, 2));
            let prepared = window
                .complete_sync(f.profile, &f.keys, &response, clock(101))
                .unwrap();
            let landed = prepared.record().clone();
            assert_eq!(landed.sync_recovery().unwrap().last_observed_unix_ms(), 101);
            let token = prepared.commit_after_durable(&landed, now).unwrap();
            assert!(matches!(
                window.release_sync_action(token, now).unwrap(),
                Action::Recovered
            ));
            assert_eq!(window.record(), &landed);
            assert_eq!(landed.sync_recovery().unwrap().status(), Status::Recovered);
            assert_eq!(
                landed.sync_state().unwrap().disposition(),
                Disposition::Continue
            );
            assert!(matches!(window.close_sync(), Err(Error::Drop)));
            for mut runtime in [window, f.restore(&landed, 8).unwrap()] {
                let ordinary = runtime
                    .open_peer(f.profile, &f.keys, &f.ordinary(3))
                    .unwrap();
                assert_eq!(
                    runtime.request_disposition(&ordinary),
                    Ok(opc_proto_ikev2::recovery::Ikev2OrdinaryRequestDisposition::New)
                );
                assert!(matches!(runtime.replay_request(), Ok(None)));
                assert_eq!(runtime.check_sync_deadline(now), Err(Error::Drop));
                assert!(matches!(
                    runtime.complete_sync(f.profile, &f.keys, &response, now),
                    Err(Error::Drop)
                ));
                assert!(matches!(runtime.retry_sync(now), Err(Error::Drop)));
                assert_eq!(runtime.record(), &landed);
            }
        }
    }
}

#[test]
fn pure_pending_wait_can_commit_closure_live_or_after_restore_without_an_event_record() {
    for role in ROLES {
        for restore_first in [false, true] {
            let f = Fixture::new(ENCRYPTIONS[0], role);
            let (mut window, mut allocator) = f.start(2, 3);
            let pending =
                Pending::from_persisted(f.agreement.sa(), Sync::new([7; 4], 2, 3)).unwrap();
            let peer = f.wire(
                f.header(true, Exchange::Informational, 0, false),
                PayloadChain::new(PayloadType::Notify, &sync_payload(Sync::new([9; 4], 4, 6))),
                Kind::Encrypted,
                100,
            );
            let prepared = window
                .begin_sync_response(f.profile, &f.keys, &peer, Some(&pending), None)
                .unwrap()
                .prepare(
                    f.profile,
                    &f.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap();
            let waiting = prepared.record().clone();
            let token = prepared.commit_after_durable(&waiting).unwrap();
            assert_eq!(
                window.release_sync_response(token).unwrap().into_parts().1,
                Disposition::AwaitLocalSync
            );
            assert!(waiting.sync_recovery().is_none());
            assert!(matches!(
                window.replay_request(),
                Err(Error::SyncInProgress)
            ));
            if restore_first {
                window = f.restore(&waiting, 8).unwrap();
            }
            let (closed, token) = commit(window.close_sync().unwrap());
            assert!(closed.sync_recovery().is_none());
            assert_eq!(
                closed.sync_state().unwrap().disposition(),
                Disposition::CloseIkeSa
            );
            assert_eq!(
                (closed.next_send(), closed.next_receive()),
                (waiting.next_send(), waiting.next_receive())
            );
            assert_eq!(
                closed.sync_state().unwrap().minimum_send_iv_end(),
                waiting.sync_state().unwrap().minimum_send_iv_end()
            );
            assert!(matches!(
                window.release_sync_action(token, clock(999)).unwrap(),
                Action::CloseIkeSa
            ));
            for mut runtime in [window, f.restore(&closed, 8).unwrap()] {
                assert!(matches!(runtime.replay_request(), Err(Error::SyncClosed)));
                assert!(matches!(runtime.close_sync(), Err(Error::SyncClosed)));
                assert!(matches!(
                    runtime.begin_sync(policy(), clock(100), None),
                    Err(Error::SyncClosed)
                ));
            }
        }
    }
}

#[test]
fn restored_clock_rejects_same_epoch_rollback_below_the_persisted_observation() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        let (mut window, mut allocator) = f.start(2, 3);
        f.propose(&mut window, &mut allocator, 100);
        f.propose(&mut window, &mut allocator, 110);
        let persisted = window.record().clone();
        let state = persisted.sync_recovery().unwrap();
        assert_eq!(state.policy().started(), clock(100));
        assert_eq!(state.last_observed_unix_ms(), 110);
        let mut same_time = f.restore(&persisted, 8).unwrap();
        assert_eq!(same_time.check_sync_deadline(clock(110)), Ok(()));
        let mut restored = f.restore(&persisted, 8).unwrap();
        assert_eq!(
            restored.check_sync_deadline(clock(105)),
            Err(Error::SyncClosed)
        );
        assert!(matches!(
            restored.retry_sync(clock(120)),
            Err(Error::SyncClosed)
        ));
        assert_eq!(restored.record(), &persisted); // No refund, timer extension or new attempt.
        assert!(matches!(restored.replay_request(), Err(Error::SyncClosed)));
    }
}

#[test]
fn responder_uses_durable_pending_and_closes_recovered_history_for_uncertain_work() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        let (mut window, mut allocator) = f.start(2, 3);
        f.propose(&mut window, &mut allocator, 100);
        let original = window.record().clone();
        let pending = original.sync_recovery().unwrap().pending().unwrap();
        let value = pending.notification();
        let mut wrong_nonce = value.nonce();
        wrong_nonce[0] ^= 1;
        let wrong = Pending::from_persisted(
            pending.sa(),
            Sync::new(
                wrong_nonce,
                value.expected_send_req_message_id(),
                value.expected_recv_req_message_id(),
            ),
        )
        .unwrap();
        let peer = f.wire(
            f.header(true, Exchange::Informational, 0, false),
            PayloadChain::new(PayloadType::Notify, &sync_payload(Sync::new([9; 4], 5, 6))),
            Kind::Encrypted,
            100,
        );
        assert!(matches!(
            window.begin_sync_response(f.profile, &f.keys, &peer, Some(&wrong), None),
            Err(Error::Drop)
        ));
        assert_eq!(window.record(), &original);
        let mut restored = f.restore(&original, 8).unwrap();
        assert!(matches!(
            restored.begin_sync_response(f.profile, &f.keys, &peer, Some(&wrong), None),
            Err(Error::Drop)
        ));
        assert_eq!(restored.record(), &original);
        f.complete(
            &mut window,
            &f.response(Sync::new(value.nonce(), 3, 2)),
            101,
        );
        assert_eq!(
            window.record().sync_recovery().unwrap().status(),
            Status::Recovered
        );
        let prepared = window
            .prepare_request(
                f.profile,
                &f.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
                Exchange::CreateChildSa,
                delete(),
            )
            .unwrap();
        let with_work = prepared.record().clone();
        let _outcome = prepared.commit_after_durable(&with_work).unwrap();
        let prepared = window
            .begin_sync_response(f.profile, &f.keys, &peer, None, None)
            .unwrap()
            .prepare(
                f.profile,
                &f.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
            )
            .unwrap();
        let closed = prepared.record().clone();
        assert_eq!(closed.sync_recovery().unwrap().status(), Status::Closed);
        assert_eq!(
            closed.sync_recovery().unwrap().attempts(),
            original.sync_recovery().unwrap().attempts()
        );
        assert_eq!(closed.sync_recovery().unwrap().policy(), policy());
        assert_eq!(
            closed.sync_state().unwrap().disposition(),
            Disposition::OutcomeUncertain
        );
        let token = prepared.commit_after_durable(&closed).unwrap();
        assert_eq!(
            window.release_sync_response(token).unwrap().into_parts().1,
            Disposition::OutcomeUncertain
        );
        for mut runtime in [window, f.restore(&closed, 8).unwrap()] {
            assert!(matches!(
                runtime.replay_request(),
                Err(Error::OutcomeUncertain)
            ));
            assert!(matches!(
                runtime.retry_sync(clock(110)),
                Err(Error::OutcomeUncertain)
            ));
        }
    }
}

#[test]
fn voluntary_close_commits_a_pending_event_without_any_prior_closure_latch() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        let (mut window, mut allocator) = f.start(2, 3);
        f.propose(&mut window, &mut allocator, 100);
        assert_eq!(window.check_sync_deadline(clock(105)), Ok(()));
        let pending = window.record().clone();
        let (closed, token) = commit(window.close_sync().unwrap());
        assert_eq!(closed.sync_recovery().unwrap().status(), Status::Closed);
        assert_eq!(closed.sync_recovery().unwrap().policy(), policy());
        assert_eq!(
            closed.sync_recovery().unwrap().attempts(),
            pending.sync_recovery().unwrap().attempts()
        );
        assert!(matches!(
            window.release_sync_action(token, clock(105)).unwrap(),
            Action::CloseIkeSa
        ));
        for mut runtime in [window, f.restore(&closed, 8).unwrap()] {
            assert!(matches!(runtime.replay_request(), Err(Error::SyncClosed)));
            assert!(matches!(runtime.close_sync(), Err(Error::SyncClosed)));
            assert!(matches!(
                runtime.retry_sync(clock(110)),
                Err(Error::SyncClosed)
            ));
        }
    }
}
