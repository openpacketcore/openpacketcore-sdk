use bytes::Bytes;
use opc_proto_ikev2::{
    open_protected_payloads,
    recovery::{
        Ikev2AuthenticatedOrdinary as Ordinary, Ikev2CommittedExchangeRecord as ExchangeRecord,
        Ikev2CommittedWindow as Window, Ikev2CommittedWindowDomain as Domain,
        Ikev2CommittedWindowRecord as Record, Ikev2PreparedSyncResponse as Prepared,
        Ikev2ReservationRetry as Retry, Ikev2ReservationRetryError as RetryError,
        Ikev2ReservationRetryPolicy as Policy, Ikev2ReservationRetryRecord as RetryRecord,
        Ikev2SyncCommit as Commit, Ikev2SyncDisposition as Disposition,
        Ikev2SyncResponderRecord as SyncRecord, Ikev2WindowError as Error,
    },
    seal_ikev2_sa_init_protected_payload, Header, HeaderFlags, Ikev2AesGcmIvAllocator as Allocator,
    Ikev2AesGcmIvLimits as Limits, Ikev2AesGcmIvPurpose as Purpose,
    Ikev2AesGcmIvRecord as IvRecord, Ikev2DhGroup, Ikev2EncryptionAlgorithm as Encryption,
    Ikev2ExchangeKind as Exchange, Ikev2MessageIdSync as Sync,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncCounters as Counters,
    Ikev2MessageIdSyncMode as Mode, Ikev2MessageIdSyncPending as Pending,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncRuleError as RuleError,
    Ikev2MessageIdSyncSa as Sa, Ikev2PrfAlgorithm, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys,
    Ikev2SaInitProtectedPayloadProvider as Provider, Message, PayloadChain, PayloadType,
    ProtectedPayloadKind as Kind, ProtectedPayloadSealContext,
};
use opc_protocol::{BorrowDecode, DecodeContext};

mod support;

const ROLES: [Role; 2] = [Role::Initiator, Role::Responder];
const ENCRYPTIONS: [Encryption; 3] = [
    Encryption::AesGcm16_128,
    Encryption::AesGcm16_192,
    Encryption::AesGcm16_256,
];
const NONCE: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
const DELETE: &[u8] = &[0, 0, 0, 8, 1, 0, 0, 0];

fn delete() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::Delete, DELETE)
}
fn empty() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::NoNext, &[])
}
fn sync_payload(value: Sync) -> Bytes {
    // Hand-framed sole Notify, independent of the runtime response builder.
    let mut bytes = vec![0, 0, 0, 20, 0, 0, 0x40, 0x26];
    bytes.extend_from_slice(&value.nonce());
    bytes.extend_from_slice(&value.expected_send_req_message_id().to_be_bytes());
    bytes.extend_from_slice(&value.expected_recv_req_message_id().to_be_bytes());
    bytes.into()
}
fn committed(prepared: Prepared<'_>) -> (Record, Commit) {
    let record = prepared.record().clone();
    let token = prepared.commit_after_durable(&record).unwrap();
    (record, token)
}
fn ordinary_commit(prepared: opc_proto_ikev2::recovery::Ikev2PreparedWindow<'_>) -> Record {
    let record = prepared.record().clone();
    let _token = prepared.commit_after_durable(&record).unwrap();
    record
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
        let domain = support::window_domain(0x101, 0x202, direction, profile, &keys).unwrap();
        let agreement =
            Agreement::from_persisted(Sa::new(0x101, 0x202, role).unwrap(), Mode::Negotiated);
        Self {
            profile,
            keys,
            domain,
            agreement,
            role,
        }
    }

    fn record(&self, counters: Counters, disposition: Disposition) -> Record {
        Record::from_persisted(
            self.domain.clone(),
            1,
            Some(counters.next_send),
            Some(counters.next_receive),
            None,
            None,
        )
        .unwrap()
        .with_sync_state(
            SyncRecord::from_persisted(
                self.agreement,
                counters.highest_local_request,
                counters.highest_peer_request,
                counters.highest_local_proposal,
                counters.highest_peer_proposal,
                disposition,
                0,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn epoch_inputs(&self) -> opc_proto_ikev2::Ikev2AesGcmEpochInputs<'_> {
        let domain = self.domain.send_iv_domain();
        support::epoch_inputs(
            domain.initiator_spi(),
            domain.responder_spi(),
            domain.direction(),
            self.profile,
            &self.keys,
        )
    }
    fn iv_record(&self, end: u64) -> IvRecord {
        IvRecord::from_persisted(
            self.epoch_inputs(),
            Limits::new(128, 2, 1, 2).unwrap(),
            end,
            Some(1),
        )
        .unwrap()
    }

    fn restore(&self, record: &Record, iv_record: &IvRecord) -> Window {
        Window::restore(&self.domain, self.profile, &self.keys, record, iv_record).unwrap()
    }

    fn start(&self, counters: Counters) -> (Window, Allocator, IvRecord) {
        let mut allocator =
            Allocator::fresh(self.epoch_inputs(), self.iv_record(0).limits()).unwrap();
        let prepared = allocator.prepare(8, Purpose::Ordinary).unwrap();
        let iv_record = prepared.record().clone();
        prepared.activate_after_commit(&iv_record).unwrap();
        let window = self.restore(&self.record(counters, Disposition::Continue), &iv_record);
        (window, allocator, iv_record)
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

    fn peer_sync(&self, value: Sync) -> Bytes {
        self.wire(
            self.header(true, Exchange::Informational, 0, false),
            PayloadChain::new(PayloadType::Notify, &sync_payload(value)),
            Kind::Encrypted,
            100,
        )
    }

    fn peer_ordinary(&self, id: u32, exchange: Exchange, payloads: PayloadChain<'_>) -> Bytes {
        self.wire(
            self.header(true, exchange, id, false),
            payloads,
            Kind::Encrypted,
            101,
        )
    }

    fn prepare<'w>(
        &self,
        window: &'w mut Window,
        allocator: &mut Allocator,
        wire: &[u8],
        pending: Option<&Pending>,
        inbound: Option<&Ordinary>,
    ) -> Result<Prepared<'w>, Error> {
        window
            .begin_sync_response(self.profile, &self.keys, wire, pending, inbound)?
            .prepare(
                self.profile,
                &self.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
            )
    }

    fn assert_reply(&self, wire: &[u8], value: Sync, iv: u64) {
        let expected = self.wire(
            self.header(false, Exchange::Informational, 0, true),
            PayloadChain::new(PayloadType::Notify, &sync_payload(value)),
            Kind::Encrypted,
            iv,
        );
        assert_eq!(wire, expected.as_ref());
        let (tail, message) = Message::decode(wire, DecodeContext::default()).unwrap();
        assert!(tail.is_empty());
        let provider = Provider::new(
            self.profile,
            &self.keys,
            self.domain.send_iv_domain().direction(),
        );
        let opened =
            open_protected_payloads(&message, wire, DecodeContext::default(), &provider).unwrap();
        assert_eq!(opened[0].cleartext, sync_payload(value));
    }
}

#[test]
fn authenticated_cutovers_commit_before_reply_and_never_cache_sync_duplicates() {
    for algorithm in ENCRYPTIONS {
        for role in ROLES {
            let f = Fixture::new(algorithm, role);
            let (mut window, mut allocator, iv_record) = f.start(Counters::new(0, 0));
            for (m1, p1, iv) in [(0, 5, 0), (1, 4, 1)] {
                let wire = f.peer_sync(Sync::new(NONCE, m1, p1));
                assert!(matches!(
                    window.open_peer(f.profile, &f.keys, &wire),
                    Err(Error::Drop)
                ));
                let (record, token) = committed(
                    f.prepare(&mut window, &mut allocator, &wire, None, None)
                        .unwrap(),
                );
                assert_eq!(record.next_send(), Some(5));
                assert_eq!(record.next_receive(), Some(m1));
                assert_eq!(
                    record.sync_state().unwrap().highest_peer_proposal(),
                    Some(m1)
                );
                let (reply, disposition) =
                    window.release_sync_response(token).unwrap().into_parts();
                assert_eq!(disposition, Disposition::Continue);
                f.assert_reply(&reply, Sync::new(NONCE, 5, m1), iv);
                assert!(record.outbound().is_none() && record.inbound().is_none());
                assert!(window.replay_request().unwrap().is_none());
                for rejected in 0..=m1 {
                    let duplicate = f.peer_sync(Sync::new([9; 4], rejected, 9));
                    assert!(matches!(
                        window.begin_sync_response(f.profile, &f.keys, &duplicate, None, None),
                        Err(Error::Drop)
                    ));
                    assert_eq!(window.record(), &record);
                }
                let mut restored = f.restore(&record, &iv_record);
                assert!(matches!(
                    restored.begin_sync_response(f.profile, &f.keys, &wire, None, None),
                    Err(Error::Drop)
                ));
                assert!(restored.replay_request().unwrap().is_none());
            }
        }
    }
}

#[test]
fn wrong_authentication_shape_mode_and_direction_drop_before_freezing_or_using_an_iv() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        let (mut window, mut allocator, _) = f.start(Counters::new(0, 0));
        let original = window.record().clone();
        let data = sync_payload(Sync::new(NONCE, 1, 2));
        let header = f.header(true, Exchange::Informational, 0, false);
        let mut invalid = vec![
            f.wire(header.clone(), empty(), Kind::Encrypted, 110),
            f.wire(header.clone(), delete(), Kind::Encrypted, 110),
            f.wire(
                header.clone(),
                PayloadChain::new(PayloadType::Notify, &data),
                Kind::EncryptedFragment,
                110,
            ),
        ];
        for wrong_header in [
            f.header(true, Exchange::Informational, 1, false),
            f.header(true, Exchange::Informational, 0, true),
            f.header(true, Exchange::IkeAuth, 0, false),
            f.header(true, Exchange::IkeSaInit, 0, false),
            f.header(false, Exchange::Informational, 0, false),
            Header {
                initiator_spi: 0x999,
                ..header.clone()
            },
        ] {
            invalid.push(f.wire(
                wrong_header,
                PayloadChain::new(PayloadType::Notify, &data),
                Kind::Encrypted,
                110,
            ));
        }
        let mut duplicate = data.to_vec();
        duplicate[0] = 41;
        duplicate.extend_from_slice(&data);
        let mut extra = data.to_vec();
        extra[0] = 41;
        extra.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0x40, 0x27]);
        let mut malformed = data.to_vec();
        malformed[5] = 1;
        for bytes in [duplicate, extra, malformed] {
            invalid.push(f.wire(
                header.clone(),
                PayloadChain::new(PayloadType::Notify, &bytes),
                Kind::Encrypted,
                110,
            ));
        }
        let valid = f.peer_sync(Sync::new(NONCE, 1, 2));
        let mut bad_tag = valid.to_vec();
        *bad_tag.last_mut().unwrap() ^= 1;
        let mut tail = valid.to_vec();
        tail.push(0);
        invalid.extend([bad_tag.into(), tail.into(), valid.slice(..valid.len() - 1)]);
        for wire in invalid {
            assert!(matches!(
                window.begin_sync_response(f.profile, &f.keys, &wire, None, None),
                Err(Error::Drop)
            ));
            assert_eq!(window.record(), &original);
            assert!(window.replay_request().unwrap().is_none());
        }
        let (_, token) = committed(
            f.prepare(&mut window, &mut allocator, &valid, None, None)
                .unwrap(),
        );
        let (reply, _) = window.release_sync_response(token).unwrap().into_parts();
        f.assert_reply(&reply, Sync::new(NONCE, 2, 1), 0);
        for mode in [None, Some(Mode::BaseFallback)] {
            let mut record = Record::initial(f.domain.clone(), 0, 0);
            if let Some(mode) = mode {
                record = record
                    .with_sync_state(
                        SyncRecord::from_persisted(
                            Agreement::from_persisted(f.agreement.sa(), mode),
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
            }
            let mut disabled = f.restore(&record, &f.iv_record(0));
            assert!(matches!(
                disabled.begin_sync_response(f.profile, &f.keys, &valid, None, None),
                Err(Error::Drop)
            ));
            assert_eq!(disabled.record(), &record);
        }
    }
}

#[test]
fn cancelled_and_uncertain_cutovers_require_readback_and_never_regenerate_a_lost_reply() {
    let f = Fixture::new(ENCRYPTIONS[0], ROLES[0]);
    let wire = f.peer_sync(Sync::new(NONCE, 4, 5));
    for landed in [false, true] {
        let (mut window, _, mut iv_record) = f.start(Counters::new(0, 0));
        let original = window.record().clone();
        drop(
            window
                .begin_sync_response(f.profile, &f.keys, &wire, None, None)
                .unwrap(),
        );
        assert!(matches!(
            window.replay_request(),
            Err(Error::CommitUncertain)
        ));
        window = f.restore(&original, &iv_record);
        let mut allocator = Allocator::restore(f.domain.send_iv_domain(), &iv_record).unwrap();
        let block = allocator.prepare(1, Purpose::Ordinary).unwrap();
        iv_record = block.record().clone();
        block.activate_after_commit(&iv_record).unwrap();
        let prepared = f
            .prepare(&mut window, &mut allocator, &wire, None, None)
            .unwrap();
        let candidate = prepared.record().clone();
        assert!(matches!(
            prepared.commit_after_durable(&original),
            Err(Error::CommitMismatch)
        ));
        assert_eq!(window.record(), &original);
        assert!(matches!(
            window.replay_request(),
            Err(Error::CommitUncertain)
        ));
        let readback = if landed { &candidate } else { &original };
        window = f.restore(readback, &iv_record);
        if landed {
            assert!(matches!(
                window.begin_sync_response(f.profile, &f.keys, &wire, None, None),
                Err(Error::Drop)
            ));
            assert!(window.replay_request().unwrap().is_none());
        } else {
            // A real restore discards the allocator tail, then commits a higher block.
            allocator = Allocator::restore(f.domain.send_iv_domain(), &iv_record).unwrap();
            let block = allocator.prepare(1, Purpose::Ordinary).unwrap();
            let next_iv = block.record().clone();
            block.activate_after_commit(&next_iv).unwrap();
            let (record, token) = committed(
                f.prepare(&mut window, &mut allocator, &wire, None, None)
                    .unwrap(),
            );
            let (reply, _) = window.release_sync_response(token).unwrap().into_parts();
            f.assert_reply(&reply, Sync::new(NONCE, 5, 4), 9);
            let mut restored = f.restore(&record, &next_iv);
            assert!(matches!(
                restored.begin_sync_response(f.profile, &f.keys, &wire, None, None),
                Err(Error::Drop)
            ));
        }
    }
}

#[test]
fn peer_sync_retires_pending_outbound_mutations_and_fences_late_success() {
    for role in ROLES {
        for exchange in [Exchange::CreateChildSa, Exchange::Informational] {
            let f = Fixture::new(ENCRYPTIONS[0], role);
            let (mut window, mut allocator, iv_record) = f.start(Counters::new(0, 0));
            let prepared = window
                .prepare_request(
                    f.profile,
                    &f.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    exchange,
                    delete(),
                )
                .unwrap();
            let pending = prepared.record().clone();
            let old_completion = prepared.commit_after_durable(&pending).unwrap();
            let late = f.wire(
                f.header(true, exchange, 0, true),
                empty(),
                Kind::Encrypted,
                102,
            );
            let late = window.open_peer(f.profile, &f.keys, &late).unwrap();
            let wire = f.peer_sync(Sync::new(NONCE, 4, 3));
            let (record, token) = committed(
                f.prepare(&mut window, &mut allocator, &wire, None, None)
                    .unwrap(),
            );
            assert_eq!(
                record.sync_state().unwrap().disposition(),
                Disposition::OutcomeUncertain
            );
            assert!(matches!(
                window.apply_committed(old_completion),
                Err(Error::StaleCompletion)
            ));
            assert!(matches!(
                window.prepare_completion(&late, Bytes::from_static(b"success")),
                Err(Error::OutcomeUncertain)
            ));
            let (reply, disposition) = window.release_sync_response(token).unwrap().into_parts();
            assert_eq!(disposition, Disposition::OutcomeUncertain);
            f.assert_reply(&reply, Sync::new(NONCE, 3, 4), 1);
            let mut restored = f.restore(&record, &iv_record);
            assert!(matches!(
                restored.replay_request(),
                Err(Error::OutcomeUncertain)
            ));
            let newer = f.peer_sync(Sync::new(NONCE, 5, 4));
            assert!(matches!(
                restored.begin_sync_response(f.profile, &f.keys, &newer, None, None),
                Err(Error::OutcomeUncertain)
            ));
        }
    }
}

#[test]
fn admitted_uncommitted_inbound_mutations_close_only_after_sync_commit() {
    for role in ROLES {
        for exchange in [Exchange::CreateChildSa, Exchange::Informational] {
            let f = Fixture::new(ENCRYPTIONS[0], role);
            let (mut window, mut allocator, _) = f.start(Counters::new(0, 0));
            let incoming = f.peer_ordinary(0, exchange, delete());
            let incoming = window.open_peer(f.profile, &f.keys, &incoming).unwrap();
            let stale = f.peer_sync(Sync::new(NONCE, 0, 0));
            assert!(matches!(
                window.begin_sync_response(f.profile, &f.keys, &stale, None, Some(&incoming)),
                Err(Error::Drop)
            ));
            assert_eq!(
                window.record().sync_state().unwrap().disposition(),
                Disposition::Continue
            );
            let wire = f.peer_sync(Sync::new(NONCE, 1, 0));
            let (record, token) = committed(
                f.prepare(&mut window, &mut allocator, &wire, None, Some(&incoming))
                    .unwrap(),
            );
            assert_eq!(record.sync_state().unwrap().highest_peer_request(), Some(0));
            assert_eq!(record.next_receive(), Some(1));
            let (_, disposition) = window.release_sync_response(token).unwrap().into_parts();
            assert_eq!(disposition, Disposition::OutcomeUncertain);
            assert!(matches!(
                window.prepare_response(
                    f.profile,
                    &f.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    &incoming,
                    empty(),
                    Bytes::new()
                ),
                Err(Error::OutcomeUncertain)
            ));
        }
    }
}

#[test]
fn simultaneous_pending_proposals_merge_without_closing_or_resuming_ordinary_work() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        let mut counters = Counters::new(4, 4);
        counters.highest_local_request = Some(3);
        counters.highest_peer_request = Some(3);
        let pending = f.agreement.propose(counters, [1; 4]).unwrap();
        let (mut window, mut allocator, iv_record) = f.start(counters);
        let wire = f.peer_sync(Sync::new([2; 4], 5, 5));
        let (record, token) = committed(
            f.prepare(&mut window, &mut allocator, &wire, Some(&pending), None)
                .unwrap(),
        );
        assert_eq!(
            (record.next_send(), record.next_receive()),
            (Some(5), Some(5))
        );
        assert_eq!(
            record.sync_state().unwrap().highest_local_proposal(),
            Some(4)
        );
        let (reply, disposition) = window.release_sync_response(token).unwrap().into_parts();
        assert_eq!(disposition, Disposition::AwaitLocalSync);
        f.assert_reply(&reply, Sync::new([2; 4], 5, 5), 0);
        assert!(matches!(
            window.replay_request(),
            Err(Error::SyncInProgress)
        ));
        let restored = f.restore(&record, &iv_record);
        for id in [4, 5, 6] {
            let ordinary = f.peer_ordinary(id, Exchange::Informational, delete());
            let ordinary = restored.open_peer(f.profile, &f.keys, &ordinary).unwrap();
            assert_eq!(
                restored.request_disposition(&ordinary),
                Err(Error::SyncInProgress)
            );
        }
        // The responding direction still works while our local exchange is pending.
        let newer = f.peer_sync(Sync::new([3; 4], 6, 4));
        let (record, token) = committed(
            f.prepare(&mut window, &mut allocator, &newer, Some(&pending), None)
                .unwrap(),
        );
        assert_eq!(
            (record.next_send(), record.next_receive()),
            (Some(5), Some(6))
        );
        assert_eq!(
            window.release_sync_response(token).unwrap().into_parts().1,
            Disposition::AwaitLocalSync
        );
    }
}

#[test]
fn withheld_simultaneous_request_is_admissible_until_ordinary_peer_progress_and_never_rolls_back() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        let mut before = Counters::new(4, 4);
        before.highest_local_request = Some(3);
        before.highest_peer_request = Some(3);
        let local = f.agreement.propose(before, [1; 4]).unwrap();
        // Our sync completed with peer P2=6, before its withheld M1=4 arrives.
        // The initiating runtime is a later slice; restore this pure, committed
        // response result rather than inventing local send authority here.
        let response = sync_payload(Sync::new([1; 4], 6, 5));
        let after = f
            .agreement
            .evaluate_response(
                &f.header(true, Exchange::Informational, 0, true),
                PayloadChain::new(PayloadType::Notify, &response),
                before,
                &local,
            )
            .unwrap();
        for progressed in [false, true] {
            for mutation in [false, true] {
                let (mut window, mut allocator, _) = f.start(after);
                if mutation {
                    ordinary_commit(
                        window
                            .prepare_request(
                                f.profile,
                                &f.keys,
                                allocator.allocate(Purpose::Ordinary).unwrap(),
                                Exchange::CreateChildSa,
                                delete(),
                            )
                            .unwrap(),
                    );
                }
                if progressed {
                    let peer = f.peer_ordinary(6, Exchange::Informational, delete());
                    let peer = window.open_peer(f.profile, &f.keys, &peer).unwrap();
                    ordinary_commit(
                        window
                            .prepare_response(
                                f.profile,
                                &f.keys,
                                allocator.allocate(Purpose::Ordinary).unwrap(),
                                &peer,
                                empty(),
                                Bytes::new(),
                            )
                            .unwrap(),
                    );
                }
                let original = window.record().clone();
                let withheld = f.peer_sync(Sync::new([2; 4], 4, 4));
                if progressed {
                    assert!(matches!(
                        window.begin_sync_response(f.profile, &f.keys, &withheld, None, None),
                        Err(Error::Drop)
                    ));
                    assert_eq!(window.record(), &original);
                } else {
                    let (record, token) = committed(
                        f.prepare(&mut window, &mut allocator, &withheld, None, None)
                            .unwrap(),
                    );
                    assert!(record.next_send() >= original.next_send());
                    assert!(record.next_receive() >= original.next_receive());
                    let disposition = window.release_sync_response(token).unwrap().into_parts().1;
                    assert_eq!(
                        disposition,
                        if mutation {
                            Disposition::OutcomeUncertain
                        } else {
                            Disposition::Continue
                        }
                    );
                }
            }
        }
        // A minimal new peer proposal M1=P2 is expressly admissible too.
        let (mut window, mut allocator, _) = f.start(after);
        let equal = f.peer_sync(Sync::new([3; 4], 6, 5));
        let (record, token) = committed(
            f.prepare(&mut window, &mut allocator, &equal, None, None)
                .unwrap(),
        );
        assert_eq!(
            (record.next_send(), record.next_receive()),
            (Some(5), Some(6))
        );
        assert_eq!(
            window.release_sync_response(token).unwrap().into_parts().1,
            Disposition::Continue
        );
    }
}

#[test]
fn restart_remembers_durable_bounds_but_not_empty_requests_observed_only_in_memory() {
    let f = Fixture::new(ENCRYPTIONS[0], ROLES[0]);
    let mut counters = Counters::new(0, 7);
    counters.highest_peer_request = Some(6);
    let (mut window, _, iv_record) = f.start(counters);
    let durable = window.record().clone();
    for header in [
        f.header(true, Exchange::Informational, 6, false),
        f.header(true, Exchange::Informational, 8, false),
        f.header(true, Exchange::Informational, 7, true),
    ] {
        let invalid = f.wire(header, empty(), Kind::Encrypted, 111);
        let invalid = window.open_peer(f.profile, &f.keys, &invalid).unwrap();
        assert_eq!(window.observe_request_for_sync(&invalid), Err(Error::Drop));
        assert_eq!(window.record(), &durable);
    }
    let wire = f.peer_ordinary(7, Exchange::Informational, empty());
    let observed = window.open_peer(f.profile, &f.keys, &wire).unwrap();
    window.observe_request_for_sync(&observed).unwrap();
    assert_eq!(window.record(), &durable);
    assert_eq!(
        window.request_disposition(&observed),
        Err(Error::NoDurableWork)
    );
    let replay = f.peer_sync(Sync::new(NONCE, 7, 0));
    assert!(matches!(
        window.begin_sync_response(f.profile, &f.keys, &replay, None, None),
        Err(Error::Drop)
    ));
    let mut restored = f.restore(&durable, &iv_record);
    let mut allocator = Allocator::restore(f.domain.send_iv_domain(), &iv_record).unwrap();
    let block = allocator.prepare(1, Purpose::Ordinary).unwrap();
    let next_iv = block.record().clone();
    block.activate_after_commit(&next_iv).unwrap();
    let (record, token) = committed(
        f.prepare(&mut restored, &mut allocator, &replay, None, None)
            .unwrap(),
    );
    assert_eq!(record.sync_state().unwrap().highest_peer_request(), Some(6));
    assert_eq!(record.next_receive(), Some(7));
    assert_eq!(
        restored
            .release_sync_response(token)
            .unwrap()
            .into_parts()
            .1,
        Disposition::Continue
    );
    let older = f.peer_sync(Sync::new([9; 4], 6, 0));
    assert!(matches!(
        restored.begin_sync_response(f.profile, &f.keys, &older, None, None),
        Err(Error::Drop)
    ));
}

#[test]
fn pending_proposal_floors_dominate_and_foreign_or_superseded_proposals_drop() {
    let f = Fixture::new(ENCRYPTIONS[0], ROLES[0]);
    let mut counters = Counters::new(4, 4);
    counters.highest_local_request = Some(3);
    counters.highest_peer_request = Some(3);
    let pending = f.agreement.propose(Counters::new(9, 11), NONCE).unwrap();
    let wire = f.peer_sync(Sync::new([2; 4], 5, 5));
    let (mut window, mut allocator, _) = f.start(counters);
    let foreign =
        Agreement::from_persisted(Sa::new(0x999, 0x202, ROLES[0]).unwrap(), Mode::Negotiated)
            .propose(Counters::new(9, 11), NONCE)
            .unwrap();
    assert!(matches!(
        window.begin_sync_response(f.profile, &f.keys, &wire, Some(&foreign), None),
        Err(Error::Drop)
    ));
    let (record, token) = committed(
        f.prepare(&mut window, &mut allocator, &wire, Some(&pending), None)
            .unwrap(),
    );
    assert_eq!(
        (record.next_send(), record.next_receive()),
        (Some(9), Some(11))
    );
    let (reply, disposition) = window.release_sync_response(token).unwrap().into_parts();
    assert_eq!(disposition, Disposition::AwaitLocalSync);
    f.assert_reply(&reply, Sync::new([2; 4], 9, 11), 0);
    let mut counters = Counters::new(10, 11);
    counters.highest_local_proposal = Some(10);
    let (mut newer, _, _) = f.start(counters);
    assert!(matches!(
        newer.begin_sync_response(f.profile, &f.keys, &wire, Some(&pending), None),
        Err(Error::Drop)
    ));
    assert!(newer.replay_request().unwrap().is_none());
}

#[test]
fn cutover_retires_settled_caches_and_enforces_the_declared_ordinary_window() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        let (mut window, mut allocator, _) = f.start(Counters::new(0, 0));
        ordinary_commit(
            window
                .prepare_request(
                    f.profile,
                    &f.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    Exchange::Informational,
                    delete(),
                )
                .unwrap(),
        );
        let response = f.wire(
            f.header(true, Exchange::Informational, 0, true),
            empty(),
            Kind::Encrypted,
            102,
        );
        let response = window.open_peer(f.profile, &f.keys, &response).unwrap();
        ordinary_commit(
            window
                .prepare_completion(&response, Bytes::from_static(b"outcome-once"))
                .unwrap(),
        );
        let incoming = f.peer_ordinary(0, Exchange::Informational, delete());
        let incoming = window.open_peer(f.profile, &f.keys, &incoming).unwrap();
        let prepared = window
            .prepare_response(
                f.profile,
                &f.keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
                &incoming,
                empty(),
                Bytes::from_static(b"outcome-once"),
            )
            .unwrap();
        let history = prepared.record().clone();
        let retired_completion = prepared.commit_after_durable(&history).unwrap();
        let wire = f.peer_sync(Sync::new(NONCE, 3, 4));
        let (record, token) = committed(
            f.prepare(&mut window, &mut allocator, &wire, None, None)
                .unwrap(),
        );
        assert!(record.outbound().is_none() && record.inbound().is_none());
        assert!(matches!(
            window.apply_committed(retired_completion),
            Err(Error::StaleCompletion)
        ));
        assert!(matches!(
            window.replay_response(&incoming),
            Err(Error::Drop)
        ));
        assert!(matches!(
            window.prepare_completion(&response, Bytes::new()),
            Err(Error::Drop)
        ));
        assert!(window.replay_request().unwrap().is_none());
        assert_eq!(
            history.inbound().unwrap().outcome(),
            Some(b"outcome-once".as_slice())
        );
        let (reply, disposition) = window.release_sync_response(token).unwrap().into_parts();
        assert_eq!(disposition, Disposition::Continue);
        f.assert_reply(&reply, Sync::new(NONCE, 4, 3), 2);
        for id in [2, 3, 4] {
            let peer = f.peer_ordinary(id, Exchange::Informational, delete());
            let peer = window.open_peer(f.profile, &f.keys, &peer).unwrap();
            let result = window.request_disposition(&peer);
            if id == 3 {
                assert_eq!(
                    result,
                    Ok(opc_proto_ikev2::recovery::Ikev2OrdinaryRequestDisposition::New)
                );
            } else {
                assert_eq!(result, Err(Error::Drop));
            }
        }
    }
}

#[test]
fn a_foreign_iv_allocation_burns_no_window_commit_and_requires_readback() {
    let f = Fixture::new(ENCRYPTIONS[0], ROLES[0]);
    let foreign = Fixture::new(ENCRYPTIONS[0], ROLES[1]);
    let (mut window, _, _) = f.start(Counters::new(0, 0));
    let (_, mut wrong_allocator, _) = foreign.start(Counters::new(0, 0));
    let original = window.record().clone();
    let wire = f.peer_sync(Sync::new(NONCE, 1, 2));
    let admitted = window
        .begin_sync_response(f.profile, &f.keys, &wire, None, None)
        .unwrap();
    assert!(matches!(
        admitted.prepare(
            f.profile,
            &f.keys,
            wrong_allocator.allocate(Purpose::Ordinary).unwrap()
        ),
        Err(Error::Iv(_))
    ));
    assert_eq!(window.record(), &original);
    assert!(matches!(
        window.replay_request(),
        Err(Error::CommitUncertain)
    ));
}

#[test]
fn sync_commit_permissions_are_single_runtime_and_generation_bound() {
    let f = Fixture::new(ENCRYPTIONS[0], ROLES[0]);
    let (mut window, mut allocator, iv_record) = f.start(Counters::new(0, 0));
    let first = f.peer_sync(Sync::new([1; 4], 1, 0));
    let (record, token) = committed(
        f.prepare(&mut window, &mut allocator, &first, None, None)
            .unwrap(),
    );
    let mut restored = f.restore(&record, &iv_record);
    assert!(matches!(
        restored.release_sync_response(token),
        Err(Error::StaleCompletion)
    ));
    let second = f.peer_sync(Sync::new([2; 4], 2, 0));
    let (_, older_generation) = committed(
        f.prepare(&mut window, &mut allocator, &second, None, None)
            .unwrap(),
    );
    let third = f.peer_sync(Sync::new([3; 4], 3, 0));
    let (_, current) = committed(
        f.prepare(&mut window, &mut allocator, &third, None, None)
            .unwrap(),
    );
    assert!(matches!(
        window.release_sync_response(older_generation),
        Err(Error::StaleCompletion)
    ));
    assert_eq!(
        window
            .release_sync_response(current)
            .unwrap()
            .into_parts()
            .1,
        Disposition::Continue
    );
}

#[test]
fn storage_outage_cannot_refresh_the_same_sync_response_reservation_budget() {
    let f = Fixture::new(ENCRYPTIONS[0], ROLES[0]);
    let original = f.record(Counters::new(0, 0), Disposition::Continue);
    let policy = Policy::new(1000, 2000, 3, 100).unwrap();
    let mut charge = RetryRecord::initial(f.domain.send_iv_domain().clone(), 42, policy);
    let mut iv_record = f.iv_record(0);
    let wire = f.peer_sync(Sync::new(NONCE, 1, 0));
    for attempt in 0..3 {
        let now = 1000 + attempt * 100;
        let mut window = f.restore(&original, &iv_record);
        let admitted = window
            .begin_sync_response(f.profile, &f.keys, &wire, None, None)
            .unwrap();
        let mut allocator = Allocator::restore(f.domain.send_iv_domain(), &iv_record).unwrap();
        let mut retry = Retry::restore(f.domain.send_iv_domain(), 42, &charge).unwrap();
        let prepared = retry.prepare_attempt(&allocator, now, false).unwrap();
        charge = prepared.record().clone();
        let permit = prepared.commit_after_durable(&charge).unwrap();
        let block = permit
            .prepare(&mut allocator, 1, Purpose::Ordinary, now, false)
            .unwrap();
        iv_record = block.record().clone();
        block.activate_after_commit(&iv_record, now, false).unwrap();
        drop(
            admitted
                .prepare(
                    f.profile,
                    &f.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap(),
        );
        assert!(matches!(
            window.replay_request(),
            Err(Error::CommitUncertain)
        ));
        assert_eq!(window.record(), &original);
        assert_eq!(iv_record.exclusive_end(), attempt + 1);
    }
    let allocator = Allocator::restore(f.domain.send_iv_domain(), &iv_record).unwrap();
    let mut retry = Retry::restore(f.domain.send_iv_domain(), 42, &charge).unwrap();
    assert!(matches!(
        retry.prepare_attempt(&allocator, 1300, false),
        Err(RetryError::Closed)
    ));
    assert_eq!(charge.attempts(), 3);
    assert_eq!(charge.policy(), policy);
    assert_eq!(iv_record.exclusive_end(), 3);
    assert_eq!(
        original.sync_state().unwrap().agreement().mode(),
        Mode::Negotiated
    );
}

#[test]
fn exhausted_counter_or_generation_never_becomes_a_successful_sync() {
    let f = Fixture::new(ENCRYPTIONS[0], ROLES[0]);
    let (mut window, _, _) = f.start(Counters::new(0, 0));
    let original = window.record().clone();
    for value in [Sync::new(NONCE, u32::MAX, 0), Sync::new(NONCE, 1, u32::MAX)] {
        assert!(matches!(
            window.begin_sync_response(f.profile, &f.keys, &f.peer_sync(value), None, None),
            Err(Error::SyncRule(RuleError::RekeyRequired))
        ));
        assert_eq!(window.record(), &original);
    }
    let record = Record::from_persisted(f.domain.clone(), u64::MAX, Some(0), Some(0), None, None)
        .unwrap()
        .with_sync_state(*original.sync_state().unwrap())
        .unwrap();
    let mut exhausted = f.restore(&record, &f.iv_record(0));
    assert!(matches!(
        exhausted.begin_sync_response(
            f.profile,
            &f.keys,
            &f.peer_sync(Sync::new(NONCE, 1, 0)),
            None,
            None
        ),
        Err(Error::Exhausted)
    ));
    assert_eq!(exhausted.record(), &record);
}

#[test]
fn restored_local_sync_wait_survives_omitted_pending_and_uncertain_work_takes_priority() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        let (mut window, mut allocator, iv_record) = f.start(Counters::new(4, 7));
        let pending = f.agreement.propose(Counters::new(4, 7), [1; 4]).unwrap();
        let wire = f.peer_sync(Sync::new(NONCE, 5, 4));
        let (record, token) = committed(
            f.prepare(&mut window, &mut allocator, &wire, Some(&pending), None)
                .unwrap(),
        );
        assert_eq!(
            window.release_sync_response(token).unwrap().into_parts().1,
            Disposition::AwaitLocalSync
        );
        let mut restored = f.restore(&record, &iv_record);
        let newer = f.peer_sync(Sync::new([2; 4], 6, 4));
        let (record, token) = committed(
            f.prepare(&mut restored, &mut allocator, &newer, None, None)
                .unwrap(),
        );
        assert_eq!(record.next_receive(), Some(7)); // Retain declared P1.
        assert_eq!(
            restored
                .release_sync_response(token)
                .unwrap()
                .into_parts()
                .1,
            Disposition::AwaitLocalSync
        );
        let restored = f.restore(&record, &iv_record);
        let request = f.peer_ordinary(7, Exchange::Informational, delete());
        let request = restored.open_peer(f.profile, &f.keys, &request).unwrap();
        assert_eq!(
            restored.request_disposition(&request),
            Err(Error::SyncInProgress)
        );

        let (mut window, mut allocator, iv_record) = f.start(Counters::new(4, 7));
        ordinary_commit(
            window
                .prepare_request(
                    f.profile,
                    &f.keys,
                    allocator.allocate(Purpose::Ordinary).unwrap(),
                    Exchange::CreateChildSa,
                    delete(),
                )
                .unwrap(),
        );
        let pending = f.agreement.propose(Counters::new(5, 7), [3; 4]).unwrap();
        let (record, token) = committed(
            f.prepare(&mut window, &mut allocator, &wire, Some(&pending), None)
                .unwrap(),
        );
        assert_eq!(
            record.sync_state().unwrap().disposition(),
            Disposition::OutcomeUncertain
        );
        assert_eq!(
            window.release_sync_response(token).unwrap().into_parts().1,
            Disposition::OutcomeUncertain
        );
        assert!(matches!(
            f.restore(&record, &iv_record).replay_request(),
            Err(Error::OutcomeUncertain)
        ));
    }
}

#[test]
fn new_request_admission_automatically_protects_the_sync_drop_floor() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        let (mut window, mut allocator, iv_record) = f.start(Counters::new(4, 7));
        let wire = f.peer_ordinary(7, Exchange::CreateChildSa, delete());
        let request = window.open_peer(f.profile, &f.keys, &wire).unwrap();
        assert_eq!(
            window.request_disposition(&request),
            Ok(opc_proto_ikev2::recovery::Ikev2OrdinaryRequestDisposition::New)
        );
        let original = window.record().clone();
        // No explicit observer or pending-inbound argument is needed for this drop.
        let same = f.peer_sync(Sync::new(NONCE, 7, 4));
        assert!(matches!(
            window.begin_sync_response(f.profile, &f.keys, &same, None, None),
            Err(Error::Drop)
        ));
        assert_eq!(window.record(), &original);
        let higher = f.peer_sync(Sync::new(NONCE, 8, 4));
        let (record, token) = committed(
            f.prepare(&mut window, &mut allocator, &higher, None, None)
                .unwrap(),
        );
        assert_eq!(record.sync_state().unwrap().highest_peer_request(), Some(7));
        assert_eq!(record.next_receive(), Some(8));
        // Admission now retains the pending identity as well as the drop bound;
        // omitting pending_inbound cannot make this unfinished mutation disappear.
        assert_eq!(
            record.sync_state().unwrap().disposition(),
            Disposition::OutcomeUncertain
        );
        let _reply = window.release_sync_response(token).unwrap();
        assert_eq!(
            window.request_disposition(&request),
            Err(Error::OutcomeUncertain)
        );
        let restored = f.restore(&record, &iv_record);
        assert_eq!(
            restored.request_disposition(&request),
            Err(Error::OutcomeUncertain)
        );
    }
}

#[test]
fn cutover_restore_retains_reply_and_retired_packet_iv_bounds() {
    for algorithm in ENCRYPTIONS {
        for role in ROLES {
            let f = Fixture::new(algorithm, role);
            for retired in [None, Some((7, 3)), Some((3, 7))] {
                let (mut window, mut allocator, iv_record) = f.start(Counters::new(2, 3));
                if let Some((request_iv, response_iv)) = retired {
                    let outbound = ExchangeRecord::from_persisted(
                        f.wire(
                            f.header(false, Exchange::Informational, 1, false),
                            delete(),
                            Kind::Encrypted,
                            request_iv,
                        ),
                        Some(f.wire(
                            f.header(true, Exchange::Informational, 1, true),
                            empty(),
                            Kind::Encrypted,
                            90,
                        )),
                        Some(Bytes::new()),
                    )
                    .unwrap();
                    let inbound = ExchangeRecord::from_persisted(
                        f.peer_ordinary(2, Exchange::Informational, delete()),
                        Some(f.wire(
                            f.header(false, Exchange::Informational, 2, true),
                            empty(),
                            Kind::Encrypted,
                            response_iv,
                        )),
                        Some(Bytes::new()),
                    )
                    .unwrap();
                    let record = Record::from_persisted(
                        f.domain.clone(),
                        1,
                        Some(2),
                        Some(3),
                        Some(outbound),
                        Some(inbound),
                    )
                    .unwrap()
                    .with_sync_state(
                        SyncRecord::from_persisted(
                            f.agreement,
                            Some(1),
                            Some(2),
                            None,
                            None,
                            Disposition::Continue,
                            0,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    window = f.restore(&record, &iv_record);
                }
                // Synthetic older packet IVs exceed this allocator's first reply IV.
                // This separately exercises both retired directions and prior cutovers.
                let wire = f.peer_sync(Sync::new(NONCE, 4, 2));
                let (record, token) = committed(
                    f.prepare(&mut window, &mut allocator, &wire, None, None)
                        .unwrap(),
                );
                assert!(record.outbound().is_none() && record.inbound().is_none());
                let _reply = window.release_sync_response(token).unwrap();
                let minimum = if retired.is_some() { 8 } else { 1 };
                let state = record.sync_state().unwrap();
                assert_eq!(state.minimum_send_iv_end(), minimum);
                let rebuilt = Record::from_persisted(
                    record.domain().clone(),
                    record.generation(),
                    record.next_send(),
                    record.next_receive(),
                    None,
                    None,
                )
                .unwrap()
                .with_sync_state(
                    SyncRecord::from_persisted(
                        state.agreement(),
                        state.highest_local_request(),
                        state.highest_peer_request(),
                        state.highest_local_proposal(),
                        state.highest_peer_proposal(),
                        state.disposition(),
                        state.minimum_send_iv_end(),
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(rebuilt, record);
                for end in 0..minimum {
                    assert!(
                        matches!(
                            Window::restore(
                                &f.domain,
                                f.profile,
                                &f.keys,
                                &record,
                                &f.iv_record(end),
                            ),
                            Err(Error::InvalidRecord)
                        ),
                        "accepted rolled-back IV end {end}"
                    );
                }
                let mut restored = f.restore(&record, &f.iv_record(minimum));
                let newer = f.peer_sync(Sync::new([2; 4], 5, 2));
                let (record, token) = committed(
                    f.prepare(&mut restored, &mut allocator, &newer, None, None)
                        .unwrap(),
                );
                let _reply = restored.release_sync_response(token).unwrap();
                let minimum = minimum.max(2);
                assert_eq!(record.sync_state().unwrap().minimum_send_iv_end(), minimum);
                assert!(matches!(
                    Window::restore(
                        &f.domain,
                        f.profile,
                        &f.keys,
                        &record,
                        &f.iv_record(minimum - 1),
                    ),
                    Err(Error::InvalidRecord)
                ));
                let _restored = f.restore(&record, &f.iv_record(minimum));
            }
        }
    }
}

#[test]
fn persisted_minimum_iv_end_must_fit_the_allocator_range_and_cover_empty_caches() {
    let f = Fixture::new(ENCRYPTIONS[0], ROLES[0]);
    for end in [
        0,
        128,
        opc_proto_ikev2::IKEV2_AES_GCM_MAX_RESERVED_ALLOCATIONS,
    ] {
        let state = SyncRecord::from_persisted(
            f.agreement,
            None,
            None,
            None,
            None,
            Disposition::Continue,
            end,
        )
        .unwrap();
        assert_eq!(state.minimum_send_iv_end(), end);
    }
    for end in [
        opc_proto_ikev2::IKEV2_AES_GCM_MAX_RESERVED_ALLOCATIONS + 1,
        u64::MAX,
    ] {
        assert!(matches!(
            SyncRecord::from_persisted(
                f.agreement,
                None,
                None,
                None,
                None,
                Disposition::Continue,
                end,
            ),
            Err(Error::InvalidRecord)
        ));
    }
    let state = SyncRecord::from_persisted(
        f.agreement,
        None,
        None,
        None,
        None,
        Disposition::Continue,
        128,
    )
    .unwrap();
    let record = Record::from_persisted(f.domain.clone(), 1, Some(0), Some(0), None, None)
        .unwrap()
        .with_sync_state(state)
        .unwrap();
    assert!(matches!(
        Window::restore(&f.domain, f.profile, &f.keys, &record, &f.iv_record(127),),
        Err(Error::InvalidRecord)
    ));
    let _restored = f.restore(&record, &f.iv_record(128));
}

#[test]
fn exhausted_windows_drop_duplicate_sync_before_returning_fresh_exhaustion_intents() {
    for role in ROLES {
        let f = Fixture::new(ENCRYPTIONS[0], role);
        for exhausted_send in [true, false] {
            let (outbound, inbound, send, receive, local, peer) = if exhausted_send {
                (
                    Some(
                        ExchangeRecord::from_persisted(
                            f.wire(
                                f.header(false, Exchange::CreateChildSa, u32::MAX, false),
                                delete(),
                                Kind::Encrypted,
                                0,
                            ),
                            None,
                            None,
                        )
                        .unwrap(),
                    ),
                    None,
                    None,
                    Some(4),
                    Some(u32::MAX),
                    Some(3),
                )
            } else {
                (
                    None,
                    Some(
                        ExchangeRecord::from_persisted(
                            f.peer_ordinary(u32::MAX, Exchange::Informational, delete()),
                            Some(f.wire(
                                f.header(false, Exchange::Informational, u32::MAX, true),
                                empty(),
                                Kind::Encrypted,
                                0,
                            )),
                            Some(Bytes::new()),
                        )
                        .unwrap(),
                    ),
                    Some(1),
                    None,
                    Some(0),
                    Some(u32::MAX),
                )
            };
            let record =
                Record::from_persisted(f.domain.clone(), 1, send, receive, outbound, inbound)
                    .unwrap()
                    .with_sync_state(
                        SyncRecord::from_persisted(
                            f.agreement,
                            local,
                            peer,
                            None,
                            None,
                            Disposition::Continue,
                            0,
                        )
                        .unwrap(),
                    )
                    .unwrap();
            let mut window = f.restore(&record, &f.iv_record(1));
            for m1 in [0, peer.unwrap()] {
                let duplicate = f.peer_sync(Sync::new(NONCE, m1, 0));
                assert!(matches!(
                    window.begin_sync_response(f.profile, &f.keys, &duplicate, None, None,),
                    Err(Error::Drop)
                ));
            }
            if exhausted_send {
                let fresh = f.peer_sync(Sync::new(NONCE, 4, 0));
                assert!(matches!(
                    window.begin_sync_response(f.profile, &f.keys, &fresh, None, None,),
                    Err(Error::SyncRule(RuleError::CloseIkeSa))
                ));
            }
            assert_eq!(window.record(), &record);
        }
    }
}

#[test]
fn unexpected_pending_request_and_unnegotiated_observation_drop() {
    let f = Fixture::new(ENCRYPTIONS[0], ROLES[0]);
    let (mut window, _, iv_record) = f.start(Counters::new(4, 7));
    for id in [6, 8] {
        let wire = f.peer_ordinary(id, Exchange::Informational, delete());
        let request = window.open_peer(f.profile, &f.keys, &wire).unwrap();
        let sync = f.peer_sync(Sync::new(NONCE, 9, 4));
        assert!(matches!(
            window.begin_sync_response(f.profile, &f.keys, &sync, None, Some(&request),),
            Err(Error::Drop)
        ));
    }
    let record = Record::initial(f.domain.clone(), 4, 7);
    let mut window = f.restore(&record, &iv_record);
    let wire = f.peer_ordinary(7, Exchange::Informational, delete());
    let request = window.open_peer(f.profile, &f.keys, &wire).unwrap();
    assert_eq!(window.observe_request_for_sync(&request), Err(Error::Drop));
}
