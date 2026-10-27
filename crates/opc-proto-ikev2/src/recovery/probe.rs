#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::super::{
        Ikev2CommittedWindow as Window, Ikev2GcmRecoveryProfile as Gcm,
        Ikev2LivenessProbePolicy as Policy, Ikev2WindowError as Error,
    };
    use crate::canonical_test_fixtures::{delete, empty, Fixture};
    use crate::recovery::{
        cbc_test_fixtures, Ikev2CommittedWindowDomain as Domain,
        Ikev2OrdinaryRequestDisposition as Disposition,
    };
    use crate::{
        decode_header, open_protected_payloads, Ikev2AesGcmIvPurpose as Purpose,
        Ikev2EncryptionAlgorithm as Encryption, Ikev2ProtectedPayloadDirection as Direction,
        Ikev2SaInitProtectedPayloadProvider, Message, ProtectedPayloadKind,
    };
    use crate::{Ikev2ExchangeKind, PayloadType};
    use bytes::Bytes;
    use opc_protocol::{BorrowDecode, DecodeContext};

    fn fixture(tag: u64) -> Fixture {
        crate::test_support::ensure_ike_crypto();
        let mut f = Fixture::new(
            tag,
            Encryption::AesGcm16_128,
            Direction::InitiatorToResponder,
        );
        enable(&mut f.window);
        f
    }

    fn enable<P: super::super::profile::RecoveryProfile>(window: &mut Window<P>) {
        let prepared = window.prepare_liveness(4).unwrap();
        let row = prepared.record().clone();
        let _commit = prepared.commit_after_durable(&row).unwrap();
    }

    fn policy() -> Policy {
        Policy::new(1_000, 4, 10).unwrap()
    }

    fn send_probe(f: &mut Fixture) -> (u32, Vec<u8>) {
        let request = f
            .window
            .start_empty_probe(f.profile, &f.keys, &mut f.allocator, policy(), 100)
            .unwrap();
        (request.message_id(), request.bytes().to_vec())
    }

    fn answer_probe(f: &mut Fixture, id: u32) {
        let wire = f.peer(id, true, 37, empty(), 0, 0x9100);
        let response = f.window.open_peer(f.profile, &f.keys, &wire).unwrap();
        f.window.complete_empty_probe(&response, 101).unwrap();
    }

    #[test]
    fn seals_an_authenticated_empty_informational_request() {
        let mut f = fixture(91_001);
        let (id, bytes) = send_probe(&mut f);
        assert_eq!(id, 0);

        let (payload_region, header) = decode_header(&bytes, DecodeContext::default()).unwrap();
        assert_eq!(payload_region.len(), bytes.len() - crate::HEADER_LEN);
        assert_eq!(
            header.exchange_type,
            Ikev2ExchangeKind::Informational.as_u8()
        );
        assert_eq!(header.message_id, id);
        assert!(!header.flags.response());
        assert_eq!(header.next_payload, PayloadType::Encrypted.as_u8());

        // The peer opens the exact same authenticated empty chain.
        let (rest, message) = Message::decode(&bytes, DecodeContext::default()).unwrap();
        assert!(rest.is_empty());
        let provider = Ikev2SaInitProtectedPayloadProvider::new(f.profile, &f.keys, f.direction);
        let opened =
            open_protected_payloads(&message, &bytes, DecodeContext::default(), &provider).unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].kind, ProtectedPayloadKind::Encrypted);
        assert_eq!(opened[0].first_inner_payload, PayloadType::NoNext);
        assert!(opened[0].cleartext.is_empty());
    }

    #[test]
    fn a_matching_authenticated_response_completes_the_probe() {
        let mut f = fixture(91_002);
        let (id, _) = send_probe(&mut f);
        assert_eq!(f.window.pending_empty_request_message_id(), Some(id));

        let wire = f.peer(
            id,
            true,
            Ikev2ExchangeKind::Informational.as_u8(),
            empty(),
            0,
            0x2000,
        );
        let response = f.window.open_peer(f.profile, &f.keys, &wire).unwrap();
        f.window.complete_empty_probe(&response, 101).unwrap();
        assert_eq!(f.window.pending_empty_request_message_id(), None);
        assert_eq!(f.window.retry_empty_probe(102).err(), Some(Error::Drop));
        // A duplicate response after completion is an unknown exchange.
        assert_eq!(
            f.window.complete_empty_probe(&response, 102),
            Err(Error::Drop)
        );
    }

    #[test]
    fn unknown_ids_wrong_exchange_and_failed_integrity_do_not_complete() {
        let mut f = fixture(91_003);
        let (id, _) = send_probe(&mut f);

        let wrong_id = f.peer(
            id.wrapping_add(1),
            true,
            Ikev2ExchangeKind::Informational.as_u8(),
            empty(),
            0,
            0x2100,
        );
        let opened = f.window.open_peer(f.profile, &f.keys, &wrong_id).unwrap();
        assert_eq!(
            f.window.complete_empty_probe(&opened, 101),
            Err(Error::Drop)
        );
        assert_eq!(f.window.pending_empty_request_message_id(), Some(id));

        // The right Message ID in another exchange cannot settle this probe.
        let wrong_exchange = f.peer(
            id,
            true,
            Ikev2ExchangeKind::CreateChildSa.as_u8(),
            delete(),
            0,
            0x2101,
        );
        let opened = f
            .window
            .open_peer(f.profile, &f.keys, &wrong_exchange)
            .unwrap();
        assert_eq!(
            f.window.complete_empty_probe(&opened, 101),
            Err(Error::Drop)
        );
        assert_eq!(f.window.pending_empty_request_message_id(), Some(id));

        // A tampered response never authenticates, so it cannot complete.
        let mut tampered = f
            .peer(
                id,
                true,
                Ikev2ExchangeKind::Informational.as_u8(),
                empty(),
                0,
                0x2102,
            )
            .to_vec();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            f.window.open_peer(f.profile, &f.keys, &tampered).err(),
            Some(Error::Drop)
        );
        assert_eq!(f.window.pending_empty_request_message_id(), Some(id));
    }

    #[test]
    fn bounded_retries_preserve_exact_bytes_and_expiry_is_terminal_without_a_write() {
        let mut f = fixture(91_004);
        let (id, first) = send_probe(&mut f);
        let durable_before = f.window.record().clone();
        for now in [110, 130, 170] {
            assert_eq!(f.window.retry_empty_probe(now).unwrap().bytes(), first);
        }
        assert_eq!(
            f.window.retry_empty_probe(250).err(),
            Some(Error::LivenessRetryLimit)
        );
        assert_eq!(f.window.record(), &durable_before);
        assert_eq!(
            f.window.check_empty_probe_deadline(1_100),
            Err(Error::LivenessExpired)
        );
        assert_eq!(f.window.ready(), Err(Error::LivenessExpired));
        assert_eq!(f.window.record(), &durable_before);
        assert_eq!(f.window.next_send_message_id(), Some(id + 1));

        // A late authenticated response cannot clear the terminal failure.
        let late = f.peer(id, true, 37, empty(), 0, 0x2200);
        let opened = f.window.open_peer(f.profile, &f.keys, &late).unwrap();
        assert_eq!(
            f.window.complete_empty_probe(&opened, 1_101),
            Err(Error::LivenessExpired)
        );
    }

    #[test]
    fn ordinary_work_is_refused_until_the_probe_is_answered() {
        let mut f = fixture(91_005);
        let (id, _) = send_probe(&mut f);
        let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
        assert_eq!(
            f.window
                .prepare_request(
                    f.profile,
                    &f.keys,
                    allocation,
                    Ikev2ExchangeKind::Informational,
                    delete(),
                )
                .err(),
            Some(Error::RequestOutstanding)
        );

        answer_probe(&mut f, id);
        let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
        let prepared = f
            .window
            .prepare_request(
                f.profile,
                &f.keys,
                allocation,
                Ikev2ExchangeKind::Informational,
                delete(),
            )
            .unwrap();
        // The answered probe ID is consumed; ordinary work starts after it.
        assert_eq!(prepared.record().next_send(), Some(id + 2));
    }

    #[test]
    fn the_next_committed_operation_persists_the_probe_lead() {
        let mut f = fixture(91_006);
        let (probe_id, _) = send_probe(&mut f);
        answer_probe(&mut f, probe_id);
        let Fixture {
            profile,
            keys,
            iv,
            mut allocator,
            mut window,
            ..
        } = f;

        let allocation = allocator.allocate(Purpose::Ordinary).unwrap();
        let prepared = window
            .prepare_request(
                profile,
                &keys,
                allocation,
                Ikev2ExchangeKind::Informational,
                delete(),
            )
            .unwrap();
        let candidate = prepared.record().clone();
        assert_eq!(candidate.next_send(), Some(probe_id + 2));
        let commit = prepared.commit_after_durable(&candidate).unwrap();
        assert!(window.apply_committed(commit).unwrap().is_none());

        // Restart from the committed record observes the folded lead.
        drop(window);
        let restored: Window<Gcm> = Window::restore(
            &Domain::<Gcm>::from_iv_record(&iv),
            profile,
            &keys,
            &candidate,
            &iv,
        )
        .unwrap();
        assert_eq!(restored.record().next_send(), Some(probe_id + 2));
        assert_eq!(restored.next_send_message_id(), Some(probe_id + 2));
        assert_eq!(restored.pending_empty_request_message_id(), None);
    }

    #[test]
    fn restart_without_a_commit_skips_the_bound_and_requires_synchronization() {
        let mut f = fixture(91_007);
        let (id, _) = send_probe(&mut f);
        assert_eq!(id, 0);
        let durable_before = f.window.record().clone();
        drop(f.window);
        let mut restored: Window<Gcm> = Window::restore(
            &Domain::<Gcm>::from_iv_record(&f.iv),
            f.profile,
            &f.keys,
            &durable_before,
            &f.iv,
        )
        .unwrap();
        assert_eq!(restored.record().next_send(), Some(id));
        assert_eq!(restored.next_send_message_id(), Some(id + 4));
        assert_eq!(restored.pending_empty_request_message_id(), None);
        assert_eq!(restored.ready(), Err(Error::LivenessRecoveryRequired));
        assert_eq!(
            restored
                .start_empty_probe(f.profile, &f.keys, &mut f.allocator, policy(), 100,)
                .err(),
            Some(Error::LivenessRecoveryRequired)
        );
        assert_eq!(
            restored
                .prepare_request(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    Ikev2ExchangeKind::Informational,
                    delete(),
                )
                .err(),
            Some(Error::LivenessRecoveryRequired)
        );
    }

    #[test]
    fn peer_work_in_the_receive_direction_remains_admissible() {
        let mut f = fixture(91_008);
        let (probe_id, _) = send_probe(&mut f);

        let wire = f.peer(
            0,
            false,
            Ikev2ExchangeKind::Informational.as_u8(),
            delete(),
            0,
            0x2300,
        );
        let peer_request = f.window.open_peer(f.profile, &f.keys, &wire).unwrap();
        assert_eq!(
            f.window.request_disposition(&peer_request).unwrap(),
            Disposition::New
        );

        let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
        let prepared = f
            .window
            .prepare_response(
                f.profile,
                &f.keys,
                allocation,
                &peer_request,
                empty(),
                bytes::Bytes::from_static(b"accepted"),
            )
            .unwrap();
        let candidate = prepared.record().clone();
        // The inbound commit also persists the volatile probe send-ID advance.
        assert_eq!(candidate.next_send(), Some(probe_id + 1));
        assert_eq!(candidate.next_receive(), Some(1));
        let commit = prepared.commit_after_durable(&candidate).unwrap();
        assert!(f.window.apply_committed(commit).unwrap().is_some());
        assert_eq!(f.window.pending_empty_request_message_id(), Some(probe_id));
    }

    #[test]
    fn empty_peer_requests_are_answered_while_the_probe_is_outstanding() {
        let mut f = fixture(91_009);
        f.window
            .enable_empty_replies(crate::canonical::Ikev2CanonicalPolicy::default())
            .unwrap();
        let (probe_id, _) = send_probe(&mut f);

        let peer_request = f.request(0);
        let reply = f.window.reply_empty(&peer_request).unwrap();
        // The fixture is a restored window, so its first stateless prefix is
        // reconstruction-uncertain; the outstanding probe does not change that.
        assert_eq!(
            reply.observation(),
            crate::recovery::Ikev2EmptyReplyObservation::Uncertain
        );
        assert!(!reply.bytes().is_empty());
        drop(reply);
        assert_eq!(f.window.pending_empty_request_message_id(), Some(probe_id));
    }

    #[test]
    fn cbc_profile_seals_and_completes_with_a_random_iv() {
        let f = cbc_test_fixtures::Fixture::new(
            cbc_test_fixtures::profiles().next().unwrap(),
            cbc_test_fixtures::DIRECTIONS[0],
            91_010,
        );
        let mut window = f.window();
        enable(&mut window);
        let request = window
            .start_empty_probe(f.profile, &f.keys, policy(), 100)
            .unwrap();
        assert_eq!(request.message_id(), 1);
        drop(request);

        let response = f.peer_packet(
            1,
            true,
            crate::PayloadChain::new(crate::PayloadType::NoNext, &[]),
            0,
        );
        let opened = window.open_peer(f.profile, &f.keys, &response).unwrap();
        window.complete_empty_probe(&opened, 101).unwrap();
        assert_eq!(window.pending_empty_request_message_id(), None);
    }

    fn settle_outbound(f: &mut Fixture) {
        let allocation = f.allocator.allocate(Purpose::Ordinary).unwrap();
        let prepared = f
            .window
            .prepare_request(
                f.profile,
                &f.keys,
                allocation,
                Ikev2ExchangeKind::Informational,
                delete(),
            )
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        f.window.apply_committed(commit).unwrap();
        let wire = f.peer(0, true, 37, empty(), 0, 0x9000);
        let response = f.window.open_peer(f.profile, &f.keys, &wire).unwrap();
        let prepared = f
            .window
            .prepare_completion(&response, Bytes::from_static(b"settled"))
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        assert_eq!(
            f.window.apply_committed(commit).unwrap(),
            Some(Bytes::from_static(b"settled"))
        );
    }

    fn commit_peer_work_after_probe(
        f: &mut Fixture,
    ) -> super::super::Ikev2CommittedWindowRecord<Gcm> {
        let wire = f.peer(0, false, 37, delete(), 0, 0x9001);
        let request = f.window.open_peer(f.profile, &f.keys, &wire).unwrap();
        let prepared = f
            .window
            .prepare_response(
                f.profile,
                &f.keys,
                f.allocator.allocate(Purpose::Ordinary).unwrap(),
                &request,
                empty(),
                Bytes::from_static(b"peer-work"),
            )
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        assert_eq!(
            f.window.apply_committed(commit).unwrap(),
            Some(Bytes::from_static(b"peer-work"))
        );
        row
    }

    #[test]
    fn settled_outbound_cache_and_newer_probe_survive_inbound_commit_and_restore() {
        let mut f = fixture(92_001);
        settle_outbound(&mut f);
        let (id, _) = send_probe(&mut f);
        assert_eq!(id, 1);
        let row = commit_peer_work_after_probe(&mut f);
        assert_eq!(row.next_send(), Some(2));
        let restored: Window<Gcm> = Window::restore(
            &Domain::from_iv_record(&f.iv),
            f.profile,
            &f.keys,
            &row,
            &f.iv,
        )
        .unwrap();
        assert_eq!(
            restored.record().outbound().unwrap().outcome(),
            Some(b"settled".as_slice())
        );
    }

    #[test]
    fn settled_outbound_cache_and_newer_probe_survive_inbound_readback() {
        let mut f = fixture(92_002);
        settle_outbound(&mut f);
        send_probe(&mut f);
        let row = commit_peer_work_after_probe(&mut f);
        assert_eq!(f.window.reconcile(f.profile, &f.keys, &row, &f.iv), Ok(()));
        assert_eq!(f.window.record(), &row);
    }

    #[test]
    fn cbc_settled_outbound_cache_and_newer_probe_survive_inbound_commit() {
        let f = cbc_test_fixtures::Fixture::new(
            cbc_test_fixtures::profiles().next().unwrap(),
            cbc_test_fixtures::DIRECTIONS[0],
            92_003,
        );
        let mut window = f.window();
        enable(&mut window);
        let prepared = window
            .prepare_request(
                f.profile,
                &f.keys,
                Ikev2ExchangeKind::Informational,
                delete(),
            )
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        window.apply_committed(commit).unwrap();
        let wire = f.peer_packet(1, true, empty(), 0);
        let response = window.open_peer(f.profile, &f.keys, &wire).unwrap();
        let prepared = window
            .prepare_completion(&response, Bytes::from_static(b"settled"))
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        window.apply_committed(commit).unwrap();
        let probe = window
            .start_empty_probe(f.profile, &f.keys, policy(), 100)
            .unwrap();
        assert_eq!(probe.message_id(), 2);
        drop(probe);
        let wire = f.peer_packet(1, false, delete(), 0);
        let request = window.open_peer(f.profile, &f.keys, &wire).unwrap();
        let prepared = window
            .prepare_response(
                f.profile,
                &f.keys,
                &request,
                empty(),
                Bytes::from_static(b"peer-work"),
            )
            .unwrap();
        let row = prepared.record().clone();
        let commit = prepared.commit_after_durable(&row).unwrap();
        window.apply_committed(commit).unwrap();
        let restored = f.restore(&row);
        assert_eq!(restored.record().next_send(), Some(3));
        assert_eq!(
            restored.record().outbound().unwrap().outcome(),
            Some(b"settled".as_slice())
        );
    }

    #[test]
    fn the_last_message_id_is_reserved_for_rekey_or_closure() {
        let mut f = fixture(92_004);
        let row = super::super::Ikev2CommittedWindowRecord::initial(
            Domain::from_iv_record(&f.iv),
            u32::MAX,
            0,
        );
        f.window = Window::restore(
            &Domain::from_iv_record(&f.iv),
            f.profile,
            &f.keys,
            &row,
            &f.iv,
        )
        .unwrap();
        enable(&mut f.window);
        assert_eq!(
            f.window
                .start_empty_probe(f.profile, &f.keys, &mut f.allocator, policy(), 100)
                .err(),
            Some(Error::Exhausted)
        );
    }

    #[test]
    fn an_answered_probe_cannot_be_reused_for_a_delete_after_restart() {
        let mut f = fixture(92_005);
        let (id, _) = send_probe(&mut f);
        let response = f.peer(id, true, 37, empty(), 0, 0x9002);
        let opened = f.window.open_peer(f.profile, &f.keys, &response).unwrap();
        f.window.complete_empty_probe(&opened, 101).unwrap();
        let row = f.window.record().clone();
        let mut restored: Window<Gcm> = Window::restore(
            &Domain::from_iv_record(&f.iv),
            f.profile,
            &f.keys,
            &row,
            &f.iv,
        )
        .unwrap();
        assert_eq!(
            restored
                .prepare_request(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                    Ikev2ExchangeKind::Informational,
                    delete()
                )
                .err(),
            Some(Error::LivenessRecoveryRequired),
            "restart must synchronize or retire before reusing the probe's ID for durable work"
        );
    }

    #[test]
    fn a_failed_probe_cannot_release_the_sa_for_another_request() {
        let mut f = fixture(92_006);
        send_probe(&mut f);
        assert_eq!(
            f.window.check_empty_probe_deadline(1_100),
            Err(Error::LivenessExpired)
        );
        assert_eq!(
            f.window.ready(),
            Err(Error::LivenessExpired),
            "exhausted liveness must retire the scoped SA"
        );
    }

    #[test]
    fn probe_origination_requires_a_durable_positive_bound() {
        crate::test_support::ensure_ike_crypto();
        let mut f = Fixture::new(
            92_007,
            Encryption::AesGcm16_128,
            Direction::InitiatorToResponder,
        );
        assert_eq!(
            f.window
                .start_empty_probe(f.profile, &f.keys, &mut f.allocator, policy(), 100)
                .err(),
            Some(Error::LivenessDisabled),
            "an unconfigured SA has no safe crash bound for unwritten probes"
        );
    }
}
