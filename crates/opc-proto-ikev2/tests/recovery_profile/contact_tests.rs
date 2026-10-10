use super::{
    auth,
    authority::{EpochOwners, Transport},
    codec::ProfileCodec,
    contact,
    driver::{self, Cut, Runtime},
    envelope::{self, Provider},
    inputs,
    lifecycle::matrix,
    peer::{Event, PeerModel},
    store::{CasStore, Command, Mutation},
    wire::Wire,
};
use opc_proto_ikev2::{Ikev2MessageIdSyncMode as Mode, PayloadChain, PayloadType};

#[test]
fn initial_contact_commits_authenticated_identity_intents_and_preserves_new_or_unrelated_epochs() {
    for (cut_id, cut) in [
        Cut::BeforeDispatch,
        Cut::Dispatched,
        Cut::Applied,
        Cut::Acknowledged,
    ]
    .into_iter()
    .enumerate()
    {
        matrix(2_800_000 + cut_id as u64 * 1000, |row| {
            let row = auth::before_final(row);
            let provider = Provider::new();
            let mut store = CasStore::new(7);
            let owners = EpochOwners::new(7);
            let mut victims = Vec::new();
            for kind in 0..4 {
                let mut other = inputs::fresh(
                    row.key.0 + 10_000_000 + kind,
                    row.profile,
                    row.direction,
                    row.mode,
                );
                if kind == 1 {
                    other.identity += 1;
                }
                if kind == 2 {
                    other.namespace += 1;
                }
                driver::create(&provider, &mut store, &other).unwrap();
                victims.push(other);
            }
            let initial = driver::create(&provider, &mut store, &row).unwrap();
            let joined = store.fenced_read(&initial, row.key).unwrap();
            let mut runtime = Runtime::restore(&provider, &owners, &joined, false).unwrap();
            let local = auth::initiator(&row);
            let mut peer = PeerModel::new(
                Wire::new(
                    row.profile,
                    &row.keys,
                    row.spis,
                    crate::canonical_fixtures::opposite(row.direction),
                ),
                if local { 0 } else { auth::FINAL_ID },
                if local { auth::FINAL_ID } else { 0 },
                row.mode == Mode::Negotiated,
            );
            let (first, body) = contact::first_payload(&row, false);
            let opening = peer
                .wire
                .seal(1, local, 35, PayloadChain::new(first, &body));
            let pending = contact::begin(&row, &opening, row.namespace)
                .unwrap()
                .unwrap();
            let mut transport = Transport::default();
            let final_packet = contact::final_exchange(
                &mut runtime,
                &provider,
                &mut store,
                &mut peer,
                &mut transport,
            );
            let proof = pending.complete(&row, &final_packet).unwrap();
            let candidates = vec![
                row.key,
                victims[0].key,
                victims[1].key,
                victims[2].key,
                victims[3].key,
                victims[0].key,
            ];
            assert!(!proof
                .commit(
                    &provider,
                    &mut store,
                    &joined,
                    &mut runtime,
                    &candidates,
                    cut
                )
                .unwrap());
            assert!(runtime.row.contact_cleanup.is_empty());
            assert!(contact::cleanup(
                &provider,
                &mut store,
                &owners,
                &joined,
                &runtime,
                victims[0].key,
                Cut::Complete
            )
            .is_err());
            for victim in &victims {
                assert!(store.inspect(victim.key).is_some());
            }
            let committed = runtime.pending.as_ref().unwrap().clone();
            store.dispatch(committed.clone()).unwrap();
            store.apply(committed.request()).unwrap();
            store.prune(committed.request());
            drop(runtime);
            store.succeed(8);
            owners.learn_succession(8);
            let joined = store.fenced_read(&committed, row.key).unwrap();
            let mut runtime = Runtime::restore(&provider, &owners, &joined, true).unwrap();
            assert_eq!(runtime.row.contact_cleanup.len(), 2);
            assert!(runtime
                .row
                .contact_cleanup
                .iter()
                .all(|intent| intent.key == victims[0].key || intent.key == victims[3].key));
            if local {
                assert!(!runtime.dispatch_replay(&mut transport).unwrap());
            } else {
                runtime
                    .replay_response(&final_packet, &mut transport)
                    .unwrap();
                assert_eq!(
                    peer.receive(transport.submitted.last().unwrap()),
                    Ok(Event::Completed(auth::FINAL_ID))
                );
                let exact = transport.submitted.last().unwrap().clone();
                runtime
                    .replay_response(&final_packet, &mut transport)
                    .unwrap();
                assert_eq!(&exact, transport.submitted.last().unwrap());
            }
            // A later ordinary exchange replaces the final AUTH cache. Cleanup
            // remains authorized by its separately committed authentication proof.
            runtime
                .reserve(
                    &provider,
                    &mut store,
                    20,
                    1,
                    200,
                    Cut::Complete,
                    Cut::Complete,
                )
                .unwrap();
            if local {
                runtime
                    .publish_request(
                        &provider,
                        &mut store,
                        opc_proto_ikev2::Ikev2ExchangeKind::Informational,
                        super::lifecycle::child_delete(),
                        |_| {},
                        Cut::Complete,
                    )
                    .unwrap();
                runtime.dispatch_replay(&mut transport).unwrap();
                assert_eq!(
                    peer.receive(transport.submitted.last().unwrap()),
                    Ok(Event::NewRequest(auth::FINAL_ID + 1))
                );
                let reply = peer
                    .respond(auth::FINAL_ID + 1, crate::canonical_fixtures::empty())
                    .unwrap();
                runtime
                    .complete(
                        &provider,
                        &mut store,
                        &reply,
                        bytes::Bytes::from_static(b"later-work"),
                        |_| {},
                        Cut::Complete,
                    )
                    .unwrap();
            } else {
                let next = peer.request(37, super::lifecycle::child_delete()).unwrap();
                runtime
                    .publish_response(
                        &provider,
                        &mut store,
                        &next,
                        crate::canonical_fixtures::empty(),
                        bytes::Bytes::from_static(b"later-work"),
                        |_| {},
                        Cut::Complete,
                    )
                    .unwrap();
                runtime.replay_response(&next, &mut transport).unwrap();
                assert_eq!(
                    peer.receive(transport.submitted.last().unwrap()),
                    Ok(Event::Completed(auth::FINAL_ID + 1))
                );
            }
            drop(runtime);
            let joined = store.refresh_fenced(&joined).unwrap();
            let runtime = Runtime::restore(&provider, &owners, &joined, true).unwrap();
            let victim_cut = store.current_after_join(&joined, victims[0].key).unwrap();
            let victim_runtime = Runtime::restore(&provider, &owners, &victim_cut, false).unwrap();
            assert!(matches!(
                contact::cleanup(
                    &provider,
                    &mut store,
                    &owners,
                    &joined,
                    &runtime,
                    victims[0].key,
                    Cut::Complete
                ),
                Err(driver::Error::Owner(
                    super::authority::Error::DuplicateOwner
                ))
            ));
            drop(victim_runtime);
            // Reuse one selected key only after removing its old birth. The persisted
            // cleanup intent has no authority over this new independently keyed epoch.
            let old = &victims[3];
            let erased = Command::new(
                store.next_request(),
                vec![Mutation {
                    key: old.key,
                    expected: Some(old.version),
                    value: None,
                }],
            )
            .unwrap();
            store.commit(&erased).unwrap();
            let mut replacement =
                inputs::fresh(old.key.0 + 100_000, row.profile, row.direction, row.mode);
            replacement.key = old.key;
            replacement.sealed_stamp = store.stamp();
            driver::create(&provider, &mut store, &replacement).unwrap();
            let erase = contact::cleanup(
                &provider,
                &mut store,
                &owners,
                &joined,
                &runtime,
                victims[0].key,
                Cut::Applied,
            )
            .unwrap()
            .unwrap();
            store.prune(erase.request());
            assert!(store
                .fenced_read(&erase, victims[0].key)
                .unwrap()
                .row()
                .is_none());
            let before = store.publications;
            assert!(contact::cleanup(
                &provider,
                &mut store,
                &owners,
                &joined,
                &runtime,
                victims[0].key,
                Cut::Complete
            )
            .unwrap()
            .is_none());
            assert_eq!(store.publications, before);
            assert!(contact::cleanup(
                &provider,
                &mut store,
                &owners,
                &joined,
                &runtime,
                victims[3].key,
                Cut::Complete
            )
            .unwrap()
            .is_none());
            for key in [row.key, victims[1].key, victims[2].key] {
                assert!(contact::cleanup(
                    &provider,
                    &mut store,
                    &owners,
                    &joined,
                    &runtime,
                    key,
                    Cut::Complete
                )
                .is_err());
                assert!(store.inspect(key).is_some());
            }
            assert_eq!(
                store.inspect(victims[3].key).unwrap().version.birth,
                replacement.version.birth
            );
            let stored = store.inspect(row.key).unwrap();
            let plaintext = envelope::unseal(&provider, row.key, stored).unwrap();
            let restored =
                ProfileCodec::decode(&plaintext, row.key, stored.version, stored.sealed_stamp)
                    .unwrap();
            assert_eq!(restored.contact_cleanup.len(), 2);
            assert!(peer.alive());
        });
    }
}

#[test]
fn initial_contact_waits_for_final_auth_and_rejects_later_malformed_or_wrong_identity_input() {
    matrix(2_810_000, |row| {
        let row = auth::before_final(row);
        let wire = Wire::new(
            row.profile,
            &row.keys,
            row.spis,
            crate::canonical_fixtures::opposite(row.direction),
        );
        let response = auth::initiator(&row);
        let (first, body) = contact::first_payload(&row, false);
        let opening = wire.seal(1, response, 35, PayloadChain::new(first, &body));
        let pending = contact::begin(&row, &opening, row.namespace)
            .unwrap()
            .unwrap();
        assert!(pending.complete(&row, &opening).is_err());
        for id in [0, 2, auth::FINAL_ID] {
            let later = wire.seal(id, response, 35, PayloadChain::new(first, &body));
            assert!(contact::begin(&row, &later, row.namespace).is_err());
        }
        for index in [0, 8, opening.len() - 1] {
            let mut corrupt = opening.to_vec();
            corrupt[index] ^= 1;
            assert!(contact::begin(&row, &corrupt, row.namespace).is_err());
        }
        let (first, absent) = contact::first_payload(&row, true);
        let packet = wire.seal(1, response, 35, PayloadChain::new(first, &absent));
        assert!(contact::begin(&row, &packet, row.namespace)
            .unwrap()
            .is_none());
        let (first, mut wrong) = contact::first_payload(&row, false);
        let mut changed = wrong.to_vec();
        changed[8] ^= 1;
        wrong = changed.into();
        let packet = wire.seal(1, response, 35, PayloadChain::new(first, &wrong));
        let pending = contact::begin(&row, &packet, row.namespace)
            .unwrap()
            .unwrap();
        let (first, final_body) = auth::payload(&row, response);
        let final_packet = wire.seal(
            auth::FINAL_ID,
            response,
            35,
            PayloadChain::new(first, &final_body),
        );
        assert!(pending.complete(&row, &final_packet).is_err());
        let mut entries = [
            opc_proto_ikev2::Ikev2IkeAuthPayloadBuild {
                payload_type: if response {
                    PayloadType::IdentificationResponder
                } else {
                    PayloadType::IdentificationInitiator
                },
                body: auth::identity(response),
            },
            opc_proto_ikev2::Ikev2IkeAuthPayloadBuild {
                payload_type: PayloadType::Notify,
                body: vec![],
            },
        ];
        for (body, valid) in [
            (vec![1, 0, 0x40, 0], true),        // Empty SPI: ignore Protocol ID.
            (vec![1, 1, 0x40, 0, 0xaa], false), // Nonempty SPI.
            (vec![0, 0, 0x40, 0, 0xbb], false), // Nonempty notification data.
        ] {
            entries[1].body = body;
            let (first, body) =
                opc_proto_ikev2::build_ike_auth_cleartext_payload_chain(&entries).unwrap();
            let packet = wire.seal(1, response, 35, PayloadChain::new(first, &body));
            if valid {
                let pending = contact::begin(&row, &packet, row.namespace)
                    .unwrap()
                    .unwrap();
                assert!(pending.complete(&row, &final_packet).is_ok());
            } else {
                assert!(contact::begin(&row, &packet, row.namespace).is_err());
            }
        }
        let pending = contact::begin(&row, &opening, row.namespace)
            .unwrap()
            .unwrap();
        let mut forged = final_packet.to_vec();
        *forged.last_mut().unwrap() ^= 1;
        assert!(pending.complete(&row, &forged).is_err());
    });
}
