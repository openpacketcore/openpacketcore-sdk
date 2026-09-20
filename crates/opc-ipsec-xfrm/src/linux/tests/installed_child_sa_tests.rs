use super::*;
use crate::child_sa::*;
use crate::installed_child_sa::ChildSaRosterRegistry;
use crate::namespace::{NamespaceActorBinding, NetworkNamespaceBinding};
use crate::{ChildSaInstalledPairRequest, ChildSaInstalledRosterRequest};

fn actor() -> NamespaceActorBinding {
    NamespaceActorBinding::new(NetworkNamespaceBinding::for_test(7, 11))
}

fn child(id: u64) -> ChildSaId {
    ChildSaId::new(id).unwrap()
}

fn class(id: u64) -> ChildSaClass {
    ChildSaClass::new(id).unwrap()
}

fn policy(sa: &SaParameters, direction: XfrmDirection) -> PolicyParameters {
    PolicyParameters {
        selector: sa.selector.clone(),
        direction,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![XfrmTemplate {
            id: sa.id,
            source_address: sa.source_address,
            request_id: sa.request_id,
            mode: sa.mode,
        }],
        mark: sa.mark,
        if_id: sa.if_id,
    }
}

fn pair(id: u64, incarnation: u64, selected: bool) -> ChildSaInstalledPairRequest {
    let mut inbound_sa = outbound_binding_request().sa.parameters;
    inbound_sa.id.spi = 0x1000 + (id as u32) * 0x100 + (incarnation as u32) * 2;
    inbound_sa.mark = None;
    let mut outbound_sa = inbound_sa.clone();
    outbound_sa.id.spi += 1;
    outbound_sa.mark = Some(XfrmLookupMark::full(id as u32));
    let pair = ChildSaPair::new(
        child(id),
        ChildSaIncarnation::new(incarnation).unwrap(),
        ChildSaTrafficIdentity::new(inbound_sa.id, inbound_sa.mark, inbound_sa.if_id).unwrap(),
        ChildSaTrafficIdentity::new(outbound_sa.id, outbound_sa.mark, outbound_sa.if_id).unwrap(),
        if selected {
            ChildSaOutboundUse::Selected
        } else {
            ChildSaOutboundUse::ReceiveOnly
        },
    );
    ChildSaInstalledPairRequest {
        pair,
        inbound_policy: policy(&inbound_sa, XfrmDirection::In),
        outbound_policy: selected.then(|| policy(&outbound_sa, XfrmDirection::Out)),
        inbound_sa,
        outbound_sa,
    }
}

fn request_with_pairs(pairs: Vec<ChildSaInstalledPairRequest>) -> ChildSaInstalledRosterRequest {
    let plan = ChildSaSelectionPlan::new(
        pairs.iter().map(|pair| pair.pair.clone()).collect(),
        [(10, 1), (11, 1), (20, 2), (21, 2), (30, 3), (31, 3)]
            .into_iter()
            .map(|(flow, id)| ChildSaClassBinding::new(class(flow), child(id)))
            .collect(),
        child(3),
        ChildSaSelectionLimits {
            max_pairs: 32,
            max_classes: 256,
        },
    )
    .unwrap();
    ChildSaInstalledRosterRequest { plan, pairs }
}

fn request() -> ChildSaInstalledRosterRequest {
    request_with_pairs(vec![pair(1, 1, true), pair(2, 1, true), pair(3, 1, true)])
}

fn replies(request: &ChildSaInstalledRosterRequest) -> Vec<Result<Option<Vec<u8>>, XfrmError>> {
    let mut replies = Vec::new();
    for pair in &request.pairs {
        replies.push(Ok(Some(
            encode_policy_info(&pair.inbound_policy).unwrap().to_vec(),
        )));
        let mut inbound = encode_sa_binding_readback(&pair.inbound_sa);
        remove_route_attr(&mut inbound, XFRM_USER_SA_INFO_LEN, XFRMA_SA_DIR);
        append_attr(&mut inbound, XFRMA_SA_DIR, &[XFRM_SA_DIR_IN]).unwrap();
        replies.push(Ok(Some(inbound.to_vec())));
        if let Some(policy) = &pair.outbound_policy {
            replies.push(Ok(Some(encode_policy_info(policy).unwrap().to_vec())));
        }
        replies.push(Ok(Some(
            encode_sa_binding_readback(&pair.outbound_sa).to_vec(),
        )));
    }
    replies
}

#[tokio::test]
async fn whole_installed_roster_selects_signalling_two_overlapping_user_children_and_default() {
    let request = request();
    assert!(request
        .pairs
        .iter()
        .all(|pair| pair.outbound_sa.selector == request.pairs[0].outbound_sa.selector));
    let mut responses = replies(&request);
    for _ in 0..7 {
        responses.extend(replies(&request));
    }
    let transport = ScriptedTransport::new(responses);
    let capture = transport.clone();
    let backend = LinuxXfrmBackend::with_transport(transport);
    let actor = actor();
    let mut registry = ChildSaRosterRegistry::default();
    let publication = registry
        .publish(&actor, &backend, registry.begin(&actor).unwrap(), request)
        .await
        .unwrap();
    for (flow, id) in [(10, 1), (11, 1), (20, 2), (21, 2), (30, 3), (31, 3)] {
        let selected = registry
            .select(
                &actor,
                &backend,
                &publication,
                ChildSaOutboundSelection::Class(class(flow)),
            )
            .await
            .unwrap();
        assert_eq!(selected.pair().child(), child(id));
        assert_eq!(
            selected.pair().outbound().id().spi,
            0x1000 + (id as u32) * 0x100 + 3
        );
        assert_eq!(selected.generation(), publication.generation());
    }
    let selected = registry
        .select(
            &actor,
            &backend,
            &publication,
            ChildSaOutboundSelection::Default,
        )
        .await
        .unwrap();
    assert_eq!(selected.pair().child(), child(3));
    let messages: Vec<_> = capture
        .requests()
        .iter()
        .map(|message| netlink_message_type(message))
        .collect();
    assert_eq!(messages.len(), 12 * 8);
    assert!(messages
        .as_chunks::<2>()
        .0
        .iter()
        .all(|pair| *pair == [XFRM_MSG_GETPOLICY, XFRM_MSG_GETSA]));
    assert_eq!(
        format!("{publication:?}"),
        "InstalledChildSaRoster(<redacted>)"
    );
    assert_eq!(
        format!("{selected:?}"),
        "InstalledChildSaSelection(<redacted>)"
    );
}

#[tokio::test]
async fn every_policy_and_sa_readback_failure_prevents_any_prefix_publication() {
    for failed in 0..12 {
        for error in [
            XfrmError::NotFound,
            XfrmError::Unavailable,
            XfrmError::StateIndeterminate {
                operation: "detector_readback",
            },
        ] {
            let request = request();
            let mut responses = replies(&request);
            responses[failed] = Err(error);
            let transport = ScriptedTransport::new(responses);
            let capture = transport.clone();
            let backend = LinuxXfrmBackend::with_transport(transport);
            let actor = actor();
            let mut registry = ChildSaRosterRegistry::default();
            let stale_ticket = registry.begin(&actor).unwrap();
            assert!(registry
                .publish(&actor, &backend, registry.begin(&actor).unwrap(), request)
                .await
                .is_err());
            assert_eq!(capture.requests().len(), failed + 1);
            assert!(registry
                .publish(&actor, &backend, stale_ticket, self::request())
                .await
                .is_err());
            assert_eq!(capture.requests().len(), failed + 1);
        }
    }
}

#[tokio::test]
async fn failed_readback_retires_publication_and_cannot_revive_after_identical_reinstall() {
    for failed in 0..12 {
        let request = request();
        let mut responses = replies(&request);
        let mut reread = replies(&request);
        reread[failed] = Err(XfrmError::NotFound);
        responses.extend(reread.into_iter().take(failed + 1));
        responses.extend(replies(&request));
        responses.extend(replies(&request));
        let transport = ScriptedTransport::new(responses);
        let capture = transport.clone();
        let backend = LinuxXfrmBackend::with_transport(transport);
        let actor = actor();
        let mut registry = ChildSaRosterRegistry::default();
        let old = registry
            .publish(&actor, &backend, registry.begin(&actor).unwrap(), request)
            .await
            .unwrap();
        assert!(registry
            .select(&actor, &backend, &old, ChildSaOutboundSelection::Default)
            .await
            .is_err());
        let replacement = registry
            .publish(
                &actor,
                &backend,
                registry.begin(&actor).unwrap(),
                self::request(),
            )
            .await
            .unwrap();
        assert!(replacement.generation() > old.generation());
        let before = capture.requests().len();
        assert!(registry
            .select(&actor, &backend, &old, ChildSaOutboundSelection::Default)
            .await
            .is_err());
        assert_eq!(capture.requests().len(), before);
        registry
            .select(
                &actor,
                &backend,
                &replacement,
                ChildSaOutboundSelection::Default,
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn stale_writer_wrong_actor_and_intervening_mutation_admit_no_reads() {
    let actor = actor();
    let foreign_actor = self::actor(); // Same namespace, distinct actor seal.
    let mut registry = ChildSaRosterRegistry::default();
    let old_ticket = registry.begin(&actor).unwrap();
    let transport = ScriptedTransport::new(replies(&request()));
    let capture = transport.clone();
    let backend = LinuxXfrmBackend::with_transport(transport);
    let roster = registry
        .publish(&actor, &backend, registry.begin(&actor).unwrap(), request())
        .await
        .unwrap();
    let before = capture.requests().len();
    assert!(registry
        .publish(&actor, &backend, old_ticket, request())
        .await
        .is_err());
    assert!(registry
        .select(
            &foreign_actor,
            &backend,
            &roster,
            ChildSaOutboundSelection::Default
        )
        .await
        .is_err());
    let pending = registry.begin(&actor).unwrap();
    registry.invalidate();
    assert!(registry
        .publish(&actor, &backend, pending, request())
        .await
        .is_err());
    assert!(registry
        .select(&actor, &backend, &roster, ChildSaOutboundSelection::Default)
        .await
        .is_err());
    assert_eq!(capture.requests().len(), before);
}

#[tokio::test]
async fn overlap_keeps_both_sa_pairs_but_requires_one_concrete_outbound_policy() {
    let request = request_with_pairs(vec![
        pair(2, 1, false),
        pair(1, 1, true),
        pair(2, 2, true),
        pair(3, 1, true),
    ]);
    let mut responses = replies(&request);
    assert_eq!(responses.len(), 15);
    responses.extend(replies(&request));
    let transport = ScriptedTransport::new(responses);
    let capture = transport.clone();
    let backend = LinuxXfrmBackend::with_transport(transport);
    let actor = actor();
    let mut registry = ChildSaRosterRegistry::default();
    let publication = registry
        .publish(&actor, &backend, registry.begin(&actor).unwrap(), request)
        .await
        .unwrap();
    let selected = registry
        .select(
            &actor,
            &backend,
            &publication,
            ChildSaOutboundSelection::Class(class(20)),
        )
        .await
        .unwrap();
    assert_eq!(selected.pair().incarnation().get(), 2);
    assert_eq!(selected.pair().outbound().id().spi, 0x1205);
    assert_eq!(capture.requests().len(), 30);
}

#[tokio::test]
async fn malformed_rosters_and_ambiguous_outbound_policy_preferences_fail_before_io() {
    for mutation in 0..12 {
        let mut request = request();
        match mutation {
            0 => {
                request.pairs.pop();
            }
            1 => {
                request.pairs.swap(0, 1);
            }
            2 => {
                request.pairs[0].inbound_sa.id.spi += 1;
            }
            3 => {
                request.pairs[0].outbound_sa.id.spi += 1;
            }
            4 => {
                request.pairs[0].outbound_policy.as_mut().unwrap().templates[0]
                    .id
                    .spi = 0;
            }
            5 => {
                request.pairs[0].inbound_policy.direction = XfrmDirection::Out;
            }
            6 => {
                request.pairs[0].inbound_sa.replay_window = 0;
            }
            7 => {
                request.pairs[0].inbound_sa.auth = None;
                request.pairs[0].inbound_sa.aead = None;
            }
            8 => {
                request.pairs[0].outbound_policy = None;
            }
            9 => {
                request.pairs[0].outbound_policy.as_mut().unwrap().action = XfrmAction::Block;
            }
            10 => {
                request.pairs[0].outbound_policy.as_mut().unwrap().if_id = Some(999);
            }
            11 => {
                request.pairs[0].outbound_sa.mode = XfrmMode::Transport;
            }
            _ => unreachable!(),
        }
        // Even a matching installed wildcard-SPI policy must not confer
        // deterministic outbound selection. Supply successful replies for
        // that mutation so a removed validation guard cannot hide behind I/O.
        let responses = if mutation == 4 {
            replies(&request)
        } else {
            Vec::new()
        };
        let transport = ScriptedTransport::new(responses);
        let capture = transport.clone();
        let backend = LinuxXfrmBackend::with_transport(transport);
        let actor = actor();
        let mut registry = ChildSaRosterRegistry::default();
        assert!(
            registry
                .publish(&actor, &backend, registry.begin(&actor).unwrap(), request)
                .await
                .is_err(),
            "mutation {mutation}"
        );
        assert!(capture.requests().is_empty());
    }
}

#[tokio::test]
async fn every_sa_requires_exact_transient_key_proof_and_cannot_accept_direction_substitution() {
    for resource in [1, 3, 5, 7, 9, 11] {
        for mutation in 0..4 {
            let request = request();
            let mut responses = replies(&request);
            let body = responses[resource].as_mut().unwrap().as_mut().unwrap();
            match mutation {
                0 | 2 | 3 => {
                    let offset = route_attr_payload_offset_from(
                        body,
                        XFRM_USER_SA_INFO_LEN,
                        XFRMA_ALG_AUTH_TRUNC,
                    )
                    .unwrap();
                    let legacy =
                        route_attr_payload_offset_from(body, XFRM_USER_SA_INFO_LEN, XFRMA_ALG_AUTH)
                            .unwrap();
                    if mutation == 2 {
                        body[offset + 72..offset + 104].fill(0);
                        body[legacy + 68..legacy + 100].fill(0);
                    } else {
                        body[offset + 72] ^= 1;
                        if mutation == 0 {
                            // Keep both kernel authentication attributes
                            // mutually consistent with the same wrong key.
                            // Only comparison with transient intent detects it.
                            body[legacy + 68] ^= 1;
                        }
                    }
                }
                1 => {
                    let mut replacement = Zeroizing::new(body.clone());
                    remove_route_attr(&mut replacement, XFRM_USER_SA_INFO_LEN, XFRMA_SA_DIR);
                    append_attr(
                        &mut replacement,
                        XFRMA_SA_DIR,
                        &[if resource % 4 == 1 {
                            XFRM_SA_DIR_OUT
                        } else {
                            XFRM_SA_DIR_IN
                        }],
                    )
                    .unwrap();
                    *body = replacement.to_vec();
                }
                _ => unreachable!(),
            }
            let backend = LinuxXfrmBackend::with_transport(ScriptedTransport::new(responses));
            let actor = actor();
            let mut registry = ChildSaRosterRegistry::default();
            assert!(
                registry
                    .publish(&actor, &backend, registry.begin(&actor).unwrap(), request)
                    .await
                    .is_err(),
                "resource {resource} mutation {mutation}"
            );
        }
    }
}

#[derive(Debug, Default)]
struct ReadBarrier {
    entered: tokio::sync::Notify,
    released: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}

impl ReadBarrier {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

struct ReleaseOnDrop(Arc<ReadBarrier>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Debug)]
struct PublicationBarrierTransport {
    script: ScriptedTransport,
    barrier: Arc<ReadBarrier>,
    calls: std::sync::atomic::AtomicUsize,
    block_at: usize,
}

impl LinuxXfrmTransport for PublicationBarrierTransport {
    fn transact(
        &self,
        operation: &'static str,
        operation_class: NetlinkOperationClass,
        request: &[u8],
        sequence: u32,
        config: LinuxXfrmBackendConfig,
    ) -> Result<Option<SensitiveBuffer>, XfrmError> {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == self.block_at {
            self.barrier.entered.notify_one();
            let (released, timeout) = self
                .barrier
                .wake
                .wait_timeout_while(
                    self.barrier.released.lock().unwrap(),
                    Duration::from_secs(10),
                    |released| !*released,
                )
                .unwrap();
            if timeout.timed_out() || !*released {
                return Err(XfrmError::Unavailable);
            }
        }
        self.script
            .transact(operation, operation_class, request, sequence, config)
    }

    fn probe(&self, config: LinuxXfrmBackendConfig) -> XfrmProbe {
        self.script.probe(config)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_drains_after_cancellation_at_every_read_and_requires_fresh_republication() {
    for cut in 1..=12 {
        let barrier = Arc::new(ReadBarrier::default());
        let _release = ReleaseOnDrop(Arc::clone(&barrier));
        let responses = (0..4).flat_map(|_| replies(&request())).collect();
        let script = ScriptedTransport::new(responses);
        let capture = script.clone();
        let backend = LinuxXfrmBackend::with_transport(PublicationBarrierTransport {
            script,
            barrier: Arc::clone(&barrier),
            calls: std::sync::atomic::AtomicUsize::new(0),
            block_at: 12 + cut,
        })
        .bind_current_network_namespace()
        .unwrap();
        let original = backend
            .publish_child_sa_roster(
                backend.begin_child_sa_roster_update().await.unwrap(),
                request(),
            )
            .await
            .unwrap();
        let ticket = backend.begin_child_sa_roster_update().await.unwrap();
        let observer = tokio::spawn({
            let backend = backend.clone();
            async move { backend.publish_child_sa_roster(ticket, request()).await }
        });
        tokio::time::timeout(Duration::from_secs(10), barrier.entered.notified())
            .await
            .unwrap();
        observer.abort();
        assert!(observer.await.unwrap_err().is_cancelled());
        barrier.release();
        // A later actor command waits for the admitted publication to drain.
        let ticket = backend.begin_child_sa_roster_update().await.unwrap();
        assert_eq!(capture.requests().len(), 24, "cancellation at read {cut}");
        assert!(backend
            .select_installed_child_sa(&original, ChildSaOutboundSelection::Default)
            .await
            .is_err());
        assert_eq!(capture.requests().len(), 24);
        let fresh = backend
            .publish_child_sa_roster(ticket, request())
            .await
            .unwrap();
        assert!(fresh.generation() > original.generation());
        backend
            .select_installed_child_sa(&fresh, ChildSaOutboundSelection::Default)
            .await
            .unwrap();
        assert_eq!(capture.requests().len(), 48);
    }
}

#[tokio::test]
async fn raw_linux_mock_and_unsupported_backends_report_precise_missing_profile() {
    let backends: Vec<Box<dyn crate::XfrmBackend>> = vec![
        Box::new(LinuxXfrmBackend::with_transport(ScriptedTransport::new(
            Vec::new(),
        ))),
        Box::new(crate::MockXfrmBackend::new()),
        Box::new(crate::UnsupportedXfrmBackend),
    ];
    for backend in backends {
        assert!(matches!(
            backend.begin_child_sa_roster_update().await,
            Err(XfrmError::UnsupportedFeature {
                feature: "installed_child_sa_roster"
            })
        ));
    }
}
