mod fenced_non_execution {
    use super::*;
    use crate::XfrmObjectRosterMemberPhase;

    // Baseline composition seam. During implementation this one call is wired
    // to the proposed close-and-observe actor API. It must never synthesize
    // intent, treat NotFound as a proof, or weaken the assertions below.
    async fn close_generation(
        backend: &NamespaceBoundLinuxXfrmBackend,
        store: &XfrmObjectRosterRecoveryStore,
        group: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: &XfrmObjectRosterRequest,
    ) -> Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError> {
        backend
            .recover_durable_object_roster(store, group, generation, roster)
            .await
    }

    #[derive(Debug, Default)]
    struct EffectGate {
        entered: tokio::sync::Notify,
        released: Mutex<bool>,
        wake: Condvar,
    }

    impl EffectGate {
        fn hold(&self) {
            let mut released = self.released.lock().unwrap();
            self.entered.notify_one();
            while !*released {
                released = self.wake.wait(released).unwrap();
            }
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.wake.notify_all();
        }

        async fn wait_entered(&self) {
            tokio::time::timeout(Duration::from_secs(2), self.entered.notified())
                .await
                .expect("actor must reach the explicit test latch");
        }
    }

    struct ReleaseOnDrop(Arc<EffectGate>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    #[derive(Debug, Clone)]
    struct PreEffectTransport {
        gate: Arc<EffectGate>,
        query_ordinal: Arc<AtomicUsize>,
        block_query: usize,
        effects: Arc<AtomicUsize>,
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    impl PreEffectTransport {
        fn new(block_query: usize) -> Self {
            Self {
                gate: Arc::new(EffectGate::default()),
                query_ordinal: Arc::new(AtomicUsize::new(0)),
                block_query,
                effects: Arc::new(AtomicUsize::new(0)),
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl LinuxXfrmTransport for PreEffectTransport {
        fn transact(
            &self,
            operation: &'static str,
            class: crate::linux::NetlinkOperationClass,
            _: &[u8],
            _: u32,
            _: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations.lock().unwrap().push(operation);
            match class {
                crate::linux::NetlinkOperationClass::ReadOnly => {
                    if self.query_ordinal.fetch_add(1, Ordering::SeqCst) == self.block_query {
                        self.gate.hold();
                    }
                    Err(XfrmError::NotFound)
                }
                crate::linux::NetlinkOperationClass::Mutation => {
                    if operation == "install_sa" || operation == "install_policy" {
                        self.effects.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(None)
                }
            }
        }
        fn probe(&self, _: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    fn closed_without_effect(
        result: &Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError>,
    ) -> bool {
        matches!(
            result,
            Ok(XfrmObjectRosterRestartOutcome::NoMutation { .. })
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_non_execution_excludes_provider_dispatch_paused_before_actor_admission() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xB1);
        let group = roster_group(0xB2);
        let generation = roster_generation(37);
        let roster = sa_roster(2);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        // Retain the original affine authority without polling its run future.
        let fence = close_generation(&backend, &store, group, generation, &roster).await;
        let fenced = closed_without_effect(&fence);
        let label = match &fence {
            Ok(outcome) => outcome.as_str(),
            Err(error) => error.as_str(),
        };
        let delayed = backend.run_durable_object_roster(authority).await;
        let effects = transport
            .operations()
            .iter()
            .filter(|operation| **operation == "install_sa")
            .count();
        // Drain/retire the baseline's unsafe late run before the RED assertion.
        let _ = backend
            .recover_durable_object_roster(&store, group, generation, &roster)
            .await;
        assert!(fenced && delayed.is_err() && effects == 0,
            "exact closure must precede delayed provider dispatch: fence={label}, late_effects={effects}, refused={}", delayed.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_non_execution_settles_before_releasing_the_pre_effect_actor_latch() {
        let root = DurableTestRoot::new();
        // Two sweep queries, then member zero's adjacent read. No physical
        // mutation has been submitted when that last pre-effect read is held.
        let transport = PreEffectTransport::new(2);
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xB3);
        let _release = ReleaseOnDrop(Arc::clone(&transport.gate));
        let group = roster_group(0xB4);
        let generation = roster_generation(37);
        let roster = sa_roster(2);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let run = tokio::spawn({
            let backend = backend.clone();
            async move { backend.run_durable_object_roster(authority).await }
        });
        transport.gate.wait_entered().await;
        assert_eq!(transport.effects.load(Ordering::SeqCst), 0);
        let fence = tokio::time::timeout(
            Duration::from_secs(2),
            close_generation(&backend, &store, group, generation, &roster),
        )
        .await;
        let fenced_while_held = fence.as_ref().is_ok_and(closed_without_effect);
        assert!(
            !*transport.gate.released.lock().unwrap(),
            "the fence cannot release the test latch"
        );
        transport.gate.release();
        let delayed = run.await.unwrap();
        // The baseline's queued recover must finish before inspecting counters.
        let _ = backend.query_sa(query_request()).await;
        let effects = transport.effects.load(Ordering::SeqCst);
        assert!(fenced_while_held && delayed.is_err() && effects == 0,
            "closure must finish while pre-effect writer is paused: completed_before_release={fenced_while_held}, late_effects={effects}, refused={}", delayed.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_non_execution_excludes_roster_work_queued_before_the_fence_request() {
        let root = DurableTestRoot::new();
        let transport = PreEffectTransport::new(0);
        let (backend, _, _, store) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport.clone()),
            1,
            None,
            None,
            Some((
                root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0xB5; 32]).unwrap(),
            )),
        )
        .unwrap();
        let store = store.unwrap();
        let _release = ReleaseOnDrop(Arc::clone(&transport.gate));
        let group = roster_group(0xB6);
        let generation = roster_generation(37);
        let roster = sa_roster(2);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let blocking_read = tokio::spawn({
            let backend = backend.clone();
            async move { backend.query_sa(query_request()).await }
        });
        transport.gate.wait_entered().await;
        let queued_run = tokio::spawn({
            let backend = backend.clone();
            async move { backend.run_durable_object_roster(authority).await }
        });
        wait_until(|| backend.inner.sender.capacity() == 0).await;
        let fence = tokio::time::timeout(
            Duration::from_secs(2),
            close_generation(&backend, &store, group, generation, &roster),
        )
        .await;
        let fenced_while_queued = fence.as_ref().is_ok_and(closed_without_effect);
        transport.gate.release();
        let _ = blocking_read.await.unwrap();
        let delayed = queued_run.await.unwrap();
        let effects = transport.effects.load(Ordering::SeqCst);
        let _ = backend
            .recover_durable_object_roster(&store, group, generation, &roster)
            .await;
        assert!(fenced_while_queued && delayed.is_err() && effects == 0,
            "queue admission is not physical acceptance: fenced_while_queued={fenced_while_queued}, late_effects={effects}, refused={}", delayed.is_err());
    }
    /// The object becomes visible before its acknowledgement is released.
    /// Exact readback remains available after the observer disappears.
    #[derive(Debug, Clone, Default)]
    struct AcceptedEffectTransport {
        gate: Arc<EffectGate>,
        accepted: Arc<AtomicUsize>,
        removals: Arc<AtomicUsize>,
        visible: Arc<AtomicBool>,
    }

    impl LinuxXfrmTransport for AcceptedEffectTransport {
        fn transact(
            &self,
            operation: &'static str,
            class: crate::linux::NetlinkOperationClass,
            _: &[u8],
            _: u32,
            _: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            match class {
                crate::linux::NetlinkOperationClass::ReadOnly => {
                    if self.visible.load(Ordering::SeqCst) {
                        Ok(Some(durable_object_readback_body(&roster_sa_request(0))))
                    } else {
                        Err(XfrmError::NotFound)
                    }
                }
                crate::linux::NetlinkOperationClass::Mutation => {
                    match operation {
                        "install_sa" => {
                            self.visible.store(true, Ordering::SeqCst);
                            self.accepted.fetch_add(1, Ordering::SeqCst);
                            self.gate.hold();
                        }
                        "remove_sa" => {
                            self.removals.fetch_add(1, Ordering::SeqCst);
                            self.visible.store(false, Ordering::SeqCst);
                        }
                        _ => panic!("unexpected synthetic transport mutation"),
                    }
                    Ok(None)
                }
            }
        }

        fn probe(&self, _: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_non_execution_joins_accepted_work_without_granting_compensation() {
        let root = DurableTestRoot::new();
        let transport = AcceptedEffectTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xC1);
        let _release = ReleaseOnDrop(Arc::clone(&transport.gate));
        let group = roster_group(0xC2);
        let generation = roster_generation(37);
        let roster = sa_roster(1);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let observer = tokio::spawn({
            let backend = backend.clone();
            async move {
                backend
                    .detector_cut_roster_issuing_at_member(authority, 0, true)
                    .await
            }
        });
        transport.gate.wait_entered().await;
        assert_eq!(transport.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );
        // Lose the outer acknowledgement while the physically accepted work
        // remains owned by the actor. Cancellation cannot prove non-execution.
        observer.abort();
        assert!(observer.await.unwrap_err().is_cancelled());
        let pending = tokio::time::timeout(
            Duration::from_secs(2),
            close_generation(&backend, &store, group, generation, &roster),
        )
        .await;
        assert!(
            !pending.as_ref().is_ok_and(closed_without_effect),
            "an accepted, unquiesced effect cannot produce a negative receipt"
        );
        assert_eq!(transport.removals.load(Ordering::SeqCst), 0);
        transport.gate.release();
        // Drain accepted work and any retained closure after caller timeout.
        let _ = backend.query_sa(query_request()).await;
        let observed = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(
            !closed_without_effect(&observed),
            "a lost acknowledgement must never relabel accepted work as never-started"
        );
        assert_eq!(
            transport.accepted.load(Ordering::SeqCst),
            1,
            "reconciliation must not replay the effect"
        );
        assert_eq!(transport.removals.load(Ordering::SeqCst), 0,
            "closure alone cannot compensate an accepted object; complete abort authority is absent");
        assert!(
            transport.visible.load(Ordering::SeqCst),
            "the accepted object remains available for normal exact adoption"
        );
    }
    #[tokio::test]
    async fn fenced_non_execution_preserves_applied_state_for_exact_adoption() {
        let root = DurableTestRoot::new();
        let transport = RosterConvergenceTransport::new();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xD1);
        let group = roster_group(0xD2);
        let generation = roster_generation(37);
        let roster = sa_roster(2);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        backend
            .detector_cut_roster_applied(authority)
            .await
            .unwrap();
        transport
            .converge((0..2).map(|index| durable_object_readback_body(&roster_sa_request(index))));
        let before = transport.operations().len();
        let closure = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(
            !closed_without_effect(&closure),
            "Applied can never become a never-started receipt"
        );
        let after = transport.operations();
        let mutations = after[before..]
            .iter()
            .filter(|operation| **operation != "query_sa")
            .count();
        assert_eq!(
            mutations, 0,
            "closing execution must preserve Applied; it grants no aborting proof set"
        );
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Applied)
        );
        transport
            .converge((0..2).map(|index| durable_object_readback_body(&roster_sa_request(index))));
        assert_eq!(
            backend
                .adopt_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "adopted"
        );
        let repeated = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(!closed_without_effect(&repeated));
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Committed)
        );
    }

    #[tokio::test]
    async fn fenced_non_execution_preserves_partially_issued_prefix_without_compensation_authority()
    {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xD3);
        let group = roster_group(0xD4);
        let generation = roster_generation(37);
        let roster = sa_roster(3);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        backend
            .detector_cut_roster_issuing_at_member(authority, 1, false)
            .await
            .unwrap();
        let before = transport.operations();
        assert_eq!(
            before
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            1
        );
        let closure = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(
            !closed_without_effect(&closure),
            "a partially issued roster is not never-started"
        );
        let after = transport.operations();
        assert!(after[before.len()..].iter().all(|operation| *operation == "query_sa"),
            "closure must leave the owned prefix for separately authorized recovery; extra operations={:?}", &after[before.len()..]);
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );
    }

    #[tokio::test]
    async fn fenced_non_execution_conflicting_foreign_object_is_never_deleted() {
        let root = DurableTestRoot::new();
        let transport = RosterConvergenceTransport::new();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xD5);
        let group = roster_group(0xD6);
        let generation = roster_generation(37);
        let roster = sa_roster(1);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        // Even an equal-looking object predating our effect is foreign.
        transport.converge([durable_object_readback_body(&roster_sa_request(0))]);
        let run = backend.run_durable_object_roster(authority).await.unwrap();
        assert_eq!(run.as_str(), "no_mutation");
        let closure = close_generation(&backend, &store, group, generation, &roster)
            .await
            .unwrap();
        assert_eq!(closure.as_str(), "foreign_untouched");
        assert!(transport
            .operations()
            .iter()
            .all(|operation| *operation == "query_sa"));
        assert!(closure.members().has_conflict());
    }

    #[derive(Debug, Clone, Default)]
    struct UnavailableAfterCutTransport {
        inner: RecordingSuccessTransport,
        unavailable: Arc<AtomicBool>,
    }

    impl LinuxXfrmTransport for UnavailableAfterCutTransport {
        fn transact(
            &self,
            operation: &'static str,
            class: crate::linux::NetlinkOperationClass,
            request: &[u8],
            sequence: u32,
            config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            if matches!(class, crate::linux::NetlinkOperationClass::ReadOnly)
                && self.unavailable.load(Ordering::SeqCst)
            {
                return Err(XfrmError::Unavailable);
            }
            self.inner
                .transact(operation, class, request, sequence, config)
        }
        fn probe(&self, _: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[tokio::test]
    async fn fenced_non_execution_unavailable_issuing_readback_stays_unresolved() {
        let root = DurableTestRoot::new();
        let transport = UnavailableAfterCutTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xD7);
        let group = roster_group(0xD8);
        let generation = roster_generation(37);
        let roster = sa_roster(1);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        backend
            .detector_cut_roster_issuing_at_member(authority, 0, false)
            .await
            .unwrap();
        transport.unavailable.store(true, Ordering::SeqCst);
        let before = transport.inner.operations();
        let closure = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(!closed_without_effect(&closure));
        assert_eq!(closure.unwrap().as_str(), "indeterminate");
        assert_eq!(
            transport.inner.operations(),
            before,
            "unavailable readback grants no mutation authority"
        );
        assert!(store.has_unresolved_writer_authority().unwrap());
    }
    #[tokio::test]
    async fn fenced_non_execution_survives_terminal_pruning_and_unrelated_preparation() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xE1);
        let group = roster_group(0xE2);
        let generation = roster_generation(37);
        let roster = sa_roster(2);
        drop(
            backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await
                .unwrap(),
        );
        // Simulate a lost closure reply: wait for publication, discard its body.
        let _lost = close_generation(&backend, &store, group, generation, &roster)
            .await
            .unwrap();
        let repeated = close_generation(&backend, &store, group, generation, &roster)
            .await
            .unwrap();
        assert!(repeated
            .members()
            .iter()
            .all(|member| member.member_phase() == XfrmObjectRosterMemberPhase::Pending));
        let unrelated = backend
            .prepare_durable_object_roster(&store, roster_group(0xE3), generation, policy_roster(2))
            .await
            .unwrap();
        // Preparing the independent binding exercises normal terminal pruning.
        let replay = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await;
        let excluded = replay.is_err();
        drop(replay);
        drop(unrelated);
        assert!(
            excluded,
            "a closed binding became executable again after its terminal record was pruned"
        );
        let after_prune = close_generation(&backend, &store, group, generation, &roster)
            .await
            .unwrap();
        assert!(after_prune
            .members()
            .iter()
            .all(|member| member.member_phase() == XfrmObjectRosterMemberPhase::Pending));
        assert!(transport.operations().is_empty());
    }

    #[tokio::test]
    async fn fenced_non_execution_closed_binding_survives_real_store_reopen_and_empty_reset() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xE4);
        let binding = backend.network_namespace_binding().durable_bytes().unwrap();
        let group = roster_group(0xE5);
        let generation = roster_generation(37);
        let roster = sa_roster(2);
        drop(
            backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await
                .unwrap(),
        );
        assert!(closed_without_effect(
            &close_generation(&backend, &store, group, generation, &roster).await
        ));
        // No effect was ever submitted: the namespace-empty precondition is
        // proved by this transport's complete log, not guessed from a missing file.
        assert!(transport.operations().is_empty());
        store.reset_after_namespace_empty().unwrap();
        drop(store);
        drop(backend);
        // Waiting for the lease release also joins the old actor's ownership.
        wait_until(|| {
            XfrmObjectRosterRecoveryStore::open_bound(
                root.path(),
                XfrmObjectRosterRecoveryProofKey::new([0xE4; 32]).unwrap(),
                binding,
            )
            .is_ok()
        })
        .await;
        let (reopened, store) = bind_with_roster_recovery(transport.clone(), &root, 0xE4);
        let replay = reopened
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await;
        let excluded = replay.is_err();
        drop(replay);
        assert!(
            excluded,
            "store reopen after empty reset forgot execution closure for the exact binding"
        );
        let recovered = close_generation(&reopened, &store, group, generation, &roster)
            .await
            .unwrap();
        assert!(recovered
            .members()
            .iter()
            .all(|member| member.member_phase() == XfrmObjectRosterMemberPhase::Pending));
        assert!(transport.operations().is_empty());
    }

    #[tokio::test]
    async fn fenced_non_execution_never_calls_pruned_applied_history_never_started() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xE6);
        let group = roster_group(0xE7);
        let generation = roster_generation(37);
        let roster = sa_roster(2);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        assert_eq!(
            backend
                .run_durable_object_roster(authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
        drop(
            backend
                .prepare_durable_object_roster(
                    &store,
                    roster_group(0xE8),
                    generation,
                    policy_roster(2),
                )
                .await
                .unwrap(),
        );
        let observed = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(
            !closed_without_effect(&observed),
            "pruned Applied history cannot become non-execution evidence"
        );
        assert!(
            observed.is_ok(),
            "immutable applied disposition must survive normal pruning; observed={observed:?}"
        );
        assert_eq!(observed.unwrap().as_str(), "committed");
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            2
        );
        assert!(!transport.operations().contains(&"remove_sa"));
    }
    #[tokio::test]
    async fn fenced_non_execution_rejects_substituted_roster_and_store_before_any_io() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xF1);
        let group = roster_group(0xF2);
        let generation = roster_generation(37);
        let roster = sa_roster(2);
        drop(
            backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await
                .unwrap(),
        );
        assert_eq!(
            close_generation(&backend, &store, group, generation, &policy_roster(2))
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::WrongBinding
        );
        let other_root = DurableTestRoot::new();
        let (other_actor, other_store) =
            bind_with_roster_recovery(transport.clone(), &other_root, 0xF3);
        assert_eq!(
            close_generation(&backend, &other_store, group, generation, &roster)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::WrongBinding
        );
        assert!(transport.operations().is_empty());
        assert!(closed_without_effect(
            &close_generation(&backend, &store, group, generation, &roster).await
        ));
        // A refused substituted request cannot poison an independent binding.
        let independent = other_actor
            .prepare_durable_object_roster(&other_store, group, generation, roster.clone())
            .await
            .unwrap();
        assert_eq!(
            other_actor
                .run_durable_object_roster(independent)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            2
        );
    }
}
