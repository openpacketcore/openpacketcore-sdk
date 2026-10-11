mod exclusive_reset {
    use super::*;
    use crate::ExclusiveNamespaceResetAcknowledgement;
    use opc_linux_xfrm_sys::{XFRM_MSG_GETPOLICY, XFRM_MSG_GETSA};
    use std::collections::BTreeMap;

    fn acknowledgement() -> ExclusiveNamespaceResetAcknowledgement {
        ExclusiveNamespaceResetAcknowledgement::sole_xfrm_writer_and_retains_no_predecessor_state()
    }

    #[derive(Debug, Default)]
    struct Tables {
        sas: BTreeMap<Vec<u8>, SensitiveBuffer>,
        policies: BTreeMap<Vec<u8>, SensitiveBuffer>,
        operations: Vec<&'static str>,
        fail: Option<&'static str>,
    }

    #[derive(Debug, Clone, Default)]
    struct Transport(Arc<Mutex<Tables>>);

    impl LinuxXfrmTransport for Transport {
        fn transact(
            &self,
            operation: &'static str,
            _class: crate::linux::NetlinkOperationClass,
            request: &[u8],
            _sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            let mut tables = self.0.lock().unwrap();
            tables.operations.push(operation);
            if tables.fail == Some(operation) {
                return Err(XfrmError::Unavailable);
            }
            let body = &request[16..];
            match operation {
                "reset_namespace_main_policies" | "reset_namespace_sub_policies" => {
                    tables.policies.clear();
                    Ok(None)
                }
                "reset_namespace_sas" => {
                    tables.sas.clear();
                    Ok(None)
                }
                "install_sa" => {
                    let key = body[56..77].to_vec();
                    if tables.sas.contains_key(&key) {
                        return Err(XfrmError::AlreadyExists);
                    }
                    tables.sas.insert(key, Zeroizing::new(body.to_vec()));
                    Ok(None)
                }
                "install_policy" => {
                    let mut key = body[..56].to_vec();
                    key.push(body[160]);
                    if tables.policies.contains_key(&key) {
                        return Err(XfrmError::AlreadyExists);
                    }
                    tables.policies.insert(key, Zeroizing::new(body.to_vec()));
                    Ok(None)
                }
                "query_sa" => {
                    let mut key = body[..20].to_vec();
                    key.push(body[22]);
                    tables
                        .sas
                        .get(&key)
                        .cloned()
                        .map(Some)
                        .ok_or(XfrmError::NotFound)
                }
                "query_policy" => {
                    let mut key = body[..56].to_vec();
                    key.push(body[60]);
                    tables
                        .policies
                        .get(&key)
                        .cloned()
                        .map(Some)
                        .ok_or(XfrmError::NotFound)
                }
                _ => Err(XfrmError::Unavailable),
            }
        }

        fn verify_empty(
            &self,
            message_type: u16,
            _sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<(), XfrmError> {
            let mut tables = self.0.lock().unwrap();
            let operation = match message_type {
                XFRM_MSG_GETPOLICY => "reset_readback_policies",
                XFRM_MSG_GETSA => "reset_readback_sas",
                _ => panic!("unexpected dump"),
            };
            tables.operations.push(operation);
            if tables.fail == Some(operation) {
                return Err(XfrmError::Unavailable);
            }
            assert!(tables.sas.is_empty());
            assert!(tables.policies.is_empty());
            Ok(())
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::mock()
        }
    }

    fn bind_all(
        transport: &Transport,
        roots: &[DurableTestRoot; 3],
    ) -> (
        NamespaceBoundLinuxXfrmBackend,
        XfrmObjectInstallRecoveryStore,
        XfrmSaRelocationRecoveryStore,
        XfrmObjectRosterRecoveryStore,
    ) {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let result = LinuxXfrmBackend::with_transport(transport.clone())
                .bind_current_network_namespace_with_object_sa_relocation_and_roster_recovery(
                    roots[0].path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x21; 32]).unwrap(),
                    roots[1].path().to_path_buf(),
                    XfrmSaRelocationRecoveryProofKey::new([0x22; 32]).unwrap(),
                    roots[2].path().to_path_buf(),
                    XfrmObjectRosterRecoveryProofKey::new([0x23; 32]).unwrap(),
                );
            match result {
                Ok(bound) => return bound,
                Err(XfrmObjectRecoveryBindError::Store {
                    source: XfrmObjectInstallDurableError::StoreBusy,
                })
                | Err(XfrmObjectRecoveryBindError::SaRelocationStore {
                    source: XfrmSaRelocationDurableError::StoreBusy,
                })
                | Err(XfrmObjectRecoveryBindError::RosterStore {
                    source: XfrmObjectRosterDurableError::StoreBusy,
                }) if Instant::now() < until => std::thread::yield_now(),
                Err(error) => panic!("bind failed: {error:?}"),
            }
        }
    }

    #[tokio::test]
    async fn reset_reproduces_roster_process_loss_and_releases_all_selectors() {
        let roots = std::array::from_fn(|_| DurableTestRoot::new());
        let transport = Transport::default();
        let (backend, objects, relocations, rosters) = bind_all(&transport, &roots);
        let roster = child_sa_roster();
        let authority = backend
            .prepare_durable_object_roster(
                &rosters,
                roster_group(1),
                roster_generation(1),
                roster.clone(),
            )
            .await
            .unwrap();
        backend.run_durable_object_roster(authority).await.unwrap();
        assert_eq!(transport.0.lock().unwrap().sas.len(), 2);
        assert_eq!(transport.0.lock().unwrap().policies.len(), 3);
        drop((backend, objects, relocations, rosters));

        let (backend, objects, relocations, rosters) = bind_all(&transport, &roots);
        let duplicate = match roster_sa_request(0) {
            XfrmObjectInstallRequest::Sa(sa) => sa,
            _ => unreachable!(),
        };
        assert!(matches!(
            LinuxXfrmBackend::with_transport(transport.clone())
                .install_sa(duplicate.clone())
                .await,
            Err(XfrmError::AlreadyExists)
        ));
        assert!(backend.install_sa(duplicate).await.is_err());
        // Any admitted mutation closes this process's reset window, even if
        // the kernel refuses it. Start another successor before resetting.
        assert!(backend
            .reset_exclusively_owned_namespace(acknowledgement())
            .await
            .is_err());
        drop((backend, objects, relocations, rosters));
        let (backend, objects, relocations, rosters) = bind_all(&transport, &roots);
        let report = backend
            .reset_exclusively_owned_namespace(acknowledgement())
            .await
            .unwrap();
        assert_eq!(report.stores_reset, 3);
        assert!(!objects.has_unresolved_writer_authority().unwrap());
        assert!(!relocations.has_unresolved_writer_authority().unwrap());
        assert!(!rosters.has_unresolved_writer_authority().unwrap());
        backend
            .reset_exclusively_owned_namespace(acknowledgement())
            .await
            .unwrap();
        let authority = backend
            .prepare_durable_object_roster(&rosters, roster_group(1), roster_generation(1), roster)
            .await
            .unwrap();
        backend.run_durable_object_roster(authority).await.unwrap();
        assert_eq!(transport.0.lock().unwrap().sas.len(), 2);
        assert_eq!(transport.0.lock().unwrap().policies.len(), 3);
    }

    #[tokio::test]
    async fn reset_failure_preserves_records_until_readback_and_allows_retry() {
        for failed_step in [
            "reset_namespace_main_policies",
            "reset_namespace_sub_policies",
            "reset_namespace_sas",
            "reset_readback_policies",
            "reset_readback_sas",
        ] {
            let roots = std::array::from_fn(|_| DurableTestRoot::new());
            let transport = Transport::default();
            let (backend, objects, relocations, rosters) = bind_all(&transport, &roots);
            let roster = child_sa_roster();
            let authority = backend
                .prepare_durable_object_roster(
                    &rosters,
                    roster_group(2),
                    roster_generation(1),
                    roster.clone(),
                )
                .await
                .unwrap();
            backend
                .detector_cut_roster_issuing_at_member(authority, 1, true)
                .await
                .unwrap();
            assert!(rosters.has_unresolved_writer_authority().unwrap());
            assert!(backend
                .install_policy(InstallPolicyRequest {
                    parameters: policy_parameters()
                })
                .await
                .is_err());
            drop((backend, objects, relocations, rosters));

            let (backend, objects, relocations, rosters) = bind_all(&transport, &roots);
            transport.0.lock().unwrap().fail = Some(failed_step);
            assert!(backend
                .reset_exclusively_owned_namespace(acknowledgement())
                .await
                .is_err());
            assert!(rosters.has_unresolved_writer_authority().unwrap());
            transport.0.lock().unwrap().fail = None;
            let before = transport.0.lock().unwrap().operations.len();
            assert!(backend
                .install_policy(InstallPolicyRequest {
                    parameters: policy_parameters()
                })
                .await
                .is_err());
            assert!(backend
                .recover_durable_object_roster(
                    &rosters,
                    roster_group(2),
                    roster_generation(1),
                    &roster
                )
                .await
                .is_err());
            assert_eq!(transport.0.lock().unwrap().operations.len(), before);
            backend
                .reset_exclusively_owned_namespace(acknowledgement())
                .await
                .unwrap();
            assert!(!rosters.has_unresolved_writer_authority().unwrap());
            backend
                .install_policy(InstallPolicyRequest {
                    parameters: policy_parameters(),
                })
                .await
                .unwrap();
            drop((backend, objects, relocations, rosters));
        }
    }

    #[tokio::test]
    async fn reset_lost_reply_is_indeterminate_and_unobserved_success_keeps_gate_closed() {
        let (sender, mut receiver) = mpsc::channel(1);
        let backend = backend_from_sender(sender);
        let worker = tokio::spawn(async move {
            drop(receiver.recv().await);
        });
        assert!(matches!(
            backend
                .reset_exclusively_owned_namespace(acknowledgement())
                .await,
            Err(XfrmError::StateIndeterminate { .. })
        ));
        worker.await.unwrap();

        let transport = Transport::default();
        let backend = LinuxXfrmBackend::with_transport(transport.clone())
            .bind_current_network_namespace()
            .unwrap();
        let ticket = backend.begin_child_sa_roster_update().await.unwrap();
        // Snapshot reads mint no authority and must leave startup reset open.
        assert!(matches!(
            backend.query_sa_key_snapshot(key_request()).await,
            Err(XfrmError::UnsupportedFeature {
                feature: "sa_key_snapshot"
            })
        ));
        let (reply, received) = oneshot::channel();
        let (observed, observation) = oneshot::channel();
        backend
            .inner
            .sender
            .send(NamespaceCommand::ResetExclusivelyOwnedNamespace {
                contained: None,
                reply,
                observed: observation,
            })
            .await
            .unwrap();
        received.await.unwrap().unwrap();
        drop(observed);
        assert!(backend
            .install_policy(InstallPolicyRequest {
                parameters: policy_parameters()
            })
            .await
            .is_err());
        backend
            .reset_exclusively_owned_namespace(acknowledgement())
            .await
            .unwrap();
        // A ticket minted before reset is invalid even though beginning a
        // publication is read-only and left reset eligible.
        use crate::child_sa::{
            ChildSaId, ChildSaIncarnation, ChildSaOutboundUse, ChildSaPair, ChildSaSelectionLimits,
            ChildSaSelectionPlan, ChildSaTrafficIdentity,
        };
        let id = ChildSaId::new(1).unwrap();
        let inbound = ChildSaTrafficIdentity::new(sa_parameters().id, None, None).unwrap();
        let mut outbound = sa_parameters().id;
        outbound.spi += 1;
        let outbound = ChildSaTrafficIdentity::new(outbound, None, None).unwrap();
        let plan = ChildSaSelectionPlan::new(
            vec![ChildSaPair::new(
                id,
                ChildSaIncarnation::new(1).unwrap(),
                inbound,
                outbound,
                ChildSaOutboundUse::Selected,
            )],
            Vec::new(),
            id,
            ChildSaSelectionLimits {
                max_pairs: 1,
                max_classes: 0,
            },
        )
        .unwrap();
        let before = transport.0.lock().unwrap().operations.len();
        assert!(matches!(
            backend
                .publish_child_sa_roster(
                    ticket,
                    ChildSaInstalledRosterRequest {
                        plan,
                        pairs: Vec::new()
                    }
                )
                .await,
            Err(XfrmError::StateMismatch {
                operation: "installed_child_sa_roster_generation"
            })
        ));
        assert_eq!(before, transport.0.lock().unwrap().operations.len());
        assert!(
            transport
                .0
                .lock()
                .unwrap()
                .operations
                .iter()
                .filter(|op| **op == "reset_namespace_sas")
                .count()
                == 2
        );
    }

    #[tokio::test]
    async fn reset_crash_after_each_step_reopens_and_converges_with_all_store_leases() {
        for cut in 1..=6 {
            let roots = std::array::from_fn(|_| DurableTestRoot::new());
            let transport = Transport::default();
            let namespace = NetworkNamespaceBinding::capture().unwrap();
            let binding = namespace.durable_bytes().unwrap();
            let mut state = NamespaceActorState::new(NamespaceActorBinding::new(namespace));
            let objects = XfrmObjectInstallRecoveryStore::open_bound(
                roots[0].path(),
                XfrmObjectRecoveryProofKey::new([0x21; 32]).unwrap(),
                binding,
            )
            .unwrap();
            let relocations = XfrmSaRelocationRecoveryStore::open_bound(
                roots[1].path(),
                XfrmSaRelocationRecoveryProofKey::new([0x22; 32]).unwrap(),
                binding,
            )
            .unwrap();
            let rosters = XfrmObjectRosterRecoveryStore::open_bound(
                roots[2].path(),
                XfrmObjectRosterRecoveryProofKey::new([0x23; 32]).unwrap(),
                binding,
            )
            .unwrap();
            let old_object = prepare_object_install(
                &objects,
                XfrmObjectInstallOperationId::generate().unwrap(),
                XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                &roster_sa_request(8),
            )
            .unwrap();
            let old_relocation = prepare_sa_relocation(
                &relocations,
                XfrmSaRelocationOperationId::generate().unwrap(),
                XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                &relocation_request(),
            )
            .unwrap();
            let old_roster = prepare_object_roster_record(
                &rosters,
                roster_group(9),
                roster_generation(1),
                &child_sa_roster(),
            )
            .unwrap();
            state.object_recovery_store = Some(objects);
            state.relocation_recovery_store = Some(relocations);
            state.roster_recovery_store = Some(rosters);
            state.reset_fail_after_step = Some(cut);
            let raw =
                LinuxXfrmBackend::with_transport(transport.clone()).for_namespace_actor(namespace);
            let (reply, received) = oneshot::channel();
            let (observed, observation) = oneshot::channel();
            observed.send(()).unwrap();
            NamespaceCommand::ResetExclusivelyOwnedNamespace {
                contained: None,
                reply,
                observed: observation,
            }
            .execute(&raw, &mut state)
            .await;
            assert!(received.await.unwrap().is_err());
            assert!(state.reset_gate.required);
            if cut <= 3 {
                assert!(state
                    .object_recovery_store
                    .as_ref()
                    .unwrap()
                    .inspect(&old_object)
                    .is_ok());
                assert!(state
                    .relocation_recovery_store
                    .as_ref()
                    .unwrap()
                    .inspect(&old_relocation)
                    .is_ok());
                assert!(state
                    .roster_recovery_store
                    .as_ref()
                    .unwrap()
                    .inspect(&old_roster)
                    .is_ok());
            }
            let before = transport.0.lock().unwrap().operations.len();
            let (reply, received) = oneshot::channel();
            NamespaceCommand::InstallPolicy(
                InstallPolicyRequest {
                    parameters: policy_parameters(),
                },
                reply,
            )
            .execute(&raw, &mut state)
            .await;
            assert!(received.await.unwrap().is_err());
            assert_eq!(before, transport.0.lock().unwrap().operations.len());
            drop(state);
            let (backend, objects, relocations, rosters) = bind_all(&transport, &roots);
            assert_eq!(
                backend
                    .reset_exclusively_owned_namespace(acknowledgement())
                    .await
                    .unwrap()
                    .stores_reset,
                3
            );
            assert!(objects.inspect(&old_object).is_err());
            assert!(relocations.inspect(&old_relocation).is_err());
            assert!(rosters.inspect(&old_roster).is_err());
            backend
                .install_policy(InstallPolicyRequest {
                    parameters: policy_parameters(),
                })
                .await
                .unwrap();
            drop((backend, objects, relocations, rosters));
        }
    }

    #[tokio::test]
    async fn reset_touches_only_bound_store_families() {
        let roots: [DurableTestRoot; 3] = std::array::from_fn(|_| DurableTestRoot::new());
        let namespace = NetworkNamespaceBinding::capture()
            .unwrap()
            .durable_bytes()
            .unwrap();
        let relocation = XfrmSaRelocationRecoveryStore::open_bound(
            roots[1].path(),
            XfrmSaRelocationRecoveryProofKey::new([0x22; 32]).unwrap(),
            namespace,
        )
        .unwrap();
        let roster = XfrmObjectRosterRecoveryStore::open_bound(
            roots[2].path(),
            XfrmObjectRosterRecoveryProofKey::new([0x23; 32]).unwrap(),
            namespace,
        )
        .unwrap();
        let relocation_handle = prepare_sa_relocation(
            &relocation,
            XfrmSaRelocationOperationId::generate().unwrap(),
            XfrmSaRelocationOperationGeneration::new(1).unwrap(),
            &relocation_request(),
        )
        .unwrap();
        let roster_handle = prepare_object_roster_record(
            &roster,
            roster_group(7),
            roster_generation(1),
            &child_sa_roster(),
        )
        .unwrap();
        let transport = Transport::default();
        let (backend, objects) = LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace_with_object_recovery(
                roots[0].path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x21; 32]).unwrap(),
            )
            .unwrap();
        assert_eq!(
            backend
                .reset_exclusively_owned_namespace(acknowledgement())
                .await
                .unwrap()
                .stores_reset,
            1
        );
        assert_eq!(
            relocation.inspect(&relocation_handle).unwrap(),
            XfrmSaRelocationDurablePhase::Prepared
        );
        assert_eq!(
            roster.inspect(&roster_handle).unwrap(),
            XfrmObjectRosterDurablePhase::Prepared
        );
        assert!(!objects.has_unresolved_writer_authority().unwrap());
    }

    #[tokio::test]
    async fn reset_store_failure_stays_closed_and_retries_under_the_same_lease() {
        use std::os::unix::fs::PermissionsExt;
        for failed_family in 0..3 {
            let roots = std::array::from_fn(|_| DurableTestRoot::new());
            let transport = Transport::default();
            let (backend, objects, relocations, rosters) = bind_all(&transport, &roots);
            // Invalidate this leased root's security metadata without deleting
            // the store or releasing its lease. This forces actual store I/O
            // validation failure after empty kernel readback.
            fs::set_permissions(
                roots[failed_family].path(),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            assert!(backend
                .reset_exclusively_owned_namespace(acknowledgement())
                .await
                .is_err());
            assert!(transport
                .0
                .lock()
                .unwrap()
                .operations
                .contains(&"reset_readback_sas"));
            assert!(backend
                .install_policy(InstallPolicyRequest {
                    parameters: policy_parameters()
                })
                .await
                .is_err());
            fs::set_permissions(
                roots[failed_family].path(),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            assert_eq!(
                backend
                    .reset_exclusively_owned_namespace(acknowledgement())
                    .await
                    .unwrap()
                    .stores_reset,
                3
            );
            backend
                .install_policy(InstallPolicyRequest {
                    parameters: policy_parameters(),
                })
                .await
                .unwrap();
            drop((backend, objects, relocations, rosters));
        }
    }

    #[tokio::test]
    async fn reset_is_refused_after_read_only_recovery_and_drains_cancelled_commands() {
        let transport = Transport::default();
        let backend = LinuxXfrmBackend::with_transport(transport.clone())
            .bind_current_network_namespace()
            .unwrap();
        // This readback can mint an installed-SA recovery authority, so it
        // closes the reset window even though it does not mutate the kernel.
        assert!(backend
            .recover_installed_outbound_sa_binding(outbound_install_request())
            .await
            .is_err());
        let before = transport.0.lock().unwrap().operations.len();
        assert!(backend
            .reset_exclusively_owned_namespace(acknowledgement())
            .await
            .is_err());
        assert_eq!(before, transport.0.lock().unwrap().operations.len());

        let backend = LinuxXfrmBackend::with_transport(transport.clone())
            .bind_current_network_namespace()
            .unwrap();
        let (reply, received) = oneshot::channel();
        let (observed, observation) = oneshot::channel();
        drop((received, observed));
        backend
            .inner
            .sender
            .send(NamespaceCommand::ResetExclusivelyOwnedNamespace {
                contained: None,
                reply,
                observed: observation,
            })
            .await
            .unwrap();
        // A later passive probe serializes behind the entire cancelled reset.
        backend.probe().await.unwrap();
        // This fixture has no dump session: reaching that capability error
        // proves the reset-required gate still admits the passive read.
        assert!(matches!(
            backend.query_sa_key_snapshot(key_request()).await,
            Err(XfrmError::UnsupportedFeature {
                feature: "sa_key_snapshot"
            })
        ));
        assert_eq!(
            transport.0.lock().unwrap().operations.last(),
            Some(&"reset_readback_sas")
        );
        assert!(backend
            .install_policy(InstallPolicyRequest {
                parameters: policy_parameters()
            })
            .await
            .is_err());
        backend
            .reset_exclusively_owned_namespace(acknowledgement())
            .await
            .unwrap();
        backend
            .install_policy(InstallPolicyRequest {
                parameters: policy_parameters(),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reset_never_activates_or_changes_the_dscp_companion() {
        for deferred in [true, false] {
            let transport = Transport::default();
            let runtime = DeferredDscpRuntime::with_outcomes([]);
            let config = LinuxXfrmDscpMarkingConfig::new([String::from("lo")], 25).unwrap();
            let backend = if deferred {
                LinuxXfrmBackend::with_transport_and_deferred_dscp_runtime(
                    transport,
                    config,
                    runtime.clone(),
                )
            } else {
                LinuxXfrmBackend::with_transport_and_dscp_runtime(
                    transport,
                    config,
                    runtime.clone(),
                )
            }
            .unwrap()
            .bind_current_network_namespace()
            .unwrap();
            let effects = runtime.records().len();
            let probes = runtime.capability_calls();
            backend
                .reset_exclusively_owned_namespace(acknowledgement())
                .await
                .unwrap();
            assert_eq!(runtime.records().len(), effects);
            assert_eq!(runtime.capability_calls(), probes);
        }
    }
}
