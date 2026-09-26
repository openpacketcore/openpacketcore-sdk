//! Incompatible replies from a real authenticated native configuration peer.
//!
//! A reply cannot undo an already committed operation. Reads must refuse its
//! data; sent writes remain ambiguous and recover only their original handle.

use super::*;

#[derive(Debug)]
struct Phase {
    sender: ConsensusNodeId,
    family: ConsensusRpcFamily,
    original: u8,
    emitted: u16,
    calls: AtomicUsize,
    rewritten: AtomicUsize,
    applied: AtomicUsize,
}

#[derive(Debug, Default)]
struct Control(Mutex<Option<Arc<Phase>>>);

impl Control {
    fn arm(
        &self,
        sender: ConsensusNodeId,
        family: ConsensusRpcFamily,
        original: u8,
        emitted: u16,
    ) -> Arc<Phase> {
        let phase = Arc::new(Phase {
            sender,
            family,
            original,
            emitted,
            calls: AtomicUsize::new(0),
            rewritten: AtomicUsize::new(0),
            applied: AtomicUsize::new(0),
        });
        let old = self
            .0
            .lock()
            .expect("test response control")
            .replace(phase.clone());
        assert!(old.is_none(), "one bounded fault phase at a time");
        phase
    }

    fn clear(&self) {
        self.0.lock().expect("retire test response control").take();
    }
}

#[derive(Debug)]
struct ReplyProfile {
    inner: Arc<dyn ConsensusRpcHandler>,
    control: Arc<Control>,
}

#[async_trait]
impl ConsensusRpcHandler for ReplyProfile {
    async fn handle(
        &self,
        authenticated_sender: ConsensusNodeId,
        request: ConsensusWireRequest,
    ) -> ConsensusWireResponse {
        let phase = self
            .control
            .0
            .lock()
            .expect("borrow bounded response phase")
            .as_ref()
            .filter(|phase| phase.sender == authenticated_sender && phase.family == request.family)
            .cloned();
        let Some(phase) = phase else {
            return self.inner.handle(authenticated_sender, request).await;
        };
        let attempt = phase.calls.fetch_add(1, Ordering::SeqCst);
        if phase.family == ConsensusRpcFamily::ForwardMutation && attempt > 0 {
            // Only the first exact request reaches the native handler. Later
            // SDK retries see protocol failure, keeping the original outcome
            // uncertain without manufacturing another command or result.
            return ConsensusWireResponse {
                result: Err(ConsensusPeerError::Protocol),
            };
        }
        let mut response = self.inner.handle(authenticated_sender, request).await;
        let payload = response
            .result
            .as_mut()
            .expect("actual native response required");
        assert_eq!(
            payload.first(),
            Some(&phase.original),
            "original response profile"
        );
        let expected_variant = if phase.family == ConsensusRpcFamily::ForwardMutation {
            0
        } else {
            1
        };
        assert_eq!(
            payload.get(1),
            Some(&expected_variant),
            "native Applied or Ready control required"
        );
        if phase.family == ConsensusRpcFamily::ForwardMutation {
            phase.applied.fetch_add(1, Ordering::SeqCst);
        }
        if phase.emitted == 255 {
            drop(payload.splice(0..1, [0xff, 0x01]));
        } else {
            payload[0] = u8::try_from(phase.emitted).expect("one-byte test discriminator");
        }
        phase.rewritten.fetch_add(1, Ordering::SeqCst);
        // The actual SessionConsensusServer serializes this changed reply
        // through the original authenticated connection. No fake peer result.
        response
    }
}

fn authority(databases: &[PathBuf; 3]) -> [profile_rejection::AuthorityDigest; 3] {
    databases
        .each_ref()
        .map(|path| profile_rejection::authority_digest(path))
}

async fn exact_readback(
    stores: &[ConsensusConfigStore],
    expected: &CommitRecord,
    aad: &EnvelopeAad,
    plaintext: &[u8],
) {
    for store in stores {
        let read = store
            .load_latest()
            .await
            .expect("original native read barrier")
            .expect("native head");
        assert!(read.record == *expected, "complete original record");
        assert_decrypted(&read.record, aad, plaintext);
        let status = store.status();
        assert_eq!(
            status.applied_index, status.committed_index,
            "apply original positive control before baselines"
        );
    }
}

async fn run(profile: ConfigCapacityProfile) {
    let revision = match profile {
        ConfigCapacityProfile::Legacy => 7,
        ConfigCapacityProfile::BoundedV1 => 8,
        _ => panic!("unsupported fixture profile"),
    };
    let directory = disk_fixture();
    let pki = Pki::new();
    let manifest = manifest();
    let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
    let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
    let controls = [0, 1, 2].map(|_| Arc::new(Control::default()));
    let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
    let stores = open_members(
        &directory, &manifest, &pki, &addresses, &faults, false, profile,
    )
    .await;
    let mut servers = Vec::new();
    let mut released = Vec::new();
    for member in 0..3 {
        let (inner, release) = observed_handler(&stores[member]);
        let handler = Arc::new(ReplyProfile {
            inner,
            control: controls[member].clone(),
        });
        let (server, address) = SessionConsensusServer::new(
            handler,
            pki.server(member),
            manifest
                .bind_local(replica_id(member))
                .expect("original response member"),
        )
        .listen("127.0.0.1:0".parse().expect("loopback listener"))
        .await
        .expect("real authenticated response listener");
        *addresses[member].write().expect("publish original address") = Some(address);
        servers.push(Some(server));
        released.push(release);
    }
    snapshot::ready(&stores).await;
    let leader_id = stores[0].status().leader_id.expect("native leader");
    let leader = stores
        .iter()
        .position(|store| store.status().node_id == leader_id)
        .unwrap();
    let follower = (leader + 1) % 3;
    let sender = stores[follower].status().node_id;
    let (input, aad, plaintext) = commit(&stores[leader], 1, None).await;
    let expected = input.record().clone();
    let operation = stores[leader]
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xC1; 16]),
            input,
            CALLER,
        )
        .expect("original positive response control");
    stores[leader]
        .append_prepared_commit_local(operation)
        .await
        .expect("known native control");
    exact_readback(&stores, &expected, &aad, &plaintext).await;
    let baseline = authority(&databases);
    let opposite = if revision == 7 { 8 } else { 7 };
    for other in [opposite, 0, 255] {
        let phase = controls[leader].arm(sender, ConsensusRpcFamily::ReadBarrier, revision, other);
        let result = stores[follower].load_latest().await;
        controls[leader].clear();
        assert!(
            matches!(result, Err(error) if matches!(error.kind(), PersistErrorKind::Unavailable)),
            "CONFIG_CAPACITY_RESPONSE_READ_RED: incompatible reply cannot authorize readback"
        );
        assert!(
            phase.rewritten.load(Ordering::SeqCst) > 0,
            "actual authenticated wrong-profile reply"
        );
        assert!(
            authority(&databases) == baseline,
            "complete authority unchanged by rejected read response"
        );
        assert!(
            stores
                .iter()
                .all(|store| store.status().leader_id == Some(leader_id)),
            "original leader stays available"
        );
        exact_readback(&stores, &expected, &aad, &plaintext).await;
    }

    let (input, aad, plaintext) = commit(&stores[follower], 2, Some(expected.tx_id)).await;
    let expected = input.record().clone();
    let operation = stores[follower]
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xC2; 16]),
            input,
            CALLER,
        )
        .expect("prepare one exact forwarded operation");
    let handle = ConfigCommitRecoveryHandle::from_bytes(operation.recovery_handle().as_bytes())
        .expect("retain original handle");
    let phase = controls[leader].arm(
        sender,
        ConsensusRpcFamily::ForwardMutation,
        revision,
        opposite,
    );
    let result = stores[follower].append_prepared_commit(operation).await;
    controls[leader].clear();
    assert!(matches!(result, Err(error) if matches!(error.kind(), PersistErrorKind::OutcomeUnknown)),
        "CONFIG_CAPACITY_RESPONSE_WRITE_RED: incompatible acknowledgement preserves sent-operation uncertainty");
    assert_eq!(
        phase.applied.load(Ordering::SeqCst),
        1,
        "one actual native Applied response"
    );
    assert_eq!(
        phase.rewritten.load(Ordering::SeqCst),
        1,
        "one incompatible Applied response"
    );
    exact_readback(&stores, &expected, &aad, &plaintext).await;
    let committed = authority(&databases);
    let forwards = faults[follower].actual_forwards.load(Ordering::SeqCst);
    for store in &stores {
        assert!(matches!(store.lookup_commit_operation(&handle, CALLER).await.expect("exact read-only recovery"), ConfigCommitRecoveryOutcome::Committed),
            "CONFIG_CAPACITY_RESPONSE_RECOVERY_RED: recover only the original acknowledged native operation");
    }
    assert_eq!(
        faults[follower].actual_forwards.load(Ordering::SeqCst),
        forwards,
        "recovery does not resubmit"
    );
    assert!(
        authority(&databases) == committed,
        "exact recovery leaves complete authority unchanged"
    );
    snapshot::stop(stores, servers, released, &addresses).await;
    println!("CONFIG_CAPACITY_RESPONSE_PROFILE revision={revision} read_negatives=3 actual_applied_reply=1 uncertainty_preserved=true exact_recovery=true authenticated=true");
}

native_case!(
    config_capacity_957_legacy_reply_profile_preserves_reads_and_uncertainty,
    {
        run(ConfigCapacityProfile::Legacy).await;
    }
);

native_case!(
    config_capacity_957_bounded_reply_profile_preserves_reads_and_uncertainty,
    {
        run(ConfigCapacityProfile::BoundedV1).await;
    }
);
