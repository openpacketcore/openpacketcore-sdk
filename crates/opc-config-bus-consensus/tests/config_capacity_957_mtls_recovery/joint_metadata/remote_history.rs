//! Native, encrypted at-limit history through the public authenticated watch.
//! The oversized-publication control deliberately supplies an expanding model
//! serializer; it does not claim that an oversized logical input was admitted.

use super::*;
use opc_config_bus::{
    ConfigBus, ConfigRevisionCursor, EncryptingManagedDatastore, MAX_CONFIG_HISTORY_PAGE_ENTRIES,
};
use opc_config_bus_consensus::remote_watch::CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES;
use opc_config_bus_consensus::{
    fixed_config_watch_endpoint, ConfigWatchClientBinding, ConfigWatchError, ConfigWatchServer,
    ConfigWatchServerBinding, ConfigWatchServerHandle, RaftManagedDatastore, RemoteConfigWatch,
};
use opc_config_model::{
    ConfigError, OpcConfig, TrustedPrincipal, ValidationContext, ValidationError, WorkloadIdentity,
    YangPath,
};
use opc_types::SpiffeId;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Clone, Deserialize)]
#[serde(transparent)]
struct WatchConfig<const EXPAND: bool>(String);

impl<const EXPAND: bool> std::fmt::Debug for WatchConfig<EXPAND> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WatchConfig(<synthetic>)")
    }
}

impl<const EXPAND: bool> Serialize for WatchConfig<EXPAND> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if EXPAND {
            // Only the explicit negative reader uses this model. The original
            // stored logical JSON and ciphertext remain at their admitted size.
            serializer.serialize_str(&"z".repeat(CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES + 1))
        } else {
            serializer.serialize_str(&self.0)
        }
    }
}

impl<const EXPAND: bool> OpcConfig for WatchConfig<EXPAND> {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_bytes([0xB3; 32])
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        Ok(if self.0 == previous.0 {
            Vec::new()
        } else {
            vec![self.0.clone()]
        })
    }

    fn changed_paths(
        &self,
        _: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        if deltas.is_empty() {
            Ok(Vec::new())
        } else {
            YangPath::new("/synthetic/value")
                .map(|path| vec![path])
                .map_err(|_| ConfigError::new("path", "invalid synthetic path"))
        }
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        self.0 = delta;
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_semantics(&self, _: &ValidationContext<Self>) -> Result<(), ValidationError> {
        Ok(())
    }
}

fn replay_plaintext(version: u64) -> (Vec<u8>, String) {
    let mut bytes = plaintext(0);
    // Use a distinct original replay value for each operation without changing
    // any field length. Read it back from the exact plaintext used for AEAD.
    let last = bytes.len() - 3;
    bytes[last] = b'a' + u8::try_from(version).expect("finite fixture version");
    let value: serde_json::Value =
        serde_json::from_slice(&bytes[12..]).expect("actual version-two plaintext JSON");
    let replay = value["idempotency_key"]
        .as_str()
        .expect("synthetic original replay key");
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/config-bus/idempotency-lookup/v1\0");
    digest.update(replay.as_bytes());
    let lookup = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    (bytes, lookup)
}

fn bus_principal(lookup: &str) -> (String, String) {
    let encode = |padding: usize| {
        let principal = serde_json::to_string(&TrustedPrincipal::new(
            WorkloadIdentity::Internal("p".repeat(padding)),
            TenantId::from_static("test"),
        ))
        .expect("canonical synthetic authenticated principal");
        let wrapper = serde_json::to_string(&serde_json::json!({
            "principal": principal,
            "replay_lookup_digest": lookup,
            "recovery_required": false,
        }))
        .expect("canonical bus metadata");
        (principal, wrapper)
    };
    let overhead = encode(0).1.len();
    let result = encode(16_384 - overhead);
    assert_eq!(result.1.len(), 16_384);
    result
}

fn bound_aad(record: &CommitRecord, principal: &str, store_kind: &str) -> EnvelopeAad {
    EnvelopeAad::config(
        TenantId::from_static("test"),
        record.version.get(),
        ConfigAad::new(
            record.tx_id,
            record.parent_tx_id,
            record.committed_at,
            principal,
            record.schema_digest,
            store_kind,
        )
        .expect("complete bus envelope binding"),
    )
}

fn store_kind() -> String {
    let (_, lookup) = replay_plaintext(2);
    let (principal, wrapper) = bus_principal(&lookup);
    let record = record(2, Some(TxId::new()), &wrapper);
    let mut kind = String::from("synthetic-\"\\é-");
    let base = opc_key::serialize_bound_aad(&bound_aad(&record, &principal, &kind), key().key_id())
        .expect("canonical initial bus AAD")
        .len();
    kind.extend(std::iter::repeat_n('s', AAD_BYTES - base));
    kind
}

async fn native_input(
    store: &ConsensusConfigStore,
    version: u64,
    parent: Option<TxId>,
    kind: &str,
) -> (AttestedConfigCommit, String) {
    let (plaintext, lookup) = replay_plaintext(version);
    let (principal, wrapper) = bus_principal(&lookup);
    let mut record = record(version, parent, &wrapper);
    let aad = bound_aad(&record, &principal, kind);
    let reservation = store
        .try_reserve_config_preparation()
        .expect("native watch preparation capacity")
        .expect("bounded preparation reservation");
    let envelope = opc_crypto::encrypt_reserved_bounded_config_envelope(
        reservation,
        &JointProvider::default(),
        &aad,
        &plaintext,
    )
    .await
    .expect("native encrypted watch input");
    let parsed = CryptoEnvelopeRef::decode(envelope.encoded()).expect("exact encrypted input");
    assert_eq!(plaintext.len(), BOUNDED_LOGICAL_BYTES + REPLAY_BYTES);
    assert_eq!(parsed.key_id.as_str().len(), 512);
    if version > 1 {
        assert_eq!(parsed.aad.len(), AAD_BYTES);
        assert_eq!(envelope.encoded().len(), ENVELOPE_BYTES);
    }
    record.encrypted_blob = envelope.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(&plaintext).to_vec();
    let audit = (0..AUDIT_RECORDS)
        .map(|index| AuditRecord {
            tx_id: record.tx_id,
            sequence: index as u32,
            yang_path: format!("/fixture:{}", "a".repeat(AUDIT_PATH_BYTES - 9)),
            op_type: AuditOpType::Update,
            previous_value: Some("synthetic-before".into()),
            new_value: Some("synthetic-after".into()),
            redaction_applied: false,
            previous_hash: [0; 32],
            entry_hmac: [0; 32],
        })
        .collect();
    let input = AttestedConfigCommit::try_new(
        record,
        audit,
        envelope.claim().expect("one exact encryption claim"),
    )
    .expect("paired watch record evidence");
    (input, principal)
}

async fn reader<const EXPAND: bool>(
    store: &ConsensusConfigStore,
    kind: &str,
    pki: &Pki,
    scope: ConsensusIdentity,
    follower: usize,
) -> (
    ConfigWatchServerHandle,
    RemoteConfigWatch<WatchConfig<EXPAND>>,
) {
    let adapter = RaftManagedDatastore::<WatchConfig<EXPAND>>::new(Arc::new(store.clone()));
    let decrypt = EncryptingManagedDatastore::with_store_kind(
        Arc::new(adapter),
        Arc::new(JointProvider::default()),
        kind,
    );
    let bus = Arc::new(
        ConfigBus::restore_shadow(decrypt)
            .await
            .expect("restore actual native follower history"),
    );
    let server_id = SpiffeId::new(spiffe(follower)).expect("exact synthetic follower");
    let client_id = SpiffeId::new(spiffe(3)).expect("exact synthetic read-only client");
    let binding =
        ConfigWatchServerBinding::try_new(scope, server_id.clone(), vec![client_id.clone()])
            .expect("exact authenticated watch binding");
    let (server, address) = ConfigWatchServer::new(bus, pki.server(follower), binding)
        .expect("native follower watch server")
        .listen("127.0.0.1:0".parse().expect("loopback endpoint"))
        .await
        .expect("native follower watch listener");
    let remote = RemoteConfigWatch::new(
        ConfigWatchClientBinding::new(
            scope,
            client_id,
            server_id,
            SchemaDigest::from_bytes([0xB3; 32]),
        ),
        fixed_config_watch_endpoint(address),
        pki.client(3),
    );
    (server, remote)
}

fn assert_page(
    page: &opc_config_bus::ConfigHistoryPage<WatchConfig<false>>,
    after: u64,
    count: usize,
    expected: &[CommitRecord],
) {
    assert_eq!(page.requested_from().version(), ConfigVersion::new(after));
    assert_eq!(page.len(), count);
    assert_eq!(
        page.next_cursor().version(),
        ConfigVersion::new(after + count as u64)
    );
    for (index, entry) in page.entries().iter().enumerate() {
        let record = &expected[after as usize + index];
        assert!(entry.tx_id == record.tx_id, "original committed identity");
        assert_eq!(
            entry.version, record.version,
            "no cursor omission or duplication"
        );
        assert_eq!(entry.config.0.len(), BOUNDED_LOGICAL_BYTES - 2);
        assert!(
            entry.config.0.bytes().all(|value| value == b'x'),
            "complete decrypted configuration"
        );
        assert_eq!(
            serde_json::to_vec(&entry.config)
                .expect("logical JSON")
                .len(),
            BOUNDED_LOGICAL_BYTES
        );
    }
    assert!(
        serde_json::to_vec(page)
            .expect("complete page encoding")
            .len()
            < CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES
    );
}

async fn applied(stores: &[ConsensusConfigStore]) {
    for store in stores {
        store
            .probe_durable_readiness()
            .await
            .expect("original operation-bound history barrier");
    }
}

native_case!(
    config_capacity_957_native_remote_history_pages_and_reopen,
    {
        let directory = disk_fixture();
        let pki = Pki::new();
        let manifest = manifest();
        let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
        let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
        let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
        let profile = ConfigCapacityProfile::BoundedV1;
        let stores = open_members(
            &directory, &manifest, &pki, &addresses, &faults, false, profile,
        )
        .await;
        let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
        snapshot::ready(&stores).await;
        let leader_id = stores[0].status().leader_id.expect("native history leader");
        let leader = stores
            .iter()
            .position(|store| store.status().node_id == leader_id)
            .expect("fixture leader membership");
        let follower = (leader + 1) % 3;
        let kind = store_kind();
        let mut expected = Vec::<CommitRecord>::new();
        for version in 1..=6 {
            let source = if version % 2 == 1 { leader } else { follower };
            let (input, principal) = native_input(
                &stores[source],
                version,
                expected.last().map(|record| record.tx_id),
                &kind,
            )
            .await;
            expected.push(input.record().clone());
            let operation = stores[source]
                .prepare_recoverable_commit(
                    ConfigConsensusRequestId::from_bytes([0x60 + version as u8; 16]),
                    input,
                    &principal,
                )
                .expect("exact native history operation");
            if source == leader {
                stores[source].append_prepared_commit_local(operation).await
            } else {
                stores[source].append_prepared_commit(operation).await
            }
            .expect("native history durable acknowledgement");
            applied(&stores).await;
        }
        const { assert!(6 * BOUNDED_LOGICAL_BYTES > CONFIG_WATCH_MAX_RESPONSE_FRAME_BYTES) };
        let effects = databases.each_ref().map(|path| effect_counts(path));
        let forwards = faults
            .each_ref()
            .map(|fault| fault.actual_forwards.load(Ordering::SeqCst));
        let (watch, remote) = reader::<false>(
            &stores[follower],
            &kind,
            &pki,
            manifest.consensus_identity(),
            follower,
        )
        .await;
        let initial = ConfigRevisionCursor::after(ConfigVersion::INITIAL);
        let first = remote
            .load_committed_page(initial, MAX_CONFIG_HISTORY_PAGE_ENTRIES, Duration::ZERO)
            .await
            .expect("adaptive remote first page");
        assert_page(&first, 0, 4, &expected);
        let continuation = first.next_cursor();
        let second = remote
            .load_committed_page(
                continuation,
                MAX_CONFIG_HISTORY_PAGE_ENTRIES,
                Duration::ZERO,
            )
            .await
            .expect("adaptive continuation has no cursor gap");
        assert_page(&second, 4, 2, &expected);
        let singleton = remote
            .load_committed_page(
                ConfigRevisionCursor::after(ConfigVersion::new(5)),
                1,
                Duration::ZERO,
            )
            .await
            .expect("one joint-maximum encrypted record fits after decryption");
        assert_page(&singleton, 5, 1, &expected);
        let recovered = remote
            .recover_from(Some(ConfigVersion::new(6)))
            .await
            .expect("complete at-limit watch recovery");
        let (head, stream) = recovered.into_parts();
        assert_eq!(head.version, ConfigVersion::new(6));
        assert!(
            head.tx_id == Some(expected[5].tx_id),
            "original remote snapshot identity"
        );
        assert_eq!(head.config.0.len(), BOUNDED_LOGICAL_BYTES - 2);
        assert!(
            head.config.0.bytes().all(|value| value == b'x'),
            "complete decrypted recovered snapshot"
        );
        drop(stream);
        watch.shutdown().await;
        let (watch, remote) = reader::<true>(
            &stores[follower],
            &kind,
            &pki,
            manifest.consensus_identity(),
            follower,
        )
        .await;
        assert_eq!(
            remote
                .load_committed_page(initial, 1, Duration::ZERO)
                .await
                .expect_err("unrepresentable singleton is explicit"),
            ConfigWatchError::FrameTooLarge
        );
        assert!(
            matches!(
                remote.recover_from(None).await,
                Err(ConfigWatchError::FrameTooLarge)
            ),
            "oversized publication cannot return a partial snapshot"
        );
        watch.shutdown().await;
        assert_eq!(
            databases.each_ref().map(|path| effect_counts(path)),
            effects
        );
        assert_eq!(
            faults
                .each_ref()
                .map(|fault| fault.actual_forwards.load(Ordering::SeqCst)),
            forwards
        );
        eprintln!("CONFIG_CAPACITY_REMOTE_PRE_REOPEN records=6 pages=4,2 singleton=true recovery=true oversized_publication=rejected effects_unchanged=true");
        snapshot::stop(stores, servers, released, &addresses).await;
        let trace = reopen_trace::begin();
        election::begin(&faults);
        let reopen_started = tokio::time::Instant::now();
        let stores = open_members(
            &directory, &manifest, &pki, &addresses, &faults, true, profile,
        )
        .await;
        assert_eq!(
            databases.each_ref().map(|path| effect_counts(path)),
            effects
        );
        let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
        eprintln!(
            "CONFIG_CAPACITY_REMOTE_REOPEN_READY_BEGIN elapsed_ms={}",
            reopen_started.elapsed().as_millis()
        );
        let observation = history_capacity::ReopenReadinessObservation {
            started: tokio::time::Instant::now(),
            faults: &faults,
            stores: &stores,
        };
        snapshot::ready(&stores).await;
        drop(observation);
        drop(trace);
        let reopened_effects = databases.each_ref().map(|path| effect_counts(path));
        let (watch, remote) = reader::<false>(
            &stores[follower],
            &kind,
            &pki,
            manifest.consensus_identity(),
            follower,
        )
        .await;
        let page = remote
            .load_committed_page(
                continuation,
                MAX_CONFIG_HISTORY_PAGE_ENTRIES,
                Duration::ZERO,
            )
            .await
            .expect("same remote cursor after original-store reopen");
        assert_page(&page, 4, 2, &expected);
        watch.shutdown().await;
        assert_eq!(
            databases.each_ref().map(|path| effect_counts(path)),
            reopened_effects
        );
        assert_eq!(
            faults
                .each_ref()
                .map(|fault| fault.actual_forwards.load(Ordering::SeqCst)),
            forwards
        );
        snapshot::stop(stores, servers, released, &addresses).await;
        println!("CONFIG_CAPACITY_REMOTE_HISTORY logical=1572864 replay=65536 aad=65536 key_id=512 principal=16384 audit_paths=21 pages=4,2 singleton=true oversized_publication=rejected original_cursor=true original_paths=true mtls=true native_wal=true");
    }
);
