//! Namespace-serialized durable staged-object install protocol.

use std::fmt;

use crate::durable_object::{
    DurableObjectRecord, XfrmObjectInstallDurableError, XfrmObjectInstallDurablePhase,
    XfrmObjectInstallOperationGeneration, XfrmObjectInstallOperationId,
    XfrmObjectInstallRecoveryHandle, XfrmObjectInstallRecoveryStore,
};
use crate::{
    ExactRemovePolicyRequest, XfrmBackend, XfrmError, XfrmObjectInstallRequest,
    XfrmObjectRemovalRequest,
};

/// Durable terminal result of one create-exclusive staged-object install.
///
/// Every variant carries an authenticated opaque handle. The handle is only
/// correlation data until the same bound store authenticates its current
/// record; its `Debug` and `Display` forms never expose identity material.
#[non_exhaustive]
pub enum XfrmObjectInstallDurableOutcome {
    /// The backend acknowledged acquisition and durable cleanup authority was
    /// published before this result became visible.
    Acquired(XfrmObjectInstallRecoveryHandle),
    /// `AlreadyExists` definitively proved that the create-exclusive request
    /// made no mutation.
    NoMutation(XfrmObjectInstallRecoveryHandle),
    /// Ownership cannot be proved. Recovery must retain state and perform no
    /// deletion. A live call carries its value-free backend failure; a
    /// restored `Issuing` record has no recoverable source value.
    Indeterminate {
        /// Authenticated correlation handle for the fail-closed record.
        handle: XfrmObjectInstallRecoveryHandle,
        /// Observed redaction-safe backend result, when this process saw it.
        source: Option<XfrmError>,
    },
}

impl XfrmObjectInstallDurableOutcome {
    /// Stable, value-free outcome label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Acquired(_) => "acquired",
            Self::NoMutation(_) => "no_mutation",
            Self::Indeterminate { .. } => "indeterminate",
        }
    }

    /// Authenticated opaque correlation handle.
    pub const fn handle(&self) -> &XfrmObjectInstallRecoveryHandle {
        match self {
            Self::Acquired(handle) | Self::NoMutation(handle) => handle,
            Self::Indeterminate { handle, .. } => handle,
        }
    }

    /// Redaction-safe backend failure observed by the current process.
    pub const fn source(&self) -> Option<&XfrmError> {
        match self {
            Self::Indeterminate { source, .. } => source.as_ref(),
            Self::Acquired(_) | Self::NoMutation(_) => None,
        }
    }
}

impl fmt::Debug for XfrmObjectInstallDurableOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectInstallDurableOutcome")
            .field("outcome", &self.as_str())
            .finish_non_exhaustive()
    }
}

/// Deterministic disposition of a durable record after process loss.
#[non_exhaustive]
pub enum XfrmObjectInstallRestartOutcome {
    /// A prepared or explicit no-mutation record was retired without a
    /// backend removal.
    NoMutation,
    /// Exact owned residue was absent or removed and the record was retired.
    OwnedResidueRetired,
    /// The operation may have mutated state, but no authenticated acquisition
    /// was durably published. No deletion was attempted.
    Indeterminate,
    /// Product ownership was already committed; cleanup is forbidden.
    Committed,
    /// Cleanup had already completed.
    Retired,
    /// Exact removal failed after `RemovalAdmitted` was made durable. The
    /// record remains retryable and blocks a cooperating replacement.
    RemovalPending {
        /// Redaction-safe backend failure.
        source: XfrmError,
    },
}

impl XfrmObjectInstallRestartOutcome {
    /// Stable, value-free recovery label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoMutation => "no_mutation",
            Self::OwnedResidueRetired => "owned_residue_retired",
            Self::Indeterminate => "indeterminate",
            Self::Committed => "committed",
            Self::Retired => "retired",
            Self::RemovalPending { .. } => "removal_pending",
        }
    }

    /// Redaction-safe backend removal failure, when retry remains required.
    pub const fn source(&self) -> Option<&XfrmError> {
        match self {
            Self::RemovalPending { source } => Some(source),
            _ => None,
        }
    }
}

impl fmt::Debug for XfrmObjectInstallRestartOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectInstallRestartOutcome")
            .field("outcome", &self.as_str())
            .finish_non_exhaustive()
    }
}

pub(crate) fn prepare_durable_object_install(
    store: &XfrmObjectInstallRecoveryStore,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallDurableError> {
    let fingerprints = store.fingerprints_for_request(request)?;
    store.prepare(
        operation_id,
        operation_generation,
        request.object(),
        fingerprints,
    )
}

pub(crate) fn durable_object_install_phase(
    store: &XfrmObjectInstallRecoveryStore,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
) -> Result<XfrmObjectInstallDurablePhase, XfrmObjectInstallDurableError> {
    let fingerprints = store.fingerprints_for_request(request)?;
    store
        .restore(
            operation_id,
            operation_generation,
            request.object(),
            fingerprints,
        )
        .map(|record| record.phase)
}

pub(crate) fn validate_durable_object_install_admission(
    store: &XfrmObjectInstallRecoveryStore,
    prepared: &XfrmObjectInstallRecoveryHandle,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
) -> Result<(), XfrmObjectInstallDurableError> {
    let fingerprints = store.fingerprints_for_request(request)?;
    let record = store.restore_handle(prepared, request.object(), fingerprints)?;
    if record.operation_id != operation_id
        || record.operation_generation != operation_generation
        || record.phase != XfrmObjectInstallDurablePhase::Prepared
    {
        return Err(XfrmObjectInstallDurableError::WrongBinding);
    }
    Ok(())
}

pub(crate) async fn issue_durable_object_install<B>(
    store: &XfrmObjectInstallRecoveryStore,
    prepared: &XfrmObjectInstallRecoveryHandle,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
    backend: &B,
) -> Result<XfrmObjectInstallDurableOutcome, XfrmObjectInstallDurableError>
where
    B: XfrmBackend + ?Sized,
{
    validate_durable_object_install_admission(
        store,
        prepared,
        operation_id,
        operation_generation,
        request,
    )?;

    let issuing = store.transition(
        prepared,
        XfrmObjectInstallDurablePhase::Prepared,
        XfrmObjectInstallDurablePhase::Issuing,
    )?;
    let result = install(backend, request).await;
    let (phase, source) = match result {
        Ok(()) => (XfrmObjectInstallDurablePhase::Acquired, None),
        Err(XfrmError::AlreadyExists) => (XfrmObjectInstallDurablePhase::NoMutation, None),
        Err(source) => (XfrmObjectInstallDurablePhase::Indeterminate, Some(source)),
    };
    let terminal = store.transition(
        &store.handle_for_record(&issuing)?,
        XfrmObjectInstallDurablePhase::Issuing,
        phase,
    )?;
    let handle = store.handle_for_record(&terminal)?;
    Ok(match phase {
        XfrmObjectInstallDurablePhase::Acquired => {
            XfrmObjectInstallDurableOutcome::Acquired(handle)
        }
        XfrmObjectInstallDurablePhase::NoMutation => {
            XfrmObjectInstallDurableOutcome::NoMutation(handle)
        }
        XfrmObjectInstallDurablePhase::Indeterminate => {
            XfrmObjectInstallDurableOutcome::Indeterminate { handle, source }
        }
        _ => return Err(XfrmObjectInstallDurableError::InvalidTransition),
    })
}

pub(crate) fn finalize_durable_object_install(
    store: &XfrmObjectInstallRecoveryStore,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
) -> Result<XfrmObjectInstallDurablePhase, XfrmObjectInstallDurableError> {
    let fingerprints = store.fingerprints_for_request(request)?;
    let record = store.restore(
        operation_id,
        operation_generation,
        request.object(),
        fingerprints,
    )?;
    let handle = store.handle_for_record(&record)?;
    match record.phase {
        XfrmObjectInstallDurablePhase::Acquired => store
            .transition(
                &handle,
                XfrmObjectInstallDurablePhase::Acquired,
                XfrmObjectInstallDurablePhase::Committed,
            )
            .map(|record| record.phase),
        XfrmObjectInstallDurablePhase::NoMutation => store
            .transition(
                &handle,
                XfrmObjectInstallDurablePhase::NoMutation,
                XfrmObjectInstallDurablePhase::Retired,
            )
            .map(|record| record.phase),
        XfrmObjectInstallDurablePhase::Committed | XfrmObjectInstallDurablePhase::Retired => {
            Ok(record.phase)
        }
        _ => Err(XfrmObjectInstallDurableError::InvalidTransition),
    }
}

pub(crate) async fn recover_durable_object_install<B>(
    store: &XfrmObjectInstallRecoveryStore,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
    backend: &B,
) -> Result<XfrmObjectInstallRestartOutcome, XfrmObjectInstallDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let removal = request.removal();
    let fingerprints = store.fingerprints_for_request(request)?;
    let record = store.restore(
        operation_id,
        operation_generation,
        request.object(),
        fingerprints,
    )?;

    match record.phase {
        XfrmObjectInstallDurablePhase::Prepared => {
            store.transition(
                &store.handle_for_record(&record)?,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Retired,
            )?;
            Ok(XfrmObjectInstallRestartOutcome::NoMutation)
        }
        XfrmObjectInstallDurablePhase::NoMutation => {
            store.transition(
                &store.handle_for_record(&record)?,
                XfrmObjectInstallDurablePhase::NoMutation,
                XfrmObjectInstallDurablePhase::Retired,
            )?;
            Ok(XfrmObjectInstallRestartOutcome::NoMutation)
        }
        XfrmObjectInstallDurablePhase::Acquired => {
            let admitted = store.transition(
                &store.handle_for_record(&record)?,
                XfrmObjectInstallDurablePhase::Acquired,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
            )?;
            retire_admitted(store, admitted, &removal, request.policy_if_id(), backend).await
        }
        XfrmObjectInstallDurablePhase::RemovalAdmitted => {
            retire_admitted(store, record, &removal, request.policy_if_id(), backend).await
        }
        XfrmObjectInstallDurablePhase::Issuing | XfrmObjectInstallDurablePhase::Indeterminate => {
            Ok(XfrmObjectInstallRestartOutcome::Indeterminate)
        }
        XfrmObjectInstallDurablePhase::Committed => Ok(XfrmObjectInstallRestartOutcome::Committed),
        XfrmObjectInstallDurablePhase::Retired => Ok(XfrmObjectInstallRestartOutcome::Retired),
    }
}

async fn retire_admitted<B>(
    store: &XfrmObjectInstallRecoveryStore,
    admitted: DurableObjectRecord,
    removal: &XfrmObjectRemovalRequest,
    policy_if_id: Option<u32>,
    backend: &B,
) -> Result<XfrmObjectInstallRestartOutcome, XfrmObjectInstallDurableError>
where
    B: XfrmBackend + ?Sized,
{
    match remove(backend, removal, policy_if_id).await {
        Ok(()) | Err(XfrmError::NotFound) => {
            store.transition(
                &store.handle_for_record(&admitted)?,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
                XfrmObjectInstallDurablePhase::Retired,
            )?;
            Ok(XfrmObjectInstallRestartOutcome::OwnedResidueRetired)
        }
        Err(source) => Ok(XfrmObjectInstallRestartOutcome::RemovalPending { source }),
    }
}

async fn install<B>(backend: &B, request: &XfrmObjectInstallRequest) -> Result<(), XfrmError>
where
    B: XfrmBackend + ?Sized,
{
    match request {
        XfrmObjectInstallRequest::Sa(request) => backend.install_sa(request.clone()).await,
        XfrmObjectInstallRequest::Policy(request) => backend.install_policy(request.clone()).await,
    }
}

async fn remove<B>(
    backend: &B,
    request: &XfrmObjectRemovalRequest,
    policy_if_id: Option<u32>,
) -> Result<(), XfrmError>
where
    B: XfrmBackend + ?Sized,
{
    match request {
        XfrmObjectRemovalRequest::Sa(request) => backend.remove_sa(*request).await,
        XfrmObjectRemovalRequest::Policy(request) => match policy_if_id {
            Some(if_id) => {
                backend
                    .remove_policy_exact(
                        ExactRemovePolicyRequest::new(request.clone()).with_if_id(if_id),
                    )
                    .await
            }
            None => backend.remove_policy(request.clone()).await,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, DirBuilder},
        io,
        os::unix::fs::DirBuilderExt,
        path::{Path, PathBuf},
    };

    use crate::{
        AuthAlgorithm, InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial,
        MockOperation, MockXfrmBackend, PolicyParameters, SaParameters, XfrmAction, XfrmDirection,
        XfrmId, XfrmLookupMark, XfrmMode, XfrmSelector, XfrmTemplate,
    };

    use super::*;
    use crate::durable_object::XfrmObjectRecoveryProofKey;

    const NAMESPACE_BINDING: [u8; 40] = [0xa5; 40];
    const PROOF_KEY_BYTE: u8 = 0x91;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            for _ in 0..8 {
                let identity = XfrmObjectInstallOperationId::generate().unwrap();
                let name = identity
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let path =
                    std::env::temp_dir().join(format!("opc-xfrm-durable-install-test-{name}"));
                assert!(path.is_absolute());
                match DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("failed to create secure test root: {error}"),
                }
            }
            panic!("failed to allocate a unique secure test root");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.is_dir() {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    fn proof_key() -> XfrmObjectRecoveryProofKey {
        XfrmObjectRecoveryProofKey::new([PROOF_KEY_BYTE; 32]).unwrap()
    }

    fn open_store(root: &TestRoot) -> XfrmObjectInstallRecoveryStore {
        XfrmObjectInstallRecoveryStore::open_bound(root.path(), proof_key(), NAMESPACE_BINDING)
            .unwrap()
    }

    fn operation(byte: u8) -> XfrmObjectInstallOperationId {
        XfrmObjectInstallOperationId::from_bytes([byte; 16]).unwrap()
    }

    fn generation(value: u64) -> XfrmObjectInstallOperationGeneration {
        XfrmObjectInstallOperationGeneration::new(value).unwrap()
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn selector() -> XfrmSelector {
        XfrmSelector::new(ipv4(10, 67, 0, 1), ipv4(198, 51, 100, 19), 50)
    }

    fn sa_request() -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Sa(InstallSaRequest {
            parameters: SaParameters {
                selector: selector(),
                id: XfrmId {
                    destination: ipv4(198, 51, 100, 19),
                    spi: 0x6160_0001,
                    protocol: 50,
                },
                source_address: ipv4(10, 67, 0, 1),
                request_id: None,
                auth: None,
                crypt: None,
                aead: None,
                mode: XfrmMode::Tunnel,
                lifetime: Default::default(),
                replay_window: 32,
                replay_state: None,
                encap: None,
                mark: None,
                output_mark: None,
                if_id: None,
                egress_dscp: None,
            },
        })
    }

    fn policy_request(if_id: Option<u32>) -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Policy(InstallPolicyRequest {
            parameters: PolicyParameters {
                selector: selector(),
                direction: XfrmDirection::Out,
                action: XfrmAction::Allow,
                priority: 616,
                templates: vec![XfrmTemplate {
                    id: XfrmId {
                        destination: ipv4(198, 51, 100, 19),
                        spi: 0x6160_0001,
                        protocol: 50,
                    },
                    source_address: ipv4(10, 67, 0, 1),
                    request_id: None,
                    mode: XfrmMode::Tunnel,
                }],
                mark: None,
                if_id,
            },
        })
    }

    fn assert_no_removal(backend: &MockXfrmBackend) {
        assert!(backend.operations().iter().all(|operation| !matches!(
            operation,
            MockOperation::RemoveSa { .. } | MockOperation::RemovePolicy { .. }
        )));
    }

    async fn assert_present(backend: &MockXfrmBackend, request: &XfrmObjectInstallRequest) {
        assert!(matches!(
            install(backend, request).await,
            Err(XfrmError::AlreadyExists)
        ));
    }

    async fn run_durable_object_install(
        store: &XfrmObjectInstallRecoveryStore,
        operation_id: XfrmObjectInstallOperationId,
        operation_generation: XfrmObjectInstallOperationGeneration,
        request: &XfrmObjectInstallRequest,
        backend: &MockXfrmBackend,
    ) -> Result<XfrmObjectInstallDurableOutcome, XfrmObjectInstallDurableError> {
        let prepared =
            prepare_durable_object_install(store, operation_id, operation_generation, request)?;
        issue_durable_object_install(
            store,
            &prepared,
            operation_id,
            operation_generation,
            request,
            backend,
        )
        .await
    }

    #[tokio::test]
    async fn acquired_sa_and_policy_are_exactly_removed_after_restart() {
        for (case, request) in [(0x11, sa_request()), (0x12, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(1);
            let store = open_store(&root);

            let outcome = run_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(outcome.as_str(), "acquired");
            assert_eq!(
                store.inspect(outcome.handle()).unwrap(),
                XfrmObjectInstallDurablePhase::Acquired
            );

            drop(store);
            backend.clear_operations();
            let reopened = open_store(&root);
            let recovered = recover_durable_object_install(
                &reopened,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(recovered.as_str(), "owned_residue_retired");
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "retired"
            );
            install(&backend, &request)
                .await
                .expect("recovery must remove exactly the acquired object");
        }
    }

    #[tokio::test]
    async fn preexisting_sa_and_policy_are_never_deleted_after_already_exists() {
        for (case, request) in [(0x21, sa_request()), (0x22, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            install(&backend, &request).await.unwrap();
            backend.clear_operations();
            let operation_id = operation(case);
            let operation_generation = generation(2);
            let store = open_store(&root);

            let outcome = run_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(outcome.as_str(), "no_mutation");
            drop(store);

            backend.clear_operations();
            let reopened = open_store(&root);
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "no_mutation"
            );
            assert_no_removal(&backend);
            assert_present(&backend, &request).await;
        }
    }

    #[tokio::test]
    async fn indeterminate_sa_and_policy_fail_closed_across_restart() {
        for (case, request) in [(0x31, sa_request()), (0x32, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            backend.set_failure(XfrmError::Unavailable);
            let operation_id = operation(case);
            let operation_generation = generation(3);
            let store = open_store(&root);

            let outcome = run_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(outcome.as_str(), "indeterminate");
            assert!(matches!(outcome.source(), Some(XfrmError::Unavailable)));
            drop(store);

            backend.clear_failure();
            backend.clear_operations();
            let reopened = open_store(&root);
            for _ in 0..2 {
                assert_eq!(
                    recover_durable_object_install(
                        &reopened,
                        operation_id,
                        operation_generation,
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "indeterminate"
                );
                assert_no_removal(&backend);
            }
        }
    }

    #[tokio::test]
    async fn crash_after_prepare_never_deletes_a_preexisting_object() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = policy_request(None);
        install(&backend, &request).await.unwrap();
        let operation_id = operation(0x40);
        let operation_generation = generation(4);
        let store = open_store(&root);
        let fingerprints = store.fingerprints_for_request(&request).unwrap();
        store
            .prepare(
                operation_id,
                operation_generation,
                request.object(),
                fingerprints,
            )
            .unwrap();
        drop(store);

        backend.clear_operations();
        let reopened = open_store(&root);
        assert_eq!(
            recover_durable_object_install(
                &reopened,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "no_mutation"
        );
        assert_no_removal(&backend);
        assert_present(&backend, &request).await;
    }

    #[tokio::test]
    async fn crash_in_issuing_after_a_successful_mutation_never_deletes() {
        for (case, request) in [(0x41, sa_request()), (0x42, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(4);
            let store = open_store(&root);
            let fingerprints = store.fingerprints_for_request(&request).unwrap();
            let prepared = store
                .prepare(
                    operation_id,
                    operation_generation,
                    request.object(),
                    fingerprints,
                )
                .unwrap();
            store
                .transition(
                    &prepared,
                    XfrmObjectInstallDurablePhase::Prepared,
                    XfrmObjectInstallDurablePhase::Issuing,
                )
                .unwrap();
            install(&backend, &request).await.unwrap();
            drop(store);

            backend.clear_operations();
            let reopened = open_store(&root);
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "indeterminate"
            );
            assert_no_removal(&backend);
            assert_present(&backend, &request).await;
        }
    }

    #[tokio::test]
    async fn committed_old_receipt_never_deletes_a_replacement() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = sa_request();
        let operation_id = operation(0x51);
        let operation_generation = generation(5);
        let store = open_store(&root);
        let outcome = run_durable_object_install(
            &store,
            operation_id,
            operation_generation,
            &request,
            &backend,
        )
        .await
        .unwrap();
        assert_eq!(outcome.as_str(), "acquired");
        let old_handle = outcome.handle().clone();
        assert_eq!(
            finalize_durable_object_install(&store, operation_id, operation_generation, &request,)
                .unwrap(),
            XfrmObjectInstallDurablePhase::Committed
        );
        assert!(store.inspect(&old_handle).is_err());

        remove(&backend, &request.removal(), request.policy_if_id())
            .await
            .unwrap();
        install(&backend, &request).await.unwrap();
        drop(store);

        backend.clear_operations();
        let reopened = open_store(&root);
        assert_eq!(
            recover_durable_object_install(
                &reopened,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "committed"
        );
        assert_no_removal(&backend);
        assert_present(&backend, &request).await;
    }

    #[tokio::test]
    async fn scoped_policy_recovery_removes_only_the_exact_interface_identity() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let unscoped = policy_request(None);
        let scoped = policy_request(Some(77));
        install(&backend, &unscoped).await.unwrap();
        let operation_id = operation(0x61);
        let operation_generation = generation(6);
        let store = open_store(&root);
        assert_eq!(
            run_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &scoped,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "acquired"
        );
        drop(store);

        backend.clear_operations();
        let reopened = open_store(&root);
        assert_eq!(
            recover_durable_object_install(
                &reopened,
                operation_id,
                operation_generation,
                &scoped,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "owned_residue_retired"
        );
        assert_present(&backend, &unscoped).await;
        install(&backend, &scoped)
            .await
            .expect("the scoped identity must have been removed");
    }

    #[tokio::test]
    async fn narrow_lookup_marks_are_rejected_before_recording_or_backend_mutation() {
        for (case, mut request) in [(0x69, sa_request()), (0x6a, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(6);
            let narrow = XfrmLookupMark::new(0x10, 0xf0).unwrap();
            match &mut request {
                XfrmObjectInstallRequest::Sa(request) => request.parameters.mark = Some(narrow),
                XfrmObjectInstallRequest::Policy(request) => {
                    request.parameters.mark = Some(narrow);
                }
            }
            let store = open_store(&root);

            assert!(matches!(
                run_durable_object_install(
                    &store,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await,
                Err(XfrmObjectInstallDurableError::NonExactRemovalIdentity)
            ));
            assert!(backend.operations().is_empty());

            let full = XfrmLookupMark::full(0x10);
            match &mut request {
                XfrmObjectInstallRequest::Sa(request) => request.parameters.mark = Some(full),
                XfrmObjectInstallRequest::Policy(request) => {
                    request.parameters.mark = Some(full);
                }
            }
            assert_eq!(
                run_durable_object_install(
                    &store,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "acquired"
            );
            assert_eq!(backend.operations().len(), 1);
        }
    }

    #[tokio::test]
    async fn wrong_correlation_and_tampered_handle_cannot_trigger_removal() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = sa_request();
        let operation_id = operation(0x71);
        let operation_generation = generation(7);
        let store = open_store(&root);
        let outcome = run_durable_object_install(
            &store,
            operation_id,
            operation_generation,
            &request,
            &backend,
        )
        .await
        .unwrap();
        let mut tampered_bytes = outcome.handle().to_bytes();
        tampered_bytes[tampered_bytes.len() - 1] ^= 1;
        let tampered = XfrmObjectInstallRecoveryHandle::from_bytes(tampered_bytes);
        let fingerprints = store.fingerprints_for_request(&request).unwrap();
        assert!(matches!(
            store.restore_handle(&tampered, request.object(), fingerprints),
            Err(XfrmObjectInstallDurableError::AuthenticationFailed)
        ));

        backend.clear_operations();
        assert!(matches!(
            recover_durable_object_install(
                &store,
                operation_id,
                generation(8),
                &request,
                &backend,
            )
            .await,
            Err(XfrmObjectInstallDurableError::NotFound)
        ));
        assert!(matches!(
            recover_durable_object_install(
                &store,
                operation(0x72),
                operation_generation,
                &request,
                &backend,
            )
            .await,
            Err(XfrmObjectInstallDurableError::NotFound)
        ));
        let mut wrong_request = request.clone();
        let XfrmObjectInstallRequest::Sa(wrong_sa) = &mut wrong_request else {
            unreachable!();
        };
        wrong_sa.parameters.id.spi ^= 1;
        assert!(matches!(
            recover_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &wrong_request,
                &backend,
            )
            .await,
            Err(XfrmObjectInstallDurableError::WrongBinding)
        ));
        assert_no_removal(&backend);
        assert_present(&backend, &request).await;

        backend.clear_operations();
        assert_eq!(
            recover_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "owned_residue_retired"
        );
    }

    #[tokio::test]
    async fn full_install_payload_is_bound_independently_from_deletion_identity() {
        for (case, request, wrong_request) in {
            let sa = sa_request();
            let mut wrong_sa = sa.clone();
            let XfrmObjectInstallRequest::Sa(changed) = &mut wrong_sa else {
                unreachable!();
            };
            changed.parameters.auth = Some((
                AuthAlgorithm::hmac_sha256(128),
                KeyMaterial::new(vec![0x5a; 32]),
            ));

            let policy = policy_request(Some(616));
            let mut wrong_policy = policy.clone();
            let XfrmObjectInstallRequest::Policy(changed) = &mut wrong_policy else {
                unreachable!();
            };
            changed.parameters.priority += 1;
            changed.parameters.templates[0].mode = XfrmMode::Transport;
            [(0x73, sa, wrong_sa), (0x74, policy, wrong_policy)]
        } {
            assert_eq!(request.removal(), wrong_request.removal());
            assert_eq!(request.policy_if_id(), wrong_request.policy_if_id());

            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let store = open_store(&root);
            run_durable_object_install(&store, operation(case), generation(7), &request, &backend)
                .await
                .unwrap();

            backend.clear_operations();
            assert!(matches!(
                recover_durable_object_install(
                    &store,
                    operation(case),
                    generation(7),
                    &wrong_request,
                    &backend,
                )
                .await,
                Err(XfrmObjectInstallDurableError::WrongBinding)
            ));
            assert!(backend.operations().is_empty());
            assert_no_removal(&backend);
            assert_present(&backend, &request).await;
        }
    }

    #[tokio::test]
    async fn admitted_removal_failure_is_durable_and_retryable_after_restart() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = sa_request();
        let operation_id = operation(0x81);
        let operation_generation = generation(8);
        let store = open_store(&root);
        assert_eq!(
            run_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "acquired"
        );
        backend.set_failure(XfrmError::Unavailable);
        let first_recovery = recover_durable_object_install(
            &store,
            operation_id,
            operation_generation,
            &request,
            &backend,
        )
        .await
        .unwrap();
        assert_eq!(first_recovery.as_str(), "removal_pending");
        assert!(matches!(
            first_recovery.source(),
            Some(XfrmError::Unavailable)
        ));
        let fingerprints = store.fingerprints_for_request(&request).unwrap();
        assert_eq!(
            store
                .restore(
                    operation_id,
                    operation_generation,
                    request.object(),
                    fingerprints,
                )
                .unwrap()
                .phase,
            XfrmObjectInstallDurablePhase::RemovalAdmitted
        );
        drop(store);

        backend.clear_failure();
        backend.clear_operations();
        let reopened = open_store(&root);
        assert_eq!(
            recover_durable_object_install(
                &reopened,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "owned_residue_retired"
        );
        install(&backend, &request)
            .await
            .expect("retry must remove the admitted residue");
    }
}
