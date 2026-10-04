//! Deterministic transport fixture for consumer tests of the real Linux backend.
//!
//! This module exists only with the non-default `test-support` feature. It does
//! not expose a raw transport injection interface or qualify kernel behavior.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use super::{
    decode_address, decode_policy_direction, decode_selector, netlink_operation_class,
    parse_exact_if_id_attribute, parse_exact_mark_attribute, parse_policy_state,
    parse_sa_relocation_snapshot, read_u16_ne, read_u32_be, read_u32_ne, read_u8,
    validate_allowed_route_attributes, LinuxXfrmBackend, LinuxXfrmBackendConfig,
    LinuxXfrmTransport, NetlinkOperationClass, SensitiveBuffer, NETLINK_HEADER_LEN, XFRMA_IF_ID,
    XFRMA_MARK, XFRM_MSG_GETPOLICY, XFRM_MSG_GETSA, XFRM_MSG_NEWPOLICY, XFRM_MSG_NEWSA,
    XFRM_USER_POLICY_ID_LEN, XFRM_USER_SA_ID_LEN,
};
use crate::{
    PolicyParameters, SaRelocationIdentity, XfrmBackendKind, XfrmCapability, XfrmError, XfrmId,
    XfrmProbe,
};

const MAX_OBJECTS: usize = 1024;
const MAX_BODY_BYTES: usize = 4096;
const LOOKUP_OPERATION: &str = "mock_linux_xfrm_lookup";

/// Test-owned kernel lifetime, independent of any one backend or namespace actor.
///
/// Backends returned by this fixture use the production namespace actor and
/// durable-store implementations. Only their netlink transport is substituted.
///
/// The initial fixture supports bounded SA/policy installation and readback.
/// It refuses overlapping SA lookup keys and unsupported messages. It models
/// neither kernel concurrency nor exact-removal guarantees. At most 1,024
/// objects with 4 KiB encoded bodies may be retained; these are test-fixture
/// bounds, not production capacity limits.
#[derive(Clone, Default)]
pub struct MockLinuxXfrmKernel {
    shared: Arc<MockKernelShared>,
}

/// One deterministic fault on the next supported mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockXfrmMutationFault {
    /// Refuse before changing any simulated kernel state.
    BeforeEffectUnavailable,
    /// Apply the mutation, then return an indeterminate lost acknowledgment.
    AfterEffectLostAck,
}

impl fmt::Debug for MockLinuxXfrmKernel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MockLinuxXfrmKernel(<redacted>)")
    }
}

impl MockLinuxXfrmKernel {
    /// Create an empty deterministic kernel fixture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a real Linux backend using this fixture's kernel lifetime.
    ///
    /// Bind it through the ordinary namespace constructors before testing actor
    /// or durable-store behavior.
    #[must_use]
    pub fn backend(&self) -> LinuxXfrmBackend {
        self.shared.active_lifetimes.fetch_add(1, Ordering::AcqRel);
        LinuxXfrmBackend::with_transport(MockKernelTransport {
            shared: Arc::clone(&self.shared),
        })
    }

    /// Schedule one fault below the real Linux backend's next supported write.
    ///
    /// # Errors
    ///
    /// Returns a value-free refusal if a fault is already pending or the fixture
    /// cannot safely access its state. Read-only queries do not consume a fault.
    pub fn fail_next_mutation(&self, fault: MockXfrmMutationFault) -> Result<(), XfrmError> {
        let mut state = self
            .shared
            .kernel
            .lock()
            .map_err(|_| XfrmError::Unavailable)?;
        if state.next_fault.is_some() {
            return Err(XfrmError::Unavailable);
        }
        state.next_fault = Some(fault);
        Ok(())
    }

    /// Wait until every backend and namespace actor created by this fixture exits.
    ///
    /// The actor barrier covers its drained commands, retained runtime tasks and
    /// durable-store lease handles, even when transport drops earlier. Callers
    /// must first drop all their backend and recovery-store handles, avoid
    /// concurrently creating backends, and keep a test-level timeout around this
    /// wait. Store handles retained by the caller still own their leases.
    pub async fn wait_for_idle(&self) {
        loop {
            let notified = self.shared.idle.notified();
            tokio::pin!(notified);
            // Register before testing the predicate so final lifetime release
            // cannot be lost between the count observation and the await.
            notified.as_mut().enable();
            if self.shared.active_lifetimes.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Default)]
struct MockKernelShared {
    kernel: Mutex<MockKernelState>,
    active_lifetimes: AtomicUsize,
    idle: Notify,
    #[cfg(test)]
    transport_release_pause: Mutex<Option<TransportReleasePause>>,
}

impl MockKernelShared {
    fn release_lifetime(&self) {
        if self.active_lifetimes.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.notify_waiters();
        }
    }
}

// Held by the namespace thread outside run_actor so its release follows the
// actor's state, runtime and admitted-task teardown, including unwinding.
pub(crate) struct MockNamespaceActorLifetime {
    shared: Arc<MockKernelShared>,
}

impl Drop for MockNamespaceActorLifetime {
    fn drop(&mut self) {
        self.shared.release_lifetime();
    }
}

#[cfg(test)]
struct TransportReleasePause {
    entered: tokio::sync::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[derive(Default)]
struct MockKernelState {
    sas: Vec<SaImage>,
    policies: Vec<PolicyImage>,
    next_fault: Option<MockXfrmMutationFault>,
}

struct SaImage {
    identity: SaRelocationIdentity,
    body: SensitiveBuffer,
}

struct PolicyImage {
    parameters: PolicyParameters,
    body: SensitiveBuffer,
}

struct MockKernelTransport {
    shared: Arc<MockKernelShared>,
}

impl Drop for MockKernelTransport {
    fn drop(&mut self) {
        self.shared.release_lifetime();
        #[cfg(test)]
        {
            let pause = self
                .shared
                .transport_release_pause
                .lock()
                .ok()
                .and_then(|mut pause| pause.take());
            if let Some(pause) = pause {
                let _ = pause.entered.send(());
                let _ = pause.release.recv();
            }
        }
    }
}

impl fmt::Debug for MockKernelTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MockKernelTransport(<redacted>)")
    }
}

fn unsupported() -> XfrmError {
    XfrmError::UnsupportedFeature {
        feature: "mock_linux_xfrm_operation",
    }
}

fn readback(
    body: &SensitiveBuffer,
    operation: &'static str,
    config: LinuxXfrmBackendConfig,
) -> Result<Option<SensitiveBuffer>, XfrmError> {
    let datagram_bytes = body.len().saturating_add(NETLINK_HEADER_LEN);
    if datagram_bytes > config.receive_buffer_len {
        return Err(XfrmError::ResponseTooLarge {
            operation,
            buffer_bytes: config.receive_buffer_len,
            datagram_bytes,
        });
    }
    Ok(Some(body.clone()))
}

impl MockKernelState {
    fn reserve_object(&self, body: &[u8]) -> Result<(), XfrmError> {
        if self.sas.len().saturating_add(self.policies.len()) >= MAX_OBJECTS
            || body.len() > MAX_BODY_BYTES
        {
            return Err(unsupported());
        }
        Ok(())
    }

    fn install_sa(&mut self, body: &[u8]) -> Result<Option<SensitiveBuffer>, XfrmError> {
        self.reserve_object(body)?;
        let snapshot = parse_sa_relocation_snapshot(body)?;
        if let Some(existing) = self
            .sas
            .iter()
            .find(|image| image.identity.id == snapshot.identity.id)
        {
            return if existing.identity.mark == snapshot.identity.mark {
                Err(XfrmError::AlreadyExists)
            } else {
                Err(unsupported())
            };
        }
        self.sas
            .try_reserve(1)
            .map_err(|_| XfrmError::Unavailable)?;
        self.sas.push(SaImage {
            identity: snapshot.identity,
            body: SensitiveBuffer::new(body.to_vec()),
        });
        Ok(None)
    }

    fn query_sa(
        &self,
        body: &[u8],
        operation: &'static str,
        config: LinuxXfrmBackendConfig,
    ) -> Result<Option<SensitiveBuffer>, XfrmError> {
        validate_allowed_route_attributes(
            body,
            XFRM_USER_SA_ID_LEN,
            &[XFRMA_MARK],
            LOOKUP_OPERATION,
        )?;
        let id = XfrmId {
            destination: decode_address(body, 0, read_u16_ne(body, 20)?)?,
            spi: read_u32_be(body, 16)?,
            protocol: read_u8(body, 22)?,
        };
        let mark = parse_exact_mark_attribute(body, XFRM_USER_SA_ID_LEN, LOOKUP_OPERATION)?;
        let image = self
            .sas
            .iter()
            .find(|image| image.identity.id == id)
            .ok_or(XfrmError::NotFound)?;
        if image.identity.mark != mark {
            // This fixture never reports an overlapping kernel-selection case
            // as an absence proof and does not model which candidate wins.
            return Err(unsupported());
        }
        readback(&image.body, operation, config)
    }

    fn install_policy(&mut self, body: &[u8]) -> Result<Option<SensitiveBuffer>, XfrmError> {
        self.reserve_object(body)?;
        let parameters = parse_policy_state(body)?.parameters;
        if self.policies.iter().any(|image| {
            image.parameters.selector == parameters.selector
                && image.parameters.direction == parameters.direction
                && image.parameters.mark == parameters.mark
                && image.parameters.if_id == parameters.if_id
        }) {
            return Err(XfrmError::AlreadyExists);
        }
        self.policies
            .try_reserve(1)
            .map_err(|_| XfrmError::Unavailable)?;
        self.policies.push(PolicyImage {
            parameters,
            body: SensitiveBuffer::new(body.to_vec()),
        });
        Ok(None)
    }

    fn query_policy(
        &self,
        body: &[u8],
        operation: &'static str,
        config: LinuxXfrmBackendConfig,
    ) -> Result<Option<SensitiveBuffer>, XfrmError> {
        validate_allowed_route_attributes(
            body,
            XFRM_USER_POLICY_ID_LEN,
            &[XFRMA_MARK, XFRMA_IF_ID],
            LOOKUP_OPERATION,
        )?;
        let selector = decode_selector(body, 0)?;
        let direction = decode_policy_direction(read_u8(body, 60)?)?;
        let mark = parse_exact_mark_attribute(body, XFRM_USER_POLICY_ID_LEN, LOOKUP_OPERATION)?;
        let if_id = parse_exact_if_id_attribute(body, XFRM_USER_POLICY_ID_LEN, LOOKUP_OPERATION)?;
        let image = self
            .policies
            .iter()
            .find(|image| {
                image.parameters.selector == selector
                    && image.parameters.direction == direction
                    && image.parameters.mark == mark
                    && image.parameters.if_id == if_id
            })
            .ok_or(XfrmError::NotFound)?;
        readback(&image.body, operation, config)
    }
}

impl LinuxXfrmTransport for MockKernelTransport {
    fn test_namespace_actor_lifetime(&self) -> Option<MockNamespaceActorLifetime> {
        self.shared.active_lifetimes.fetch_add(1, Ordering::AcqRel);
        Some(MockNamespaceActorLifetime {
            shared: Arc::clone(&self.shared),
        })
    }

    fn transact(
        &self,
        operation: &'static str,
        operation_class: NetlinkOperationClass,
        request: &[u8],
        expected_sequence: u32,
        config: LinuxXfrmBackendConfig,
    ) -> Result<Option<SensitiveBuffer>, XfrmError> {
        if request.len() < NETLINK_HEADER_LEN
            || usize::try_from(read_u32_ne(request, 0)?).ok() != Some(request.len())
            || read_u32_ne(request, 8)? != expected_sequence
        {
            return Err(unsupported());
        }
        let message = read_u16_ne(request, 4)?;
        if operation_class != netlink_operation_class(message) {
            return Err(unsupported());
        }
        let body = &request[NETLINK_HEADER_LEN..];
        let mut state = self
            .shared
            .kernel
            .lock()
            .map_err(|_| XfrmError::Unavailable)?;
        let fault = if matches!(message, XFRM_MSG_NEWSA | XFRM_MSG_NEWPOLICY) {
            state.next_fault.take()
        } else {
            None
        };
        if fault == Some(MockXfrmMutationFault::BeforeEffectUnavailable) {
            return Err(XfrmError::Unavailable);
        }
        let result = match message {
            XFRM_MSG_NEWSA => state.install_sa(body),
            XFRM_MSG_GETSA => state.query_sa(body, operation, config),
            XFRM_MSG_NEWPOLICY => state.install_policy(body),
            XFRM_MSG_GETPOLICY => state.query_policy(body, operation, config),
            _ => Err(unsupported()),
        };
        if result.is_ok() && fault == Some(MockXfrmMutationFault::AfterEffectLostAck) {
            Err(XfrmError::StateIndeterminate { operation })
        } else {
            result
        }
    }

    fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
        XfrmProbe {
            kind: XfrmBackendKind::LinuxKernel,
            platform_supported: true,
            kernel_reachable: true,
            net_admin_capable: true,
            algorithms: XfrmCapability::Available,
            egress_dscp_marking: XfrmCapability::Missing,
            details: Some("deterministic Linux XFRM kernel fixture"),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::future::Future;
    use std::path::PathBuf;
    use std::task::{Context, Waker};
    use std::time::Duration;

    use super::{MockLinuxXfrmKernel, TransportReleasePause};
    use crate::{
        XfrmObjectInstallDurableError, XfrmObjectRecoveryBindError, XfrmObjectRecoveryProofKey,
        XfrmObjectRosterDurableError, XfrmObjectRosterGroupId, XfrmObjectRosterRecoveryProofKey,
        XfrmSaRelocationDurableError, XfrmSaRelocationRecoveryProofKey,
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let suffix = XfrmObjectRosterGroupId::generate()
                .unwrap()
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let root = std::env::temp_dir().join(format!("opc-xfrm-actor-idle-{suffix}"));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_wait_remains_pending_until_actor_releases_every_store_lease() {
        let root = TestRoot::new();
        let object_path = root.0.join("object");
        let relocation_path = root.0.join("relocation");
        let roster_path = root.0.join("roster");
        let kernel = MockLinuxXfrmKernel::new();
        let (backend, object_store, relocation_store, roster_store) = kernel
            .backend()
            .bind_current_network_namespace_with_object_sa_relocation_and_roster_recovery(
                object_path.clone(),
                XfrmObjectRecoveryProofKey::new([0x31; 32]).unwrap(),
                relocation_path.clone(),
                XfrmSaRelocationRecoveryProofKey::new([0x32; 32]).unwrap(),
                roster_path.clone(),
                XfrmObjectRosterRecoveryProofKey::new([0x33; 32]).unwrap(),
            )
            .unwrap();
        // Hold the exact gap: transport release has been published, while the
        // actor's state still owns all three durable-store leases. Dropping the
        // sender also releases this pause if any assertion unwinds the test.
        let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        *kernel.shared.transport_release_pause.lock().unwrap() = Some(TransportReleasePause {
            entered: entered_sender,
            release: release_receiver,
        });
        drop((object_store, relocation_store, roster_store));
        drop(backend);
        tokio::time::timeout(Duration::from_secs(5), entered_receiver)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            MockLinuxXfrmKernel::new()
                .backend()
                .bind_current_network_namespace_with_object_recovery(
                    object_path.clone(),
                    XfrmObjectRecoveryProofKey::new([0x31; 32]).unwrap(),
                ),
            Err(XfrmObjectRecoveryBindError::Store {
                source: XfrmObjectInstallDurableError::StoreBusy
            })
        ));
        assert!(matches!(
            MockLinuxXfrmKernel::new()
                .backend()
                .bind_current_network_namespace_with_sa_relocation_recovery(
                    relocation_path.clone(),
                    XfrmSaRelocationRecoveryProofKey::new([0x32; 32]).unwrap(),
                ),
            Err(XfrmObjectRecoveryBindError::SaRelocationStore {
                source: XfrmSaRelocationDurableError::StoreBusy
            })
        ));
        assert!(matches!(
            MockLinuxXfrmKernel::new()
                .backend()
                .bind_current_network_namespace_with_object_roster_recovery(
                    roster_path.clone(),
                    XfrmObjectRosterRecoveryProofKey::new([0x33; 32]).unwrap(),
                ),
            Err(XfrmObjectRecoveryBindError::RosterStore {
                source: XfrmObjectRosterDurableError::StoreBusy
            })
        ));
        let mut wait = Box::pin(kernel.wait_for_idle());
        let mut context = Context::from_waker(Waker::noop());
        assert!(
            wait.as_mut().poll(&mut context).is_pending(),
            "transport release must not publish idle while actor leases remain held"
        );
        drop(release_sender);
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .unwrap();

        let successor = kernel
            .backend()
            .bind_current_network_namespace_with_object_sa_relocation_and_roster_recovery(
                object_path,
                XfrmObjectRecoveryProofKey::new([0x31; 32]).unwrap(),
                relocation_path,
                XfrmSaRelocationRecoveryProofKey::new([0x32; 32]).unwrap(),
                roster_path,
                XfrmObjectRosterRecoveryProofKey::new([0x33; 32]).unwrap(),
            )
            .unwrap();
        drop(successor);
        tokio::time::timeout(Duration::from_secs(5), kernel.wait_for_idle())
            .await
            .unwrap();
    }
}
