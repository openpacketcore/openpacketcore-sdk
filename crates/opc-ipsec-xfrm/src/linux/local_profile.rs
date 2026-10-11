//! The private, noncandidate SA used to qualify full key readback.

use super::*;
use crate::local_scope::profile::{self, ProbeKernel, ProbeProgress, ProbeRead};
use opc_local_kernel_lifecycle::LocalContainedOperation;
use rand::{rngs::SysRng, TryRng};

pub(crate) struct LocalAdmissionProbe {
    parameters: SaParameters,
    expectation: OutboundSaPolicyExpectation,
    progress: ProbeProgress,
}
impl LocalAdmissionProbe {
    pub(crate) fn has_uncertain_effects(&self) -> bool {
        self.progress.has_uncertain_effects()
    }
    pub(crate) fn new() -> Result<Self, XfrmError> {
        let mut key = Zeroizing::new(vec![0_u8; 20]);
        SysRng
            .try_fill_bytes(&mut key)
            .map_err(|_| XfrmError::Unavailable)?;
        // Avoid ambiguous all-zero readback even on an astronomically unlikely
        // RNG result. This probe key is never published, negotiated or reused.
        if key.iter().all(|byte| *byte == 0) {
            return Err(XfrmError::Unavailable);
        }
        let source = IpAddress::Ipv4([127, 0, 0, 1]);
        let destination = IpAddress::Ipv4([127, 0, 0, 2]);
        let parameters = SaParameters {
            selector: XfrmSelector::new(source, destination, 0),
            id: XfrmId {
                destination,
                spi: 0xffff_fffd,
                protocol: IPPROTO_ESP,
            },
            source_address: source,
            request_id: XfrmRequestId::new(0xffff_fffd),
            auth: None,
            crypt: None,
            aead: Some((
                crate::AeadAlgorithm::rfc4106_gcm_aes(128),
                crate::KeyMaterial::new(key.to_vec()),
            )),
            mode: XfrmMode::Tunnel,
            lifetime: LifetimeConfig::default(),
            replay_window: 32,
            replay_state: None,
            encap: None,
            mark: Some(XfrmLookupMark::full(0xffff_fffd)),
            output_mark: None,
            if_id: None,
            egress_dscp: None,
        };
        let policy = PolicyParameters {
            selector: parameters.selector.clone(),
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: 1,
            mark: parameters.mark,
            if_id: None,
            templates: vec![XfrmTemplate {
                id: XfrmId {
                    spi: 0,
                    ..parameters.id
                },
                source_address: source,
                request_id: parameters.request_id,
                mode: parameters.mode,
            }],
        };
        let expectation = crate::outbound_binding::validate_sa_policy_request(
            &parameters,
            &policy,
            XfrmDirection::Out,
        )
        .map_err(|_| XfrmError::Unavailable)?;
        Ok(Self {
            parameters,
            expectation,
            progress: ProbeProgress::default(),
        })
    }

    pub(crate) async fn run(
        &mut self,
        backend: &LinuxXfrmBackend,
        guard: &LocalContainedOperation,
        attempt: opc_local_kernel_lifecycle::CleanupAttempt,
    ) -> Result<(), XfrmError> {
        profile::run(
            &mut NativeProbe {
                backend,
                guard,
                parameters: &self.parameters,
                expectation: &self.expectation,
                attempt,
            },
            &mut self.progress,
        )
        .await
    }
}
struct NativeProbe<'a> {
    backend: &'a LinuxXfrmBackend,
    guard: &'a LocalContainedOperation,
    parameters: &'a SaParameters,
    expectation: &'a OutboundSaPolicyExpectation,
    attempt: opc_local_kernel_lifecycle::CleanupAttempt,
}
impl NativeProbe<'_> {
    fn identity(&self) -> SaRelocationIdentity {
        SaRelocationIdentity {
            selector: SaRelocationSelector::from_selector(&self.parameters.selector),
            id: self.parameters.id,
            source_address: self.parameters.source_address,
            request_id: self.parameters.request_id,
            mode: self.parameters.mode,
            encap: self.parameters.encap,
            mark: self.parameters.mark,
            if_id: self.parameters.if_id,
            output_mark: self.parameters.output_mark,
        }
    }
}
#[async_trait]
impl ProbeKernel for NativeProbe<'_> {
    fn contained(&self) -> Result<(), XfrmError> {
        if !self.attempt.has_budget() {
            return Err(XfrmError::Unavailable);
        }
        self.guard
            .recheck()
            .map_err(|_| XfrmError::StateIndeterminate {
                operation: "local_scope_profile_containment",
            })?;
        self.backend.ensure_namespace_binding()
    }
    fn empty(&self) -> Result<(), XfrmError> {
        for kind in [XFRM_MSG_GETPOLICY, XFRM_MSG_GETSA] {
            self.contained()?;
            self.backend.inner.transport.verify_empty_scoped(
                kind,
                self.backend.next_sequence(),
                self.backend.inner.config,
            )?;
        }
        Ok(())
    }
    async fn create(&mut self) -> Result<(), XfrmError> {
        self.backend
            .install_sa(InstallSaRequest {
                parameters: self.parameters.clone(),
            })
            .await
    }
    async fn read(&mut self) -> Result<ProbeRead, XfrmError> {
        self.contained()?;
        let snapshot = self
            .backend
            .query_sa_key_snapshot(SaLookupKey::from(self.parameters.id))
            .await?;
        if snapshot.is_empty() {
            return Ok(ProbeRead::Absent);
        }
        // The admission probe began in an empty namespace under the sole actor.
        // A new occupant or duplicate invalidates that proof even if GETSA would
        // happen to select the original. Never remove it from a snapshot alone.
        if snapshot.states() != [self.identity()] {
            return Err(XfrmError::StateMismatch {
                operation: "local_scope_profile_probe_identity",
            });
        }
        self.contained()?;
        let body = self
            .backend
            .query_sa_for_outbound_binding(self.parameters)
            .await?;
        let observed = parse_outbound_sa_binding_shape(&body, self.expectation)?;
        if observed.identity != self.identity()
            || observed.state.lifetime_config != self.parameters.lifetime
            || observed.state.replay_window != self.parameters.replay_window
        {
            return Err(XfrmError::StateMismatch {
                operation: "local_scope_profile_probe_identity",
            });
        }
        match validate_outbound_sa_crypto(&body, self.parameters) {
            Ok(()) => Ok(ProbeRead::ExactKeys),
            // Metadata is exact and this is still our private probe, not a
            // session receipt. Remove it before returning unsupported; never
            // carry this exception into general SA undo.
            Err(_) => Ok(ProbeRead::KeysUnavailable),
        }
    }
    async fn remove(&mut self) -> Result<(), XfrmError> {
        self.contained()?;
        if self.read().await? == ProbeRead::Absent {
            return Ok(());
        }
        self.backend
            .remove_sa(RemoveSaRequest {
                destination: self.parameters.id.destination,
                protocol: self.parameters.id.protocol,
                spi: self.parameters.id.spi,
                mark: self.parameters.mark,
            })
            .await
    }
}
