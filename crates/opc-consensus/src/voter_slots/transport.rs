use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use super::*;
use crate::{
    ConsensusIdentity, ConsensusNodeId, ConsensusPeer, ConsensusPeerError, ConsensusWireRequest,
    ConsensusWireResponse,
};

/// One authenticated transport response. The proof has no wire deserializer.
#[derive(Debug)]
pub struct VoterAuthenticatedResponse {
    /// Complete bounded result, including a peer's explicit refusal.
    pub response: ConsensusWireResponse,
    /// A fresh proof of the remote key, request/result pair and actual channel.
    pub proof: VerifiedVoterRpc,
}

/// A configured route for one exact committed public binding.
#[derive(Debug, Clone)]
pub struct VoterPeerRoute {
    /// Exact checked descriptor/key identity supplied to the resolver.
    pub member: VoterSlotMember,
    /// Current authenticated endpoint SVID, including reused logical slot SVIDs.
    pub spiffe_id: String,
    /// Transport implementing mutual incarnation proof on every call.
    pub peer: Arc<dyn ConsensusPeer>,
}

/// Trusted transport adapter for committed members and the selected candidate.
///
/// Resolution cannot enroll a voter: stores compare the returned complete
/// binding with durable slot state, then require its private-key proof. The
/// consumer may resolve a newly selected descriptor without a process restart.
pub trait VoterPeerResolver: Send + Sync + std::fmt::Debug {
    /// Resolve one exact public binding, or fail closed without another route.
    fn resolve(&self, member: &VoterSlotMember) -> Result<VoterPeerRoute, ConsensusPeerError>;
}

/// Canonical domain-separated commitment to the complete request, including family.
pub fn voter_rpc_request_digest(
    request: &ConsensusWireRequest,
) -> Result<[u8; 32], ConsensusPeerError> {
    request.validate()?;
    let mut hash = Sha256::new();
    hash.update(b"openpacketcore/consensus/incarnation-request/v1\0");
    hash.update(postcard::to_allocvec(request).map_err(|_| ConsensusPeerError::Protocol)?);
    Ok(hash.finalize().into())
}

/// Canonical commitment to both the triggering request and complete result.
pub fn voter_rpc_response_digest(
    request: &ConsensusWireRequest,
    response: &ConsensusWireResponse,
) -> Result<[u8; 32], ConsensusPeerError> {
    response.validate()?;
    let mut hash = Sha256::new();
    hash.update(b"openpacketcore/consensus/incarnation-response/v1\0");
    hash.update(voter_rpc_request_digest(request)?);
    hash.update(postcard::to_allocvec(response).map_err(|_| ConsensusPeerError::Protocol)?);
    Ok(hash.finalize().into())
}

/// Shared authenticated transport and per-peer drain boundary for a store profile.
pub struct VoterTransport<E: VoterResponseFenceEngine> {
    local: ConsensusNodeId,
    admission: Arc<VoterAdmission<E>>,
    resolver: Arc<dyn VoterPeerResolver>,
    profile_digest: [u8; 32],
}

impl<E: VoterResponseFenceEngine> std::fmt::Debug for VoterTransport<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoterTransport").finish_non_exhaustive()
    }
}

impl<E: VoterResponseFenceEngine> VoterTransport<E> {
    /// Bind a resolver to the store-owned, initially closed admission runtime.
    pub fn new(
        local: ConsensusNodeId,
        admission: Arc<VoterAdmission<E>>,
        resolver: Arc<dyn VoterPeerResolver>,
        profile_digest: [u8; 32],
    ) -> Arc<Self> {
        Arc::new(Self {
            local,
            admission,
            resolver,
            profile_digest,
        })
    }

    /// Create a cheap dynamic route. Every call rechecks durable selection and key proof.
    pub fn peer(self: &Arc<Self>, target: ConsensusNodeId) -> Arc<dyn ConsensusPeer> {
        Arc::new(AdmittedPeer {
            transport: self.clone(),
            target,
        })
    }

    /// Check the selected route against the controller's exact candidate SVID.
    pub fn validate_candidate_route(
        &self,
        request: &VoterReplacementRequest,
    ) -> Result<(), ConsensusPeerError> {
        let route = self.route(&request.candidate)?;
        if route.spiffe_id != request.attestation.candidate_spiffe_id {
            return Err(ConsensusPeerError::ScopeMismatch);
        }
        Ok(())
    }

    fn route(&self, member: &VoterSlotMember) -> Result<VoterPeerRoute, ConsensusPeerError> {
        let route = self.resolver.resolve(member)?;
        if route.member != *member
            || route.peer.node_id() != member.identity.node_id()
            || route.spiffe_id.is_empty()
        {
            return Err(ConsensusPeerError::ScopeMismatch);
        }
        Ok(route)
    }

    /// Consume proof and count key-proven activity before later scope or payload refusal.
    /// Store-specific command and voting gates run after this common boundary.
    pub fn authenticate(
        &self,
        proof: VerifiedVoterRpc,
        request: &ConsensusWireRequest,
    ) -> Result<AuthenticatedVoterEvidence, ConsensusPeerError> {
        let evidence = proof.consume().map_err(peer_error)?;
        self.admission
            .observe_authenticated(&evidence)
            .map_err(peer_error)?;
        let binding = evidence.binding();
        let state = self.admission.durable_view().map_err(peer_error)?;
        let table = state.table();
        let source = self.route(find_member(table, request.sender)?)?;
        let destination = self.route(find_member(table, self.local)?)?;
        if binding.kind != VoterRpcProofKind::Request
            || binding.profile_digest != self.profile_digest
            || binding.cluster_instance != table.cluster_instance
            || binding.configuration != request.identity
            || !configuration_admitted(table, request.identity, request.family)
            || binding.source != source.member
            || binding.destination != destination.member
            || binding.source_spiffe_id != source.spiffe_id
            || binding.destination_spiffe_id != destination.spiffe_id
            || binding.payload_digest != voter_rpc_request_digest(request)?
        {
            return Err(ConsensusPeerError::ScopeMismatch);
        }
        Ok(evidence)
    }

    async fn call(
        self: &Arc<Self>,
        target: ConsensusNodeId,
        mut request: ConsensusWireRequest,
        timeout: Duration,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ConsensusPeerError::Timeout)?;
        let state = self.admission.durable_view().map_err(peer_error)?;
        let table = state.table();
        let source = self.route(find_member(table, self.local)?)?;
        let destination = self.route(find_member(table, target)?)?;
        if matches!(
            request.family,
            crate::ConsensusRpcFamily::Vote | crate::ConsensusRpcFamily::LeadershipTransfer
        ) && (!self.admission.local_voting_admitted()
            || !table.slots.iter().any(|slot| {
                slot.member == destination.member && slot.phase == VoterSlotPhase::Voting
            }))
        {
            return Err(ConsensusPeerError::ScopeMismatch);
        }
        request.identity = table
            .current_configuration()
            .identity(table.cluster_instance, table.manifest_digest)
            .map_err(|_| ConsensusPeerError::ScopeMismatch)?;
        request.sender = self.local;
        let binding = VoterRpcBinding {
            cluster_instance: table.cluster_instance,
            configuration: request.identity,
            profile_digest: self.profile_digest,
            source: source.member,
            destination: destination.member,
            source_spiffe_id: source.spiffe_id,
            destination_spiffe_id: destination.spiffe_id,
            replacement_digest: table
                .replacement
                .as_ref()
                .map(|operation| operation.attestation.request_digest),
            payload_digest: voter_rpc_request_digest(&request)?,
            kind: VoterRpcProofKind::Request,
        };
        let runtime = self.admission.clone();
        let result = self
            .admission
            .run_peer(target, deadline, move || async move {
                let reply = destination
                    .peer
                    .call_with_incarnation(
                        request.clone(),
                        binding.clone(),
                        deadline.saturating_duration_since(Instant::now()),
                    )
                    .await;
                let reply = match reply {
                    Ok(reply) => reply,
                    Err(error) => return Ok(Err(error)),
                };
                let evidence = reply.proof.consume()?;
                runtime.observe_authenticated(&evidence)?;
                let response_binding = evidence.binding();
                let expected_digest = voter_rpc_response_digest(&request, &reply.response)
                    .map_err(|_| VoterReplacementError::UnauthorizedReplacement)?;
                if response_binding.kind != VoterRpcProofKind::Response
                    || response_binding.profile_digest != binding.profile_digest
                    || response_binding.cluster_instance != binding.cluster_instance
                    || response_binding.configuration != binding.configuration
                    || response_binding.source != binding.destination
                    || response_binding.destination != binding.source
                    || response_binding.source_spiffe_id != binding.destination_spiffe_id
                    || response_binding.destination_spiffe_id != binding.source_spiffe_id
                    || response_binding.replacement_digest != binding.replacement_digest
                    || response_binding.payload_digest != expected_digest
                {
                    return Err(VoterReplacementError::UnauthorizedReplacement);
                }
                Ok(Ok(reply.response))
            })
            .await
            .map_err(peer_error)?;
        result
    }
}

fn find_member(
    table: &VoterSlotTable,
    node: ConsensusNodeId,
) -> Result<&VoterSlotMember, ConsensusPeerError> {
    table
        .slots
        .iter()
        .map(|slot| &slot.member)
        .chain(
            table
                .replacement
                .iter()
                .flat_map(|operation| operation.predecessor.members.iter()),
        )
        .find(|member| member.identity.node_id() == node)
        .ok_or(ConsensusPeerError::ScopeMismatch)
}

fn configuration_admitted(
    table: &VoterSlotTable,
    identity: ConsensusIdentity,
    family: crate::ConsensusRpcFamily,
) -> bool {
    let matches = |configuration: &VoterConfiguration| {
        configuration
            .identity(table.cluster_instance, table.manifest_digest)
            .ok()
            == Some(identity)
    };
    matches(&table.current_configuration())
        || table.replacement.as_ref().is_some_and(|operation| {
            // A retained candidate can lag Fence while the unchanged majority has
            // already finalized C1. That exact selected C1 may send recovery data;
            // engine/apply ordering still governs voting and application authority.
            matches!(
                family,
                crate::ConsensusRpcFamily::AppendEntries
                    | crate::ConsensusRpcFamily::InstallSnapshot
            ) && (matches(&operation.predecessor) || matches(&operation.successor))
        })
}

fn peer_error(error: VoterReplacementError) -> ConsensusPeerError {
    match error {
        VoterReplacementError::Deadline | VoterReplacementError::OutcomeUnknown => {
            ConsensusPeerError::Timeout
        }
        VoterReplacementError::Unavailable | VoterReplacementError::NoSurvivingQuorum => {
            ConsensusPeerError::Unavailable
        }
        _ => ConsensusPeerError::ScopeMismatch,
    }
}

struct AdmittedPeer<E: VoterResponseFenceEngine> {
    transport: Arc<VoterTransport<E>>,
    target: ConsensusNodeId,
}
impl<E: VoterResponseFenceEngine> std::fmt::Debug for AdmittedPeer<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmittedVoterPeer").finish_non_exhaustive()
    }
}
#[async_trait]
impl<E: VoterResponseFenceEngine> ConsensusPeer for AdmittedPeer<E> {
    fn node_id(&self) -> ConsensusNodeId {
        self.target
    }
    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.call_with_timeout(request, crate::DURABLE_CONSENSUS_OPERATION_TIMEOUT)
            .await
    }
    async fn call_with_timeout(
        &self,
        request: ConsensusWireRequest,
        timeout: Duration,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.transport.call(self.target, request, timeout).await
    }
}
