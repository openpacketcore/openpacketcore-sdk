//! Compatibility checks before engine participation and consumer admission.

use super::*;
use opc_consensus::ConsensusCompatibility;

pub(super) struct CompatibilityGate {
    identity: opc_consensus::ConsensusIdentity,
    local_node_id: ConsensusNodeId,
    profile: ConfigPeerCompatibility,
    digest: ConsensusCompatibility,
    peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
    operation_timeout: Duration,
}

impl fmt::Debug for CompatibilityGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompatibilityGate(<redacted>)")
    }
}

impl CompatibilityGate {
    pub(super) fn new(
        identity: opc_consensus::ConsensusIdentity,
        local_node_id: ConsensusNodeId,
        profile: ConfigPeerCompatibility,
        peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
        operation_timeout: Duration,
    ) -> Arc<Self> {
        let mut digest = Sha256::new();
        digest.update(b"openpacketcore/config-consensus/connection-compatibility/v1\0");
        digest.update(profile.wire_version.to_be_bytes());
        digest.update(profile.command_version.to_be_bytes());
        digest.update(profile.audit_key_epoch.to_be_bytes());
        digest.update(profile.audit_key_fingerprint);
        let digest = digest.finalize().into();
        let peers = peers
            .into_iter()
            .map(|(node, peer)| (node, peer.with_compatibility(digest).unwrap_or(peer)))
            .collect();
        Arc::new(Self {
            identity,
            local_node_id,
            profile,
            digest,
            peers,
            operation_timeout,
        })
    }

    pub(super) fn digest(&self) -> ConsensusCompatibility {
        self.digest
    }

    pub(super) fn profile(&self) -> ConfigPeerCompatibility {
        self.profile
    }

    pub(super) fn guarded_peers(
        self: &Arc<Self>,
    ) -> BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>> {
        self.peers
            .iter()
            .map(|(node, peer)| {
                let peer: Arc<dyn ConsensusPeer> = Arc::new(CompatiblePeer {
                    peer: peer.clone(),
                    gate: self.clone(),
                });
                (*node, peer)
            })
            .collect()
    }

    async fn probe(
        &self,
        target: ConsensusNodeId,
        deadline: tokio::time::Instant,
    ) -> Result<Option<ConsensusCompatibility>, ConsensusPeerError> {
        let peer = self
            .peers
            .get(&target)
            .ok_or(ConsensusPeerError::ScopeMismatch)?;
        if peer.node_id() != target {
            return Err(ConsensusPeerError::ScopeMismatch);
        }
        let request = ReadBarrierRequest {
            compatibility: self.profile,
            compatibility_probe: true,
            budget: ForwardedBudget::from_deadline(deadline)
                .map_err(|_| ConsensusPeerError::Timeout)?,
        };
        let request = ConsensusWireRequest::try_new(
            self.identity,
            self.local_node_id,
            ConsensusRpcFamily::ReadBarrier,
            encode_config_wire(&request).map_err(|_| ConsensusPeerError::Protocol)?,
        )?;
        let reply = tokio::time::timeout_at(
            deadline,
            peer.call_with_compatibility(
                request,
                None,
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            ),
        )
        .await
        .map_err(|_| ConsensusPeerError::Timeout)??;
        reply.response.validate()?;
        let response: ReadBarrierReply = decode_config_wire(&reply.response.result?)
            .map_err(|_| ConsensusPeerError::Protocol)?;
        if response != ReadBarrierReply::Compatible
            || reply
                .compatibility
                .is_some_and(|profile| profile != self.digest)
        {
            return Err(ConsensusPeerError::ScopeMismatch);
        }
        Ok(reply.compatibility)
    }

    pub(super) async fn verify(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
        require_all: bool,
    ) -> Result<(), ConfigConsensusOpenError> {
        let quorum = self.peers.len().div_ceil(2) + 1;
        loop {
            let mut probes = tokio::task::JoinSet::new();
            for target in self.peers.keys().copied() {
                let gate = self.clone();
                probes.spawn(async move { gate.probe(target, deadline).await });
            }
            let mut compatible = 1;
            let mut verified = 1;
            let mut incompatible = false;
            while let Some(result) = probes.join_next().await {
                match result {
                    Ok(Ok(proof)) => {
                        compatible += 1;
                        verified += usize::from(proof.is_some());
                    }
                    Ok(Err(ConsensusPeerError::ScopeMismatch | ConsensusPeerError::Protocol)) => {
                        incompatible = true;
                    }
                    Ok(Err(_)) | Err(_) => {}
                }
                if !require_all && verified >= quorum {
                    return Ok(());
                }
            }
            if compatible == self.peers.len() + 1 {
                return Ok(());
            }
            if incompatible {
                return Err(ConfigConsensusOpenError::ClusterFormationRejected);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(if require_all {
                    ConfigConsensusOpenError::ClusterFormationRejected
                } else {
                    ConfigConsensusOpenError::CompatibleQuorumUnavailable
                });
            }
            tokio::time::sleep_until(
                (tokio::time::Instant::now() + ROUTE_RETRY_BACKOFF).min(deadline),
            )
            .await;
        }
    }

    pub(super) async fn authorize_inbound(
        self: &Arc<Self>,
        sender: ConsensusNodeId,
        proof: Option<ConsensusCompatibility>,
    ) -> Result<(), ConsensusPeerError> {
        if let Some(proof) = proof {
            return if proof == self.digest {
                Ok(())
            } else {
                Err(ConsensusPeerError::ScopeMismatch)
            };
        }
        let deadline = tokio::time::Instant::now() + self.operation_timeout;
        // Legacy evidence is never a connection proof. Recheck the sender on
        // every engine call so a rejected/restarted member has no cached grant.
        if self.probe(sender, deadline).await?.is_some() {
            return Err(ConsensusPeerError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct CompatiblePeer {
    peer: Arc<dyn ConsensusPeer>,
    gate: Arc<CompatibilityGate>,
}

#[async_trait]
impl ConsensusPeer for CompatiblePeer {
    fn node_id(&self) -> ConsensusNodeId {
        self.peer.node_id()
    }

    fn scope_identity(&self) -> Option<opc_consensus::ConsensusIdentity> {
        self.peer.scope_identity()
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.call_with_timeout(request, self.gate.operation_timeout)
            .await
    }

    async fn call_with_timeout(
        &self,
        request: ConsensusWireRequest,
        timeout: Duration,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        if !matches!(
            request.family,
            ConsensusRpcFamily::Vote
                | ConsensusRpcFamily::AppendEntries
                | ConsensusRpcFamily::InstallSnapshot
        ) {
            return self.peer.call_with_timeout(request, timeout).await;
        }
        let deadline = tokio::time::Instant::now() + timeout;
        let proof = self.gate.probe(self.peer.node_id(), deadline).await?;
        let reply = tokio::time::timeout_at(
            deadline,
            self.peer.call_with_compatibility(
                request,
                proof,
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            ),
        )
        .await
        .map_err(|_| ConsensusPeerError::Timeout)??;
        Ok(reply.response)
    }
}
