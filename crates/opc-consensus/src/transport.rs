//! Authenticated bounded transport port shared by consensus consumers.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{ConsensusIdentity, ConsensusNodeId};

/// Current SDK-owned consensus envelope schema.
pub const CONSENSUS_SCHEMA_VERSION: u16 = 1;

/// Maximum decoded inner payload accepted for one consensus call.
pub const CONSENSUS_MAX_RPC_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

/// Fixed request family used for authorization, deadlines, and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConsensusRpcFamily {
    /// Openraft vote request.
    Vote,
    /// Openraft append/heartbeat request.
    AppendEntries,
    /// One bounded Openraft snapshot chunk.
    InstallSnapshot,
    /// Forward one consumer command to the current leader.
    ForwardMutation,
    /// Ask the leader for a linearizable read barrier.
    ReadBarrier,
}

impl ConsensusRpcFamily {
    /// Stable fixed-cardinality metrics code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vote => "vote",
            Self::AppendEntries => "append_entries",
            Self::InstallSnapshot => "install_snapshot",
            Self::ForwardMutation => "forward_mutation",
            Self::ReadBarrier => "read_barrier",
        }
    }
}

/// Redaction-safe peer/authorization failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
pub enum ConsensusPeerError {
    /// Peer could not be reached.
    #[error("consensus peer unavailable")]
    Unavailable,
    /// Complete logical call exceeded its deadline.
    #[error("consensus peer timeout")]
    Timeout,
    /// Mutual authentication or peer binding failed.
    #[error("consensus peer authentication failed")]
    Authentication,
    /// Cluster, configuration, epoch, sender, or schema did not match.
    #[error("consensus peer scope mismatch")]
    ScopeMismatch,
    /// Bounded inner payload was malformed or oversized.
    #[error("consensus peer protocol violation")]
    Protocol,
    /// Remote engine rejected or failed the call.
    #[error("consensus peer rejected request")]
    Rejected,
}

/// One authenticated consensus call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusWireRequest {
    /// Exact consensus envelope schema.
    pub schema_version: u16,
    /// Cluster/configuration/epoch scope.
    pub identity: ConsensusIdentity,
    /// Canonical sender ordinal bound to the live authenticated peer.
    pub sender: ConsensusNodeId,
    /// Bounded operation family.
    pub family: ConsensusRpcFamily,
    /// Serialized private engine request or consumer command.
    pub payload: Vec<u8>,
}

impl ConsensusWireRequest {
    /// Construct after enforcing the inner payload ceiling.
    pub fn try_new(
        identity: ConsensusIdentity,
        sender: ConsensusNodeId,
        family: ConsensusRpcFamily,
        payload: Vec<u8>,
    ) -> Result<Self, ConsensusPeerError> {
        if payload.len() > CONSENSUS_MAX_RPC_PAYLOAD_BYTES {
            return Err(ConsensusPeerError::Protocol);
        }
        Ok(Self {
            schema_version: CONSENSUS_SCHEMA_VERSION,
            identity,
            sender,
            family,
            payload,
        })
    }

    /// Validate schema and payload bounds before inner decoding.
    pub fn validate(&self) -> Result<(), ConsensusPeerError> {
        if self.schema_version != CONSENSUS_SCHEMA_VERSION
            || self.payload.len() > CONSENSUS_MAX_RPC_PAYLOAD_BYTES
        {
            return Err(ConsensusPeerError::Protocol);
        }
        Ok(())
    }
}

/// One bounded consensus response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusWireResponse {
    /// Serialized private engine response or a fixed failure.
    pub result: Result<Vec<u8>, ConsensusPeerError>,
}

impl ConsensusWireResponse {
    /// Validate the success payload ceiling before inner decoding.
    pub fn validate(&self) -> Result<(), ConsensusPeerError> {
        if self
            .result
            .as_ref()
            .is_ok_and(|payload| payload.len() > CONSENSUS_MAX_RPC_PAYLOAD_BYTES)
        {
            return Err(ConsensusPeerError::Protocol);
        }
        Ok(())
    }
}

/// Outbound consensus-only peer port.
#[async_trait]
pub trait ConsensusPeer: Send + Sync + std::fmt::Debug {
    /// Canonical ordinal expected for the authenticated remote peer.
    fn node_id(&self) -> ConsensusNodeId;

    /// Send one scoped call under one complete logical deadline.
    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError>;
}

/// Inbound consensus-only handler exposed by an authenticated server.
#[async_trait]
pub trait ConsensusRpcHandler: Send + Sync + std::fmt::Debug {
    /// Handle one already-authenticated bounded request.
    async fn handle(
        &self,
        authenticated_sender: ConsensusNodeId,
        request: ConsensusWireRequest,
    ) -> ConsensusWireResponse;
}
