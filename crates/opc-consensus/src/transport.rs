//! Authenticated bounded transport port shared by consensus consumers.

use std::time::Duration;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{ConsensusCodecError, ConsensusIdentity, ConsensusNodeId};

/// Current SDK-owned consensus envelope schema.
pub const CONSENSUS_SCHEMA_VERSION: u16 = 1;

/// Maximum decoded inner payload accepted for one consensus call.
pub const CONSENSUS_MAX_RPC_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

// These are frozen upper bounds for the two alternative singleton
// protected-roster commands. They are intentionally kept as components so a
// future command-shape change must update its own accounting rather than
// silently widening the shared RPC budget.
const PROTECTED_ROSTER_ADMISSION_CANONICAL_BYTES: usize = 2_245_658;
const PROTECTED_ROSTER_ADMISSION_INGRESS_BYTES: usize = 1_024;
const PROTECTED_ROSTER_ADMISSION_COMPACT_PROVENANCE_BYTES: usize = 2_048;
const PROTECTED_ROSTER_ADMISSION_AUTHORITY_COMMAND_WRAPPER_BYTES: usize = 4_096;

const PROTECTED_ROSTER_TERMINAL_CODEC_BYTES: usize = 1_065_423;
/// Maximum canonical Profile-V2 executor proof bundle accepted in a
/// protected-roster consensus command.
///
/// This is sourced from the public roster profile bound. Keeping it public
/// permits the session-store profile to assert that consensus never rejects a
/// profile-valid command before its deterministic validation path.
pub const CONSENSUS_PROTECTED_ROSTER_TERMINAL_PROOF_BUNDLE_BYTES: usize = 40_960;
/// Maximum canonical Profile-V2 compact terminal evidence accepted in a
/// protected-roster consensus command.
///
/// This is sourced from the public roster profile bound; it is intentionally
/// not a separate transport-only limit.
pub const CONSENSUS_PROTECTED_ROSTER_TERMINAL_COMPACT_EVIDENCE_BYTES: usize = 8_192;
const PROTECTED_ROSTER_TERMINAL_INGRESS_BYTES: usize = 1_024;
const PROTECTED_ROSTER_TERMINAL_BINDING_COMMAND_WRAPPER_BYTES: usize = 4_096;

const PROTECTED_ROSTER_SINGLETON_APPEND_ENTRIES_FORWARD_ENVELOPE_BYTES: usize = 512;

const fn protected_roster_checked_add(left: usize, right: usize) -> usize {
    match left.checked_add(right) {
        Some(sum) => sum,
        None => panic!("protected-roster bound must fit usize"),
    }
}

const PROTECTED_ROSTER_ADMISSION_COMMAND_BYTES: usize = protected_roster_checked_add(
    protected_roster_checked_add(
        protected_roster_checked_add(
            PROTECTED_ROSTER_ADMISSION_CANONICAL_BYTES,
            PROTECTED_ROSTER_ADMISSION_INGRESS_BYTES,
        ),
        PROTECTED_ROSTER_ADMISSION_COMPACT_PROVENANCE_BYTES,
    ),
    PROTECTED_ROSTER_ADMISSION_AUTHORITY_COMMAND_WRAPPER_BYTES,
);

const PROTECTED_ROSTER_TERMINAL_COMMAND_BYTES: usize = protected_roster_checked_add(
    protected_roster_checked_add(
        protected_roster_checked_add(
            protected_roster_checked_add(
                PROTECTED_ROSTER_TERMINAL_CODEC_BYTES,
                CONSENSUS_PROTECTED_ROSTER_TERMINAL_PROOF_BUNDLE_BYTES,
            ),
            CONSENSUS_PROTECTED_ROSTER_TERMINAL_COMPACT_EVIDENCE_BYTES,
        ),
        PROTECTED_ROSTER_TERMINAL_INGRESS_BYTES,
    ),
    PROTECTED_ROSTER_TERMINAL_BINDING_COMMAND_WRAPPER_BYTES,
);

const PROTECTED_ROSTER_MAX_COMMAND_BYTES: usize =
    if PROTECTED_ROSTER_ADMISSION_COMMAND_BYTES > PROTECTED_ROSTER_TERMINAL_COMMAND_BYTES {
        PROTECTED_ROSTER_ADMISSION_COMMAND_BYTES
    } else {
        PROTECTED_ROSTER_TERMINAL_COMMAND_BYTES
    };

/// Maximum decoded payload for one roster-only forwarding or singleton
/// AppendEntries request.
///
/// The admission and terminal commands are alternatives, not a combined
/// payload. This is their larger frozen command budget plus the singleton
/// AppendEntries/forward envelope. Every unrelated family, response, and
/// mixed or multi-entry AppendEntries request retains
/// [`CONSENSUS_MAX_RPC_PAYLOAD_BYTES`].
pub const CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES: usize = protected_roster_checked_add(
    PROTECTED_ROSTER_MAX_COMMAND_BYTES,
    PROTECTED_ROSTER_SINGLETON_APPEND_ENTRIES_FORWARD_ENVELOPE_BYTES,
);

const _: () = {
    assert!(PROTECTED_ROSTER_ADMISSION_COMMAND_BYTES == 2_252_826);
    assert!(PROTECTED_ROSTER_TERMINAL_COMMAND_BYTES == 1_119_695);
    assert!(CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES == 2_253_338);
};

/// Fixed request family used for authorization, deadlines, and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConsensusRpcFamily {
    /// Openraft vote request.
    Vote,
    /// Openraft append/heartbeat request.
    AppendEntries,
    /// One normal AppendEntries request carrying exactly one protected-roster
    /// command.
    ///
    /// The session Raft adapter selects this family only after proving the
    /// singleton roster predicate. Receivers repeat that proof after bounded
    /// decoding and before invoking Openraft.
    AppendEntriesRoster,
    /// One bounded Openraft snapshot chunk.
    InstallSnapshot,
    /// Forward one consumer command to the current leader.
    ForwardMutation,
    /// Forward one atomic protected-roster command to the current leader.
    ///
    /// This is the only forwarded family with the roster-specific bounded
    /// payload ceiling. Consumers must reject every non-roster command before
    /// dispatching it through this family.
    ForwardRosterMutation,
    /// Ask the leader for a linearizable read barrier.
    ReadBarrier,
    /// Prove that a staged membership candidate applied a durable transition
    /// marker before successor Vote traffic is admitted.
    TopologyAdmissionBarrier,
}

impl ConsensusRpcFamily {
    /// Stable fixed-cardinality metrics code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vote => "vote",
            Self::AppendEntries => "append_entries",
            Self::AppendEntriesRoster => "append_entries_roster",
            Self::InstallSnapshot => "install_snapshot",
            Self::ForwardMutation => "forward_mutation",
            Self::ForwardRosterMutation => "forward_roster_mutation",
            Self::ReadBarrier => "read_barrier",
            Self::TopologyAdmissionBarrier => "topology_admission_barrier",
        }
    }

    /// Return the bounded request payload ceiling for this RPC family.
    ///
    /// A roster-sized AppendEntries envelope uses the distinct
    /// [`Self::AppendEntriesRoster`] family. The session Raft adapter must
    /// prove that it is exactly one normal roster command before selecting
    /// that family, and receivers must prove it again after decoding.
    pub const fn max_request_payload_bytes(self) -> usize {
        match self {
            Self::ForwardRosterMutation | Self::AppendEntriesRoster => {
                CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES
            }
            Self::Vote
            | Self::AppendEntries
            | Self::InstallSnapshot
            | Self::ForwardMutation
            | Self::ReadBarrier
            | Self::TopologyAdmissionBarrier => CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
        }
    }
}

/// Encode one protected-roster value with the isolated roster payload ceiling.
///
/// This is intentionally separate from [`crate::encode_bounded`]. Callers
/// must use it only after proving that the value is one roster admission or
/// terminal command, or one singleton normal AppendEntries request carrying
/// such a command.
pub fn encode_roster_bounded<T>(value: &T) -> Result<Vec<u8>, ConsensusCodecError>
where
    T: Serialize + ?Sized,
{
    encode_with_limit(value, CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES)
}

/// Decode one complete protected-roster value with the isolated roster
/// payload ceiling.
///
/// Callers must verify the decoded value's roster-only structural predicate
/// before accepting it. This function solely owns bounded, canonical codec
/// admission.
pub fn decode_roster_bounded<T>(encoded: &[u8]) -> Result<T, ConsensusCodecError>
where
    T: DeserializeOwned,
{
    decode_with_limit(encoded, CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES)
}

fn encode_with_limit<T>(value: &T, limit: usize) -> Result<Vec<u8>, ConsensusCodecError>
where
    T: Serialize + ?Sized,
{
    let serialized_size =
        postcard::experimental::serialized_size(value).map_err(|_| ConsensusCodecError::Encode)?;
    if serialized_size > limit {
        return Err(ConsensusCodecError::TooLarge);
    }
    let mut encoded = vec![0_u8; serialized_size];
    let actual_len = postcard::to_slice(value, encoded.as_mut_slice())
        .map_err(|_| ConsensusCodecError::Encode)?
        .len();
    if actual_len > serialized_size || actual_len > limit {
        return Err(ConsensusCodecError::TooLarge);
    }
    encoded.truncate(actual_len);
    Ok(encoded)
}

fn decode_with_limit<T>(encoded: &[u8], limit: usize) -> Result<T, ConsensusCodecError>
where
    T: DeserializeOwned,
{
    if encoded.len() > limit {
        return Err(ConsensusCodecError::TooLarge);
    }
    let (decoded, remainder) =
        postcard::take_from_bytes(encoded).map_err(|_| ConsensusCodecError::Decode)?;
    if !remainder.is_empty() {
        return Err(ConsensusCodecError::Decode);
    }
    Ok(decoded)
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
        if payload.len() > family.max_request_payload_bytes() {
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
            || self.payload.len() > self.family.max_request_payload_bytes()
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

    /// Exact authenticated cluster/configuration/epoch scope of this peer.
    ///
    /// Fixed-topology compatibility adapters may leave this absent. Dynamic
    /// peer directories must reject `None` rather than treating a caller-
    /// supplied node ordinal as sufficient identity evidence.
    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        None
    }

    /// Send one scoped call under one complete logical deadline.
    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError>;

    /// Send one scoped call under the caller's complete logical timeout.
    ///
    /// The default preserves compatibility for in-process and test peers by
    /// delegating unchanged; their caller retains its existing outer hard
    /// deadline. Network transports should override this method and drive
    /// their own connection, handshake, and frame deadlines to an explicit
    /// terminal result before that outer hard deadline can cancel the future.
    async fn call_with_timeout(
        &self,
        request: ConsensusWireRequest,
        _timeout: Duration,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.call(request).await
    }
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Notify;

    use super::*;
    use crate::{ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusConfigurationId};

    #[derive(Debug)]
    struct CompatibilityPeer {
        entered: Notify,
        release: Notify,
    }

    #[async_trait]
    impl ConsensusPeer for CompatibilityPeer {
        fn node_id(&self) -> ConsensusNodeId {
            ConsensusNodeId::new(2).expect("non-zero node ID")
        }

        async fn call(
            &self,
            _request: ConsensusWireRequest,
        ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(ConsensusWireResponse {
                result: Ok(Vec::new()),
            })
        }
    }

    fn request() -> ConsensusWireRequest {
        ConsensusWireRequest::try_new(
            ConsensusIdentity::new(
                ConsensusClusterId::from_bytes([1; 32]),
                ConsensusConfigurationId::from_bytes([2; 32]),
                ConsensusConfigurationEpoch::new(1).expect("positive epoch"),
            ),
            ConsensusNodeId::new(1).expect("non-zero node ID"),
            ConsensusRpcFamily::Vote,
            Vec::new(),
        )
        .expect("bounded request")
    }

    #[test]
    fn wire_payload_ceiling_is_inclusive_for_requests_and_responses() {
        let template = request();
        let exact_request = ConsensusWireRequest::try_new(
            template.identity,
            template.sender,
            template.family,
            vec![0; CONSENSUS_MAX_RPC_PAYLOAD_BYTES],
        )
        .expect("the exact request payload ceiling is valid");
        assert_eq!(exact_request.validate(), Ok(()));

        let over_request = ConsensusWireRequest {
            payload: vec![0; CONSENSUS_MAX_RPC_PAYLOAD_BYTES + 1],
            ..request()
        };
        assert_eq!(over_request.validate(), Err(ConsensusPeerError::Protocol));
        assert_eq!(
            ConsensusWireRequest::try_new(
                over_request.identity,
                over_request.sender,
                over_request.family,
                over_request.payload,
            ),
            Err(ConsensusPeerError::Protocol)
        );

        let exact_response = ConsensusWireResponse {
            result: Ok(vec![0; CONSENSUS_MAX_RPC_PAYLOAD_BYTES]),
        };
        assert_eq!(exact_response.validate(), Ok(()));
        let over_response = ConsensusWireResponse {
            result: Ok(vec![0; CONSENSUS_MAX_RPC_PAYLOAD_BYTES + 1]),
        };
        assert_eq!(over_response.validate(), Err(ConsensusPeerError::Protocol));
    }

    #[test]
    fn roster_request_ceiling_is_inclusive_without_relaxing_ordinary_families() {
        let template = request();
        assert_eq!(CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES, 2_253_338);
        for family in [
            ConsensusRpcFamily::AppendEntriesRoster,
            ConsensusRpcFamily::ForwardRosterMutation,
        ] {
            assert_eq!(
                family.max_request_payload_bytes(),
                CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES
            );
            let roster = ConsensusWireRequest::try_new(
                template.identity,
                template.sender,
                family,
                vec![u8::MAX; CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES],
            )
            .expect("the exact roster ceiling is valid");
            assert_eq!(roster.validate(), Ok(()));
            assert_eq!(
                ConsensusWireRequest::try_new(
                    template.identity,
                    template.sender,
                    family,
                    vec![u8::MAX; CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES + 1],
                ),
                Err(ConsensusPeerError::Protocol)
            );
        }
        for family in [
            ConsensusRpcFamily::AppendEntries,
            ConsensusRpcFamily::ForwardMutation,
            ConsensusRpcFamily::Vote,
            ConsensusRpcFamily::InstallSnapshot,
            ConsensusRpcFamily::ReadBarrier,
            ConsensusRpcFamily::TopologyAdmissionBarrier,
        ] {
            assert_eq!(
                family.max_request_payload_bytes(),
                CONSENSUS_MAX_RPC_PAYLOAD_BYTES
            );
            assert!(
                ConsensusWireRequest::try_new(
                    template.identity,
                    template.sender,
                    family,
                    vec![u8::MAX; CONSENSUS_MAX_RPC_PAYLOAD_BYTES],
                )
                .is_ok(),
                "the ordinary {family:?} ceiling remains 2 MiB"
            );
            assert_eq!(
                ConsensusWireRequest::try_new(
                    template.identity,
                    template.sender,
                    family,
                    vec![u8::MAX; CONSENSUS_MAX_RPC_PAYLOAD_BYTES + 1],
                ),
                Err(ConsensusPeerError::Protocol)
            );
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct BytesValue {
        bytes: Vec<u8>,
    }

    #[test]
    fn roster_codec_accepts_its_exact_limit_and_rejects_one_byte_more() {
        // The postcard vector length uses a four-byte varint at this size.
        let exact = BytesValue {
            bytes: vec![u8::MAX; CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES - 4],
        };
        let encoded = encode_roster_bounded(&exact).expect("exact roster codec ceiling");
        assert_eq!(encoded.len(), CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES);
        assert_eq!(decode_roster_bounded::<BytesValue>(&encoded), Ok(exact));

        let over = BytesValue {
            bytes: vec![u8::MAX; CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES - 3],
        };
        assert_eq!(
            encode_roster_bounded(&over),
            Err(ConsensusCodecError::TooLarge)
        );
        assert_eq!(
            decode_roster_bounded::<BytesValue>(&vec![
                0;
                CONSENSUS_MAX_ROSTER_RPC_PAYLOAD_BYTES + 1
            ]),
            Err(ConsensusCodecError::TooLarge)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn compatibility_default_does_not_add_a_soft_cancellation_boundary() {
        let peer = Arc::new(CompatibilityPeer {
            entered: Notify::new(),
            release: Notify::new(),
        });
        let call = tokio::spawn({
            let peer = Arc::clone(&peer);
            async move {
                peer.call_with_timeout(request(), Duration::from_millis(10))
                    .await
            }
        });

        peer.entered.notified().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !call.is_finished(),
            "the compatibility default must leave hard cancellation to its caller"
        );

        peer.release.notify_one();
        assert_eq!(
            call.await.expect("compatibility peer task"),
            Ok(ConsensusWireResponse {
                result: Ok(Vec::new()),
            })
        );
    }
}
