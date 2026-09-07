//! Product-neutral authority gate for consensus-backed config servers.

use async_trait::async_trait;
use opc_types::{ConfigVersion, Timestamp, TxId};
use thiserror::Error;

/// Maximum encoded leader-hint length accepted at the management boundary.
pub const MAX_CONFIG_LEADER_HINT_BYTES: usize = 255;

/// Config operation that must be admitted by the current writer of record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigAuthorityOperation {
    /// A mutation that may sequence or publish a new running config.
    Write,
    /// A read that must be fenced before serving a local projection.
    LinearizableRead,
}

/// Exact transaction/version head represented by the local config projection.
///
/// Authority adapters compare this metadata with their canonical state machine
/// before admitting a management request. The config payload is deliberately
/// absent, so proving freshness never crosses the plaintext boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigProjectionHead {
    tx_id: Option<TxId>,
    version: ConfigVersion,
}

impl ConfigProjectionHead {
    /// Builds a projection head from one atomic config-bus snapshot.
    pub const fn new(tx_id: Option<TxId>, version: ConfigVersion) -> Self {
        Self { tx_id, version }
    }

    /// Returns the transaction that produced the projection, or `None` for an
    /// unpersisted bootstrap projection.
    pub const fn tx_id(self) -> Option<TxId> {
        self.tx_id
    }

    /// Returns the projected running-config version.
    pub const fn version(self) -> ConfigVersion {
        self.version
    }
}

/// Validated, bounded routing hint for the current config leader.
///
/// The value is deliberately opaque to the SDK. A product may use a consensus
/// node ID, a logical member name, or a management endpoint. Only printable
/// ASCII without whitespace is accepted so the same value can be transported
/// safely in gRPC metadata and NETCONF XML after protocol escaping.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ConfigLeaderHint(String);

impl ConfigLeaderHint {
    /// Validates and stores an opaque leader-routing hint.
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigLeaderHintError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CONFIG_LEADER_HINT_BYTES
            || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(ConfigLeaderHintError);
        }
        Ok(Self(value))
    }

    /// Returns the validated routing value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ConfigLeaderHint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigLeaderHint")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Invalid leader-routing hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid config leader hint")]
pub struct ConfigLeaderHintError;

/// Result of consulting the config writer-of-record authority.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigAuthorityOutcome {
    /// The local process may serve or apply the requested operation.
    LocalAuthority,
    /// Another node is authoritative; the optional hint may be returned to the
    /// client for a bounded retry.
    Retry {
        /// Validated opaque routing hint for the current leader, when known.
        leader_hint: Option<ConfigLeaderHint>,
    },
    /// Authority or exact projection freshness could not be proven. Callers
    /// must fail closed.
    Unavailable,
}

/// Result of one authoritative in-place projection rebuild.
///
/// The worker keeps this payload-free metadata private to its control path;
/// it uses the deadline to replace its existing commit-confirmed expiry timer
/// only after the authority owner has completed its final proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigProjectionPublication {
    head: ConfigProjectionHead,
    pending_confirmed_deadline: Option<Timestamp>,
}

impl ConfigProjectionPublication {
    /// Builds publication metadata for an already rebuilt live projection.
    pub const fn new(
        head: ConfigProjectionHead,
        pending_confirmed_deadline: Option<Timestamp>,
    ) -> Self {
        Self {
            head,
            pending_confirmed_deadline,
        }
    }

    /// Returns the exact transaction/version head now in the live slot.
    pub const fn head(self) -> ConfigProjectionHead {
        self.head
    }

    /// Returns the recovered confirmed-commit expiry deadline, if one exists.
    pub const fn pending_confirmed_deadline(self) -> Option<Timestamp> {
        self.pending_confirmed_deadline
    }
}

/// Worker-owned operation that rebuilds and atomically publishes one live
/// authoritative projection.
///
/// Only an authority port invokes this callback. Keeping it boxed and owned by
/// the config-bus worker prevents an external caller cancellation from
/// detaching publication from the store-owned leader-open admission guard.
#[async_trait]
pub trait ConfigProjectionRebuilder: Send {
    /// Rebuilds from the locally applied committed source and publishes only
    /// when that source exactly matches `expected`.
    async fn rebuild(
        self: Box<Self>,
        expected: ConfigProjectionHead,
    ) -> Result<ConfigProjectionPublication, crate::StoreError>;
}

/// Injected writer-of-record gate shared by management protocol servers.
///
/// Consensus consumers adapt their engine-owned linearizability outcome to
/// this port. Implementations must return [`ConfigAuthorityOutcome::Unavailable`]
/// whenever local authority cannot be proven; protocol servers never fall back
/// to their local snapshot after such a result. Implementations that own a
/// canonical state machine must also reject a projection head that does not
/// exactly match that state machine's durable head.
#[async_trait]
pub trait ConfigAuthorityPort: Send + Sync {
    /// Determines whether this process may perform `operation` against the
    /// supplied local projection now.
    async fn ensure_local_authority(
        &self,
        operation: ConfigAuthorityOperation,
        projection: ConfigProjectionHead,
    ) -> ConfigAuthorityOutcome;

    /// Runs a worker-owned live-projection rebuild while this port retains its
    /// own local-authority proof through publication and final verification.
    ///
    /// Implementations that cannot provide a cancellation-safe held proof
    /// leave the default fail-closed result in place. This additive method
    /// preserves existing mutation-only authority ports.
    async fn reconcile_local_projection(
        &self,
        _rebuild: Box<dyn ConfigProjectionRebuilder>,
    ) -> Result<ConfigProjectionPublication, ConfigAuthorityOutcome> {
        Err(ConfigAuthorityOutcome::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leader_hints_are_bounded_and_metadata_safe() {
        let hint = ConfigLeaderHint::new("config-0.example.test:57400").expect("valid hint");
        assert_eq!(hint.as_str(), "config-0.example.test:57400");
        assert!(ConfigLeaderHint::new("").is_err());
        assert!(ConfigLeaderHint::new("contains space").is_err());
        assert!(ConfigLeaderHint::new("x".repeat(MAX_CONFIG_LEADER_HINT_BYTES + 1)).is_err());
    }

    #[test]
    fn leader_hint_debug_does_not_disclose_routing_value() {
        let hint = ConfigLeaderHint::new("secret-peer.example.test:57400").expect("valid hint");
        let debug = format!("{hint:?}");
        assert!(!debug.contains("secret-peer"));
        assert!(debug.contains("bytes"));
    }
}
