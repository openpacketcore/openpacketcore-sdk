//! Fail-closed mTLS bootstrap for the OpenPacketCore management plane.
//!
//! `opc-tls`'s `TlsConfigBuilder` builds a SPIFFE mTLS server config but ships an
//! allow-all `PeerPolicy::default()` and sets no ALPN — correct library defaults,
//! wrong production defaults. [`TlsBootstrap`] is the management-plane gate that
//! makes the production posture explicit: in a fail-closed [`RuntimeMode`]
//! (`Production`/`Conformance`) it refuses to build a server config from an
//! unconstrained peer policy, and it always stamps the caller's ALPN set on the
//! result after validating that each ALPN protocol id is non-empty and within
//! the TLS wire limit. [`ensure_plaintext_permitted`] allows plaintext only in
//! `Dev` or an explicit `Lab` profile, so `Perf` does not become a plaintext
//! management mode just because it is not runtime fail-closed.
//!
//! Chain verification and SVID handling remain in `opc-tls`/rustls; this crate
//! only enforces management-plane policy and wiring.

#![forbid(unsafe_code)]

use opc_identity::IdentityState;
use opc_runtime::RuntimeMode;
use opc_tls::{PeerPolicy, ServerConfig, TlsConfigBuilder};
use thiserror::Error;
use tokio::sync::watch;

/// ALPN protocol id for HTTP/2 (gNMI/gRPC).
pub const ALPN_H2: &[u8] = b"h2";

const MAX_ALPN_PROTOCOL_LEN: usize = 255;

/// A transport bootstrap failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransportError {
    /// The peer policy authorizes any trusted peer, which is forbidden in a
    /// fail-closed runtime mode.
    #[error("unconstrained peer policy is not allowed in {mode:?} mode")]
    UnconstrainedPeerPolicy {
        /// The runtime mode that rejected the policy.
        mode: RuntimeMode,
    },
    /// A plaintext listener was requested in a runtime mode that disallows it.
    #[error("plaintext transport is not allowed in {mode:?} mode")]
    PlaintextForbidden {
        /// The runtime mode that rejected plaintext.
        mode: RuntimeMode,
    },
    /// An ALPN protocol id was empty or too long for TLS ALPN.
    #[error("invalid ALPN protocol id")]
    InvalidAlpnProtocol,
    /// `opc-tls` failed to build the rustls server config.
    #[error("TLS configuration error: {0}")]
    Tls(String),
}

/// Builder for a management-plane mTLS server config with fail-closed policy
/// enforcement.
#[derive(Clone)]
pub struct TlsBootstrap {
    mode: RuntimeMode,
    peer_policy: PeerPolicy,
    alpn_protocols: Vec<Vec<u8>>,
    compat_tls12: bool,
}

impl TlsBootstrap {
    /// Starts a bootstrap for the given runtime mode and peer policy. ALPN is
    /// empty and TLS 1.2 compatibility is off until set.
    pub fn new(mode: RuntimeMode, peer_policy: PeerPolicy) -> Self {
        Self {
            mode,
            peer_policy,
            alpn_protocols: Vec::new(),
            compat_tls12: false,
        }
    }

    /// Sets the ALPN protocol set stamped on the built config (e.g. `[ALPN_H2]`
    /// for gNMI). NETCONF over TLS may leave this empty.
    pub fn with_alpn(mut self, protocols: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.alpn_protocols = protocols.into_iter().collect();
        self
    }

    /// Enables TLS 1.2 alongside TLS 1.3. This is the explicit compatibility
    /// opt-in the spec requires; the default (off) is TLS 1.3 only.
    pub fn with_tls12_compat(mut self, enabled: bool) -> Self {
        self.compat_tls12 = enabled;
        self
    }

    /// Builds the mTLS `ServerConfig` from a hot-reloading SVID watch, enforcing
    /// the fail-closed policy. Returns [`TransportError::UnconstrainedPeerPolicy`]
    /// in a fail-closed mode when the policy authorizes any trusted peer.
    pub fn build_server_config(
        self,
        identity: watch::Receiver<Option<IdentityState>>,
    ) -> Result<ServerConfig, TransportError> {
        if self.mode.fail_closed() && self.peer_policy.is_unconstrained() {
            return Err(TransportError::UnconstrainedPeerPolicy { mode: self.mode });
        }
        validate_alpn_protocols(&self.alpn_protocols)?;

        let mut config = TlsConfigBuilder::new(identity)
            .with_policy(self.peer_policy)
            .with_compat_mode(self.compat_tls12)
            .build_server_config()
            .map_err(|err| TransportError::Tls(err.to_string()))?;

        config.alpn_protocols = self.alpn_protocols;
        Ok(config)
    }
}

fn validate_alpn_protocols(protocols: &[Vec<u8>]) -> Result<(), TransportError> {
    if protocols
        .iter()
        .any(|protocol| protocol.is_empty() || protocol.len() > MAX_ALPN_PROTOCOL_LEN)
    {
        Err(TransportError::InvalidAlpnProtocol)
    } else {
        Ok(())
    }
}

/// Returns whether a plaintext listener may be bound in this runtime mode.
/// Plaintext is permitted only for local development or an explicit lab profile.
pub fn plaintext_permitted(mode: RuntimeMode) -> bool {
    matches!(mode, RuntimeMode::Dev | RuntimeMode::Lab)
}

/// Fails if a plaintext listener is requested outside development or an explicit
/// lab profile. Call this before binding any plaintext management listener so it
/// cannot be selected by accident in production/conformance/perf runs.
pub fn ensure_plaintext_permitted(mode: RuntimeMode) -> Result<(), TransportError> {
    if plaintext_permitted(mode) {
        Ok(())
    } else {
        Err(TransportError::PlaintextForbidden { mode })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_identity::{IdentityState, TrustDomain};
    use opc_tls::PeerPolicy;
    use std::collections::HashSet;

    fn no_identity() -> watch::Receiver<Option<IdentityState>> {
        let (_tx, rx) = watch::channel(None);
        rx
    }

    fn constrained_policy() -> PeerPolicy {
        PeerPolicy {
            allowed_trust_domains: Some(HashSet::from([
                TrustDomain::new("example.org").expect("trust domain")
            ])),
            ..Default::default()
        }
    }

    #[test]
    fn production_rejects_unconstrained_peer_policy() {
        let result = TlsBootstrap::new(RuntimeMode::Production, PeerPolicy::default())
            .build_server_config(no_identity());
        assert_eq!(
            result.err(),
            Some(TransportError::UnconstrainedPeerPolicy {
                mode: RuntimeMode::Production
            })
        );
    }

    #[test]
    fn conformance_also_rejects_unconstrained_peer_policy() {
        let result = TlsBootstrap::new(RuntimeMode::Conformance, PeerPolicy::default())
            .build_server_config(no_identity());
        assert!(matches!(
            result,
            Err(TransportError::UnconstrainedPeerPolicy { .. })
        ));
    }

    #[test]
    fn production_with_constrained_policy_builds_and_sets_alpn() {
        let config = TlsBootstrap::new(RuntimeMode::Production, constrained_policy())
            .with_alpn([ALPN_H2.to_vec()])
            .build_server_config(no_identity())
            .expect("server config");
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn alpn_is_empty_unless_caller_sets_it() {
        let config = TlsBootstrap::new(RuntimeMode::Production, constrained_policy())
            .build_server_config(no_identity())
            .expect("server config");
        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    fn rejects_invalid_alpn_protocol_ids() {
        let empty = TlsBootstrap::new(RuntimeMode::Production, constrained_policy())
            .with_alpn([Vec::new()])
            .build_server_config(no_identity());
        assert_eq!(empty.err(), Some(TransportError::InvalidAlpnProtocol));

        let oversized = TlsBootstrap::new(RuntimeMode::Production, constrained_policy())
            .with_alpn([vec![b'a'; MAX_ALPN_PROTOCOL_LEN + 1]])
            .build_server_config(no_identity());
        assert_eq!(oversized.err(), Some(TransportError::InvalidAlpnProtocol));
    }

    #[test]
    fn tls12_compat_is_explicit_but_not_rejected_in_fail_closed_mode() {
        let config = TlsBootstrap::new(RuntimeMode::Production, constrained_policy())
            .with_tls12_compat(true)
            .build_server_config(no_identity());
        assert!(config.is_ok());
    }

    #[test]
    fn dev_permits_unconstrained_policy() {
        // Low-level convenience for labs: unconstrained is allowed outside
        // fail-closed modes.
        let config = TlsBootstrap::new(RuntimeMode::Dev, PeerPolicy::default())
            .build_server_config(no_identity());
        assert!(config.is_ok());
    }

    #[test]
    fn plaintext_guard_matches_runtime_mode() {
        assert!(!plaintext_permitted(RuntimeMode::Production));
        assert!(!plaintext_permitted(RuntimeMode::Conformance));
        assert!(plaintext_permitted(RuntimeMode::Dev));
        assert!(plaintext_permitted(RuntimeMode::Lab));
        assert!(!plaintext_permitted(RuntimeMode::Perf));

        assert_eq!(
            ensure_plaintext_permitted(RuntimeMode::Production),
            Err(TransportError::PlaintextForbidden {
                mode: RuntimeMode::Production
            })
        );
        assert!(ensure_plaintext_permitted(RuntimeMode::Dev).is_ok());
        assert_eq!(
            ensure_plaintext_permitted(RuntimeMode::Perf),
            Err(TransportError::PlaintextForbidden {
                mode: RuntimeMode::Perf
            })
        );
    }
}
