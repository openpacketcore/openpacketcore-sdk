//! Exclusive bounded engine lifetime for one admitted backend connection.

use std::sync::{Arc, Mutex, Weak};

use super::{BackendConnection, SqliteBackend};
use crate::consensus::ConfigConsensusStorageError;

#[derive(Default)]
pub(super) struct ConfigEngineAdmission {
    current: Mutex<Weak<ConfigEngineClaim>>,
}

// The claim retains the connection, including retained-file admission. The
// connection does not point back to this claim, and admission holds only Weak.
// Pools and detached workers can therefore extend the lifetime without a cycle.
pub(crate) struct ConfigEngineClaim {
    _connection: Arc<tokio::sync::Mutex<BackendConnection>>,
}

impl std::fmt::Debug for ConfigEngineClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfigEngineClaim(<redacted>)")
    }
}

impl ConfigEngineAdmission {
    fn try_claim(
        &self,
        connection: Arc<tokio::sync::Mutex<BackendConnection>>,
    ) -> Result<Arc<ConfigEngineClaim>, ConfigConsensusStorageError> {
        let mut current = self
            .current
            .lock()
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        if current.upgrade().is_some() {
            return Err(ConfigConsensusStorageError::BackendUnavailable);
        }
        let claim = Arc::new(ConfigEngineClaim {
            _connection: connection,
        });
        *current = Arc::downgrade(&claim);
        Ok(claim)
    }
}

impl SqliteBackend {
    /// Claim a new engine before startup. Cloning an admitted backend carries
    /// its existing ownership but never grants permission for another engine.
    /// Legacy opens preserve their existing construction behavior.
    pub(crate) fn claim_config_consensus_engine(
        mut self,
    ) -> Result<Self, ConfigConsensusStorageError> {
        if self.retained_binding.as_ref().is_some_and(|binding| {
            binding.capacity_profile() == opc_crypto::ConfigCapacityProfile::BoundedV1
        }) {
            self.config_consensus_engine_claim = Some(
                self.config_consensus_engine_admission
                    .try_claim(self.conn())?,
            );
        }
        Ok(self)
    }

    pub(crate) fn config_consensus_engine_claim(&self) -> Option<Arc<ConfigEngineClaim>> {
        self.config_consensus_engine_claim.clone()
    }
}

#[cfg(all(test, target_os = "linux"))]
impl SqliteBackend {
    // The existing before-commit initializer hook belongs to Legacy schema
    // creation. This white-box fixture installs the same real claim there so
    // cancellation can observe the detached initializer's backend ownership.
    pub(crate) fn claim_config_engine_for_initialization_control(
        mut self,
    ) -> Result<Self, ConfigConsensusStorageError> {
        self.config_consensus_engine_claim = Some(
            self.config_consensus_engine_admission
                .try_claim(self.conn())?,
        );
        Ok(self)
    }
}
