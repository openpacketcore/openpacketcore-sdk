//! Required management-audit composition at the encrypted configuration boundary.
use std::{fmt, sync::Arc, time::Duration};

use opc_config_bus::{CommitWrite, SealedConfig, StoreError};
use opc_config_model::{ConfigOperation, OpcConfig, TransportType};
use opc_persist::audit_authority::{
    AuditAdmission, AuditCaller, AuditOperationState, AuditPrivacyProjection,
};
use opc_persist::{
    ConsensusConfigStore, ManagementAuditEventRecord, ManagementAuditInstant,
    ManagementAuditOperationCode, ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode,
    ManagementAuditTransportCode,
};

/// Explicit required audit policy for the existing configuration authority.
///
/// The projection provider must match the already provisioned ledger. This
/// policy cannot activate, reset, or bypass that ledger. `lifetime` bounds a
/// single admitted operation; it does not extend ConfigBus request deadlines.
#[derive(Clone)]
pub struct ConfigAuditPolicy {
    privacy: Arc<dyn AuditPrivacyProjection>,
    lifetime: Duration,
}

impl ConfigAuditPolicy {
    /// Select a purpose-separated privacy provider and fixed operation lifetime
    /// of 1 through 3600 whole seconds. There is no implicit key or fallback.
    pub fn new(
        privacy: Arc<dyn AuditPrivacyProjection>,
        lifetime: Duration,
    ) -> Result<Self, StoreError> {
        if lifetime.subsec_nanos() != 0 || !(1..=3600).contains(&lifetime.as_secs()) {
            return Err(StoreError::internal("invalid audit operation lifetime"));
        }
        Ok(Self { privacy, lifetime })
    }

    pub(super) async fn append<C: OpcConfig>(
        &self,
        store: &ConsensusConfigStore,
        commit: CommitWrite<SealedConfig<C>>,
    ) -> Result<(), StoreError> {
        let context = commit.audit_context().ok_or_else(|| {
            StoreError::internal("required configuration audit context unavailable")
        })?;
        let record = commit.record();
        let version = record.version.get();
        let principal = opc_mgmt_audit::principal_descriptor(&record.principal);
        let caller = AuditCaller::project(
            self.privacy.as_ref(),
            record.principal.tenant.as_str(),
            &principal,
        )
        .map_err(|_| StoreError::unavailable("configuration audit projection unavailable"))?;
        let instant = record.committed_at.as_offset_datetime();
        let occurred_at = ManagementAuditInstant::try_new(
            instant.unix_timestamp(),
            instant.nanosecond(),
            0,
            ManagementAuditTimeSourceCode::NodeClock,
        )
        .map_err(|_| StoreError::internal("invalid configuration audit timestamp"))?;
        let transport = match context.transport() {
            TransportType::Gnmi => ManagementAuditTransportCode::Gnmi,
            TransportType::NetconfSsh => ManagementAuditTransportCode::NetconfSsh,
            TransportType::NetconfTls => ManagementAuditTransportCode::NetconfTls,
            TransportType::RestconfHttps => ManagementAuditTransportCode::RestconfHttps,
            TransportType::Internal => ManagementAuditTransportCode::Internal,
        };
        let operation = match context.operation() {
            ConfigOperation::Replace => ManagementAuditOperationCode::Replace,
            ConfigOperation::Patch => ManagementAuditOperationCode::Update,
            ConfigOperation::Delete => ManagementAuditOperationCode::Delete,
            ConfigOperation::Rollback => ManagementAuditOperationCode::Rollback,
        };
        // This is the complete configuration commit boundary. Exact private
        // paths/mode/candidate remain in the authenticated encrypted payload;
        // do not parse instance paths or retain plaintext replay metadata here.
        let event = ManagementAuditEventRecord::try_new(
            *context.request_id().as_uuid().as_bytes(),
            occurred_at,
            record.principal.tenant.as_str(),
            principal,
            transport,
            operation,
            ManagementAuditOutcomeCode::Intent,
            None::<&str>,
            std::iter::empty::<&str>(),
            Some(record.tx_id.to_string()),
        )
        .map_err(|_| StoreError::internal("invalid configuration audit context"))?;
        let commit = super::attested_bus_commit(commit)?;
        let prepared = store
            .prepare_audited_commit(self.privacy.as_ref(), &event, commit, self.lifetime)
            .map_err(|_| StoreError::unavailable("configuration audit preparation refused"))?;
        // No mutation is submitted for Unknown admission. The durable Intent
        // remains discoverable by the bounded recovery pass and expires at its
        // original fixed deadline. It is never replayed with a new handle.
        let admitted = match store
            .admit_audit_operation_local(prepared.handle(), caller)
            .await
        {
            AuditAdmission::Applied(receipt) if receipt.state() == AuditOperationState::Intent => {
                receipt
            }
            AuditAdmission::Unknown(_) => {
                return Err(StoreError::outcome_unknown(
                    "configuration audit admission unknown",
                ))
            }
            _ => {
                return Err(StoreError::unavailable(
                    "required configuration audit intent refused",
                ))
            }
        };
        match store
            .submit_audited_mutation_local(&prepared, &admitted, caller)
            .await
        {
            AuditAdmission::Applied(receipt) => match receipt.state() {
                AuditOperationState::Committed { version: committed } if committed == version => {
                    // Outcome and reserved terminal obligation are already in
                    // the same durable transaction as the encrypted config.
                    // Recovery finishes that obligation; no second write/read
                    // can turn this known result into an ordinary failure.
                    Ok(())
                }
                AuditOperationState::Rejected => Err(StoreError::unavailable(
                    "audited configuration mutation refused",
                )),
                _ => Err(StoreError::outcome_unknown(
                    "audited configuration result unresolved",
                )),
            },
            AuditAdmission::Rejected(_) => Err(StoreError::unavailable(
                "audited configuration mutation refused",
            )),
            AuditAdmission::Unknown(_) => Err(StoreError::outcome_unknown(
                "audited configuration result unknown",
            )),
        }
    }
}

impl fmt::Debug for ConfigAuditPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigAuditPolicy(<redacted>)")
    }
}
