//! Authenticated point-in-time receipt returned by the committing state machine.

use serde::{Deserialize, Serialize};

use super::ledger::{authenticate, verify};
use super::{
    AuditAuthorityError, AuditCaller, AuditOperationHandle, AuditOperationReceipt,
    AuditOperationState,
};
use crate::{AuditKey, ConfigConsensusIdentity};

const RECEIPT_DOMAIN: &[u8] = b"openpacketcore/management-audit/applied-receipt/v1\0";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptBody {
    identity: ConfigConsensusIdentity,
    operation: [u8; 32],
    state: AuditOperationState,
    terminal_recorded: bool,
    sequence: u64,
}

/// Internal wire/storage representation only. Public receipts remain neither
/// constructible nor deserializable by a caller. A known quorum-applied outcome
/// does not depend on a later successful quorum or checkpoint lookup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthenticatedAuditReceipt {
    body: ReceiptBody,
    mac: [u8; 32],
}

impl std::fmt::Debug for AuthenticatedAuditReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticatedAuditReceipt(<redacted>)")
    }
}

impl AuthenticatedAuditReceipt {
    pub(crate) fn seal(
        key: &AuditKey,
        receipt: &AuditOperationReceipt,
    ) -> Result<Self, AuditAuthorityError> {
        receipt.state.validate_target_for(&receipt.handle)?;
        let body = ReceiptBody {
            identity: receipt.handle.body.identity,
            operation: receipt.handle.mac,
            state: receipt.state,
            terminal_recorded: receipt.terminal_recorded,
            sequence: receipt.sequence,
        };
        let mac = authenticate(key, RECEIPT_DOMAIN, &body)?;
        Ok(Self { body, mac })
    }

    pub(crate) fn read_back(
        &self,
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> Result<AuditOperationReceipt, AuditAuthorityError> {
        handle.verify(key, identity, caller)?;
        if self.body.identity != identity
            || self.body.operation != handle.mac
            || self.body.sequence == 0
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        verify(key, RECEIPT_DOMAIN, &self.body, &self.mac)?;
        self.body.state.validate_target_for(handle)?;
        Ok(AuditOperationReceipt {
            handle: handle.clone(),
            state: self.body.state,
            terminal_recorded: self.body.terminal_recorded,
            sequence: self.body.sequence,
        })
    }
}
