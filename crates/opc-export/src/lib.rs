//! Safe export and backup metadata model contracts for OpenPacketCore SDK.

#![forbid(unsafe_code)]

use opc_data_governance::{DataClass, RetentionPolicy};
use opc_redaction::RedactionLevel;
use serde::{Deserialize, Serialize};

/// Payload states describing the privacy treatment of the exported payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayloadState {
    Raw,
    Redacted,
    Encrypted,
    DigestOnly,
}

/// Metadata describing the classification and policies tied to the exported payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportMetadata {
    pub data_class: DataClass,
    pub redaction_level: RedactionLevel,
    pub retention_policy: RetentionPolicy,
    pub tenant_id: String,
    pub schema_version: String,
    pub payload_state: PayloadState,
}

/// An individual item packaged for export or backup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportedItem {
    pub metadata: ExportMetadata,
    pub payload: Vec<u8>,
}

/// Validation errors for the export contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportError {
    MissingMetadata,
    DataClassMismatch,
    RetentionPolicyInvalid,
    TenantMismatch,
    RawSensitiveExportRejected,
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingMetadata => write!(
                f,
                "Export validation error: required export metadata is missing"
            ),
            Self::DataClassMismatch => write!(
                f,
                "Export validation error: retention policy data class does not match export metadata"
            ),
            Self::RetentionPolicyInvalid => {
                write!(f, "Export validation error: retention policy is invalid")
            }
            Self::TenantMismatch => write!(
                f,
                "Export validation error: retention policy tenant does not match export metadata"
            ),
            Self::RawSensitiveExportRejected => write!(
                f,
                "Export validation error: raw sensitive payload export rejected in production without encryption"
            ),
        }
    }
}

impl std::error::Error for ExportError {}

impl ExportedItem {
    /// Validates the exported item before serialization in the target mode.
    pub fn validate_for_export(&self, is_production: bool) -> Result<(), ExportError> {
        if self.metadata.tenant_id.trim().is_empty()
            || self.metadata.schema_version.trim().is_empty()
            || self.payload.is_empty()
        {
            return Err(ExportError::MissingMetadata);
        }

        if self.metadata.retention_policy.data_class != self.metadata.data_class {
            return Err(ExportError::DataClassMismatch);
        }

        if let Some(policy_tenant) = &self.metadata.retention_policy.tenant_id {
            if policy_tenant != &self.metadata.tenant_id {
                return Err(ExportError::TenantMismatch);
            }
        }

        self.metadata
            .retention_policy
            .validate(is_production)
            .map_err(|_| ExportError::RetentionPolicyInvalid)?;

        if is_production && self.metadata.payload_state == PayloadState::Raw {
            let sensitive = !matches!(
                self.metadata.data_class,
                DataClass::Public | DataClass::Operational
            );
            if sensitive {
                return Err(ExportError::RawSensitiveExportRejected);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_data_governance::DisposalAction;
    use std::time::Duration;

    #[test]
    fn test_round_trip_serialization() {
        let policy = RetentionPolicy {
            data_class: DataClass::SubscriberId,
            retention_duration: Some(Duration::from_secs(3600)),
            legal_hold: false,
            disposal_action: DisposalAction::Purge,
            policy_source_id: Some("src-1".to_string()),
            tenant_id: Some("tenant-1".to_string()),
        };
        let metadata = ExportMetadata {
            data_class: DataClass::SubscriberId,
            redaction_level: RedactionLevel::Mask,
            retention_policy: policy,
            tenant_id: "tenant-1".to_string(),
            schema_version: "1.0.0".to_string(),
            payload_state: PayloadState::Redacted,
        };
        let item = ExportedItem {
            metadata,
            payload: b"redacted-payload".to_vec(),
        };

        let serialized = serde_json::to_string(&item).unwrap();
        let deserialized: ExportedItem = serde_json::from_str(&serialized).unwrap();
        assert_eq!(item, deserialized);
    }

    #[test]
    fn test_production_rejects_raw_sensitive() {
        let policy = RetentionPolicy {
            data_class: DataClass::SubscriberId,
            retention_duration: Some(Duration::from_secs(3600)),
            legal_hold: false,
            disposal_action: DisposalAction::Purge,
            policy_source_id: Some("src-1".to_string()),
            tenant_id: Some("tenant-1".to_string()),
        };
        let metadata = ExportMetadata {
            data_class: DataClass::SubscriberId,
            redaction_level: RedactionLevel::Cleartext,
            retention_policy: policy,
            tenant_id: "tenant-1".to_string(),
            schema_version: "1.0.0".to_string(),
            payload_state: PayloadState::Raw,
        };
        let item = ExportedItem {
            metadata,
            payload: b"raw-sensitive-data".to_vec(),
        };

        // Rejects raw sensitive in production
        assert_eq!(
            item.validate_for_export(true),
            Err(ExportError::RawSensitiveExportRejected)
        );

        // Allows raw sensitive in dev mode
        assert!(item.validate_for_export(false).is_ok());

        // Allows encrypted sensitive in production
        let mut encrypted_item = item.clone();
        encrypted_item.metadata.payload_state = PayloadState::Encrypted;
        assert!(encrypted_item.validate_for_export(true).is_ok());

        // Allows raw public in production
        let mut public_item = item.clone();
        public_item.metadata.data_class = DataClass::Public;
        public_item.metadata.retention_policy.data_class = DataClass::Public;
        assert!(public_item.validate_for_export(true).is_ok());
    }

    #[test]
    fn test_export_metadata_consistency_validation() {
        let policy = RetentionPolicy {
            data_class: DataClass::SubscriberId,
            retention_duration: Some(Duration::from_secs(3600)),
            legal_hold: false,
            disposal_action: DisposalAction::Purge,
            policy_source_id: Some("src-1".to_string()),
            tenant_id: Some("tenant-1".to_string()),
        };
        let mut item = ExportedItem {
            metadata: ExportMetadata {
                data_class: DataClass::SubscriberId,
                redaction_level: RedactionLevel::Mask,
                retention_policy: policy,
                tenant_id: "tenant-1".to_string(),
                schema_version: "1.0.0".to_string(),
                payload_state: PayloadState::Redacted,
            },
            payload: b"redacted-payload".to_vec(),
        };

        item.metadata.retention_policy.data_class = DataClass::Operational;
        assert_eq!(
            item.validate_for_export(true),
            Err(ExportError::DataClassMismatch)
        );

        item.metadata.retention_policy.data_class = DataClass::SubscriberId;
        item.metadata.retention_policy.tenant_id = Some("tenant-2".to_string());
        assert_eq!(
            item.validate_for_export(true),
            Err(ExportError::TenantMismatch)
        );

        item.metadata.retention_policy.tenant_id = Some("tenant-1".to_string());
        item.metadata.retention_policy.policy_source_id = Some("   ".to_string());
        assert_eq!(
            item.validate_for_export(true),
            Err(ExportError::RetentionPolicyInvalid)
        );
    }
}
