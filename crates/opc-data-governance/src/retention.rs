use crate::DataClass;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Disposal/deletion actions for data classification lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DisposalAction {
    Purge,
    Anonymize,
    Archive,
    ImmediateDisposal,
}

/// A policy defining the retention guidelines for a specific data class.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub data_class: DataClass,
    pub retention_duration: Option<Duration>,
    pub legal_hold: bool,
    pub disposal_action: DisposalAction,
    pub policy_source_id: Option<String>,
    pub tenant_id: Option<String>,
}

/// Error type for retention policy validation, with redacted/non-leaking error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyError {
    InvalidDuration,
    MissingPolicySource,
    LegalHoldBlocked,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDuration => write!(
                f,
                "Policy error: duration cannot be zero or negative unless disposal is immediate"
            ),
            Self::MissingPolicySource => write!(
                f,
                "Policy error: production policy requires a valid policy source or evidence ID"
            ),
            Self::LegalHoldBlocked => write!(
                f,
                "Policy error: operation blocked due to active legal hold"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

impl RetentionPolicy {
    /// Validates the retention policy rules.
    pub fn validate(&self, is_production: bool) -> Result<(), PolicyError> {
        // retained classes require a non-zero duration unless disposal is immediate.
        if self.disposal_action != DisposalAction::ImmediateDisposal {
            match self.retention_duration {
                Some(dur) if !dur.is_zero() => {}
                _ => return Err(PolicyError::InvalidDuration),
            }
        }

        // legal hold prevents purge/export deletion decisions;
        if self.legal_hold
            && matches!(
                self.disposal_action,
                DisposalAction::Purge | DisposalAction::ImmediateDisposal
            )
        {
            return Err(PolicyError::LegalHoldBlocked);
        }

        // production policies require an evidence or policy source ID;
        if is_production
            && match self.policy_source_id.as_ref() {
                Some(source) => source.trim().is_empty(),
                None => true,
            }
        {
            return Err(PolicyError::MissingPolicySource);
        }

        Ok(())
    }

    /// Checks if a deletion decision can be made under this policy.
    pub fn can_delete(&self) -> bool {
        !self.legal_hold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DataClass;

    #[test]
    fn test_valid_policy() {
        let p = RetentionPolicy {
            data_class: DataClass::SubscriberId,
            retention_duration: Some(Duration::from_secs(3600)),
            legal_hold: false,
            disposal_action: DisposalAction::Purge,
            policy_source_id: Some("policy-123".to_string()),
            tenant_id: Some("tenant-a".to_string()),
        };
        assert!(p.validate(true).is_ok());
        assert!(p.can_delete());
    }

    #[test]
    fn test_invalid_duration() {
        let p = RetentionPolicy {
            data_class: DataClass::SubscriberId,
            retention_duration: Some(Duration::from_secs(0)),
            legal_hold: false,
            disposal_action: DisposalAction::Purge,
            policy_source_id: Some("policy-123".to_string()),
            tenant_id: Some("tenant-a".to_string()),
        };
        assert_eq!(p.validate(true), Err(PolicyError::InvalidDuration));
    }

    #[test]
    fn test_immediate_disposal_zero_duration() {
        let p = RetentionPolicy {
            data_class: DataClass::SubscriberId,
            retention_duration: Some(Duration::from_secs(0)),
            legal_hold: false,
            disposal_action: DisposalAction::ImmediateDisposal,
            policy_source_id: Some("policy-123".to_string()),
            tenant_id: Some("tenant-a".to_string()),
        };
        assert!(p.validate(true).is_ok());
    }

    #[test]
    fn test_retained_policy_requires_duration() {
        let p = RetentionPolicy {
            data_class: DataClass::SubscriberId,
            retention_duration: None,
            legal_hold: false,
            disposal_action: DisposalAction::Purge,
            policy_source_id: Some("policy-123".to_string()),
            tenant_id: Some("tenant-a".to_string()),
        };
        assert_eq!(p.validate(true), Err(PolicyError::InvalidDuration));
    }

    #[test]
    fn test_legal_hold_blocks_disposal() {
        let p = RetentionPolicy {
            data_class: DataClass::SubscriberId,
            retention_duration: Some(Duration::from_secs(3600)),
            legal_hold: true,
            disposal_action: DisposalAction::Purge,
            policy_source_id: Some("policy-123".to_string()),
            tenant_id: Some("tenant-a".to_string()),
        };
        assert_eq!(p.validate(true), Err(PolicyError::LegalHoldBlocked));
        assert!(!p.can_delete());
    }

    #[test]
    fn test_missing_source_id_in_production() {
        let p = RetentionPolicy {
            data_class: DataClass::SubscriberId,
            retention_duration: Some(Duration::from_secs(3600)),
            legal_hold: false,
            disposal_action: DisposalAction::Purge,
            policy_source_id: None,
            tenant_id: Some("tenant-a".to_string()),
        };
        assert_eq!(p.validate(true), Err(PolicyError::MissingPolicySource));
        assert!(p.validate(false).is_ok());

        let mut blank = p;
        blank.policy_source_id = Some("   ".to_string());
        assert_eq!(blank.validate(true), Err(PolicyError::MissingPolicySource));
    }
}
