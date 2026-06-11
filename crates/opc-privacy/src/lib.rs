//! Privacy minimization and k-anonymity utilities for OpenPacketCore analytics exports.

#![forbid(unsafe_code)]

use opc_data_governance::{DataClass, IdentifierType};
use serde::{Deserialize, Serialize};

/// Privacy minimization policy defining the k-anonymity constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MinimizationPolicy {
    pub policy_id: String,
    pub min_cohort_size: usize,
    pub enforce_k_anonymity: bool,
    pub allowed_classes: Vec<DataClass>,
}

/// A cohort or group record representing aggregated analytics statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CohortRecord {
    pub keys: Vec<String>,
    pub count: usize,
}

/// Validation errors during minimization evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MinimizationError {
    InvalidPolicy,
    InvalidBinSize,
    CohortTooSmall(usize, usize),
    DirectIdentifierNotAllowed(DataClass),
    ClassNotAllowed(DataClass),
}

impl std::fmt::Display for MinimizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPolicy => write!(f, "Minimization error: analytics policy is invalid"),
            Self::InvalidBinSize => write!(
                f,
                "Minimization error: aggregate bin size must be greater than zero"
            ),
            Self::CohortTooSmall(size, threshold) => write!(
                f,
                "Minimization error: cohort size {} is below k-anonymity threshold {}",
                size, threshold
            ),
            Self::DirectIdentifierNotAllowed(class) => write!(
                f,
                "Minimization error: direct identifier class '{}' is not allowed in analytics",
                class
            ),
            Self::ClassNotAllowed(class) => write!(
                f,
                "Minimization error: class '{}' is not permitted by current analytics policy",
                class
            ),
        }
    }
}

impl std::error::Error for MinimizationError {}

impl MinimizationPolicy {
    /// Validates policy structure before use in production analytics exports.
    pub fn validate(&self) -> Result<(), MinimizationError> {
        if self.policy_id.trim().is_empty() {
            return Err(MinimizationError::InvalidPolicy);
        }
        if self.enforce_k_anonymity && self.min_cohort_size == 0 {
            return Err(MinimizationError::InvalidPolicy);
        }
        if self
            .allowed_classes
            .iter()
            .any(|class| class.is_subscriber_identifier())
        {
            return Err(MinimizationError::DirectIdentifierNotAllowed(
                DataClass::SubscriberId,
            ));
        }
        Ok(())
    }

    /// Validates an export of a list of cohorts against k-anonymity requirements.
    pub fn validate_cohorts(&self, cohorts: &[CohortRecord]) -> Result<(), MinimizationError> {
        self.validate()?;
        if self.enforce_k_anonymity {
            for cohort in cohorts {
                if cohort.count < self.min_cohort_size {
                    return Err(MinimizationError::CohortTooSmall(
                        cohort.count,
                        self.min_cohort_size,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Evaluates if a given data class can be exported under the policy.
    pub fn check_class_allowed(&self, class: DataClass) -> Result<(), MinimizationError> {
        if class.is_subscriber_identifier() {
            return Err(MinimizationError::DirectIdentifierNotAllowed(class));
        }
        if !self.allowed_classes.contains(&class) {
            return Err(MinimizationError::ClassNotAllowed(class));
        }
        Ok(())
    }
}

/// Helper to bin numeric values to create safe aggregate bins.
pub fn bin_value(val: u64, bin_size: u64) -> String {
    try_bin_value(val, bin_size).unwrap_or_else(|_| "invalid-bin".to_string())
}

/// Fallible helper to bin numeric values to create safe aggregate bins.
pub fn try_bin_value(val: u64, bin_size: u64) -> Result<String, MinimizationError> {
    if bin_size == 0 {
        return Err(MinimizationError::InvalidBinSize);
    }
    let lower = (val / bin_size) * bin_size;
    let upper = lower + bin_size;
    Ok(format!("{}-{}", lower, upper))
}

/// Helper to hash a subscriber ID if needed, using a keyed digest.
pub fn hash_identifier(
    key: &opc_redaction::DigestKey,
    id_type: IdentifierType,
    raw_val: &str,
) -> String {
    opc_redaction::compute_digest(key, DataClass::SubscriberId, id_type, raw_val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_data_governance::DataClass;

    #[test]
    fn test_k_anonymity_cohort_threshold() {
        let policy = MinimizationPolicy {
            policy_id: "analytics-v1".to_string(),
            min_cohort_size: 5,
            enforce_k_anonymity: true,
            allowed_classes: vec![DataClass::AnalyticsSensitive, DataClass::Public],
        };

        // cohort of size 10 is allowed
        let ok_cohorts = vec![
            CohortRecord {
                keys: vec!["age:20-30".to_string()],
                count: 10,
            },
            CohortRecord {
                keys: vec!["age:30-40".to_string()],
                count: 5,
            },
        ];
        assert!(policy.validate_cohorts(&ok_cohorts).is_ok());

        // cohort of size 3 is rejected
        let bad_cohorts = vec![
            CohortRecord {
                keys: vec!["age:20-30".to_string()],
                count: 10,
            },
            CohortRecord {
                keys: vec!["age:30-40".to_string()],
                count: 3,
            },
        ];
        assert_eq!(
            policy.validate_cohorts(&bad_cohorts),
            Err(MinimizationError::CohortTooSmall(3, 5))
        );
    }

    #[test]
    fn test_rejects_direct_identifiers() {
        let policy = MinimizationPolicy {
            policy_id: "analytics-v1".to_string(),
            min_cohort_size: 5,
            enforce_k_anonymity: true,
            allowed_classes: vec![DataClass::SubscriberId, DataClass::Public],
        };

        // Even if SubscriberId is in allowed_classes, check_class_allowed rejects it!
        assert_eq!(
            policy.validate(),
            Err(MinimizationError::DirectIdentifierNotAllowed(
                DataClass::SubscriberId
            ))
        );
        assert_eq!(
            policy.check_class_allowed(DataClass::SubscriberId),
            Err(MinimizationError::DirectIdentifierNotAllowed(
                DataClass::SubscriberId
            ))
        );

        assert!(policy.check_class_allowed(DataClass::Public).is_ok());
        assert_eq!(
            policy.check_class_allowed(DataClass::AnalyticsSensitive),
            Err(MinimizationError::ClassNotAllowed(
                DataClass::AnalyticsSensitive
            ))
        );
    }

    #[test]
    fn test_binning_and_hashing() {
        // Binning
        assert_eq!(bin_value(23, 10), "20-30");
        assert_eq!(bin_value(45, 20), "40-60");
        assert_eq!(bin_value(9, 5), "5-10");
        assert_eq!(try_bin_value(9, 0), Err(MinimizationError::InvalidBinSize));
        assert_eq!(bin_value(9, 0), "invalid-bin");

        // Digesting
        let key = opc_redaction::DigestKey::new([0xbb; 32]);
        let digested = hash_identifier(&key, IdentifierType::Supi, "208950000000001");
        assert_eq!(digested.len(), 64);
    }
}
