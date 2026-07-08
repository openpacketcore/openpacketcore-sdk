//! Privacy minimization and k-anonymity utilities for OpenPacketCore analytics exports.

#![forbid(unsafe_code)]

use opc_data_governance::{DataClass, IdentifierType};
use serde::{Deserialize, Serialize};

/// No cohort smaller than this may be released: a cohort of one re-identifies
/// its subject even when configured k-anonymity enforcement is relaxed.
const ABSOLUTE_MIN_COHORT: usize = 2;

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
    UnsafeCohortKey,
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
                "Minimization error: cohort size {size} is below k-anonymity threshold {threshold}"
            ),
            Self::UnsafeCohortKey => write!(
                f,
                "Minimization error: cohort key contains a raw sensitive identifier"
            ),
            Self::DirectIdentifierNotAllowed(class) => write!(
                f,
                "Minimization error: direct identifier class '{class}' is not allowed in analytics"
            ),
            Self::ClassNotAllowed(class) => write!(
                f,
                "Minimization error: class '{class}' is not permitted by current analytics policy"
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
    ///
    /// When `enforce_k_anonymity` is set, every cohort must meet
    /// `min_cohort_size`. Even when it is not set, an absolute floor still
    /// applies: a singleton cohort (count `< 2`) is directly re-identifying and
    /// is never released. Disabling enforcement relaxes the configured `k`, not
    /// the singleton floor.
    pub fn validate_cohorts(&self, cohorts: &[CohortRecord]) -> Result<(), MinimizationError> {
        self.validate()?;
        let floor = if self.enforce_k_anonymity {
            self.min_cohort_size.max(ABSOLUTE_MIN_COHORT)
        } else {
            ABSOLUTE_MIN_COHORT
        };
        for cohort in cohorts {
            if cohort.keys.iter().any(|key| contains_raw_identifier(key)) {
                return Err(MinimizationError::UnsafeCohortKey);
            }
            if cohort.count < floor {
                return Err(MinimizationError::CohortTooSmall(cohort.count, floor));
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

/// Builds cohort records from generalized row keys, computing counts internally.
pub fn aggregate_cohorts<I>(rows: I) -> Vec<CohortRecord>
where
    I: IntoIterator<Item = Vec<String>>,
{
    let mut counts = std::collections::BTreeMap::<Vec<String>, usize>::new();
    for keys in rows {
        *counts.entry(keys).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(keys, count)| CohortRecord { keys, count })
        .collect()
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
    Ok(format!("{lower}-{upper}"))
}

/// Helper to hash a subscriber ID if needed, using a keyed digest.
pub fn hash_identifier(
    key: &opc_redaction::DigestKey,
    id_type: IdentifierType,
    raw_val: &str,
) -> String {
    opc_redaction::compute_digest(key, DataClass::SubscriberId, id_type, raw_val)
}

fn contains_raw_identifier(key: &str) -> bool {
    contains_long_digit_run(key) || contains_ipv4_literal(key)
}

fn contains_long_digit_run(key: &str) -> bool {
    let mut run = 0usize;
    for c in key.chars() {
        if c.is_ascii_digit() {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn contains_ipv4_literal(key: &str) -> bool {
    key.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(looks_like_ipv4)
}

fn looks_like_ipv4(candidate: &str) -> bool {
    let mut parts = candidate.split('.');
    let Some(a) = parts.next() else {
        return false;
    };
    let Some(b) = parts.next() else {
        return false;
    };
    let Some(c) = parts.next() else {
        return false;
    };
    let Some(d) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [a, b, c, d].iter().all(|part| {
        !part.is_empty()
            && part.len() <= 3
            && part.chars().all(|c| c.is_ascii_digit())
            && part.parse::<u8>().is_ok()
    })
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
    fn test_singleton_cohort_rejected_even_without_k_anonymity() {
        // Disabling k-anonymity relaxes the configured `k`, not the absolute
        // singleton floor: a cohort of one is directly re-identifying.
        let policy = MinimizationPolicy {
            policy_id: "analytics-v1".to_string(),
            min_cohort_size: 5,
            enforce_k_anonymity: false,
            allowed_classes: vec![DataClass::AnalyticsSensitive, DataClass::Public],
        };

        // A singleton cohort is rejected against the floor of 2.
        let singleton = vec![CohortRecord {
            keys: vec!["imsi-bucket".to_string()],
            count: 1,
        }];
        assert_eq!(
            policy.validate_cohorts(&singleton),
            Err(MinimizationError::CohortTooSmall(1, 2))
        );

        // A cohort of two or more is allowed once k-anonymity is not enforced.
        let pair = vec![CohortRecord {
            keys: vec!["age:20-30".to_string()],
            count: 2,
        }];
        assert!(policy.validate_cohorts(&pair).is_ok());
    }

    #[test]
    fn test_k_anonymity_enforcement_cannot_release_singletons() {
        let policy = MinimizationPolicy {
            policy_id: "analytics-v1".to_string(),
            min_cohort_size: 1,
            enforce_k_anonymity: true,
            allowed_classes: vec![DataClass::AnalyticsSensitive, DataClass::Public],
        };

        let singleton = vec![CohortRecord {
            keys: vec!["age:20-30".to_string()],
            count: 1,
        }];
        assert_eq!(
            policy.validate_cohorts(&singleton),
            Err(MinimizationError::CohortTooSmall(1, 2))
        );

        let pair = vec![CohortRecord {
            keys: vec!["age:20-30".to_string()],
            count: 2,
        }];
        assert!(policy.validate_cohorts(&pair).is_ok());
    }

    #[test]
    fn test_cohort_keys_reject_raw_identifiers_regardless_of_count() {
        let policy = MinimizationPolicy {
            policy_id: "analytics-v1".to_string(),
            min_cohort_size: 2,
            enforce_k_anonymity: true,
            allowed_classes: vec![DataClass::AnalyticsSensitive, DataClass::Public],
        };

        for key in ["imsi:208950000000001", "peer:10.0.0.1"] {
            let cohort = vec![CohortRecord {
                keys: vec![key.to_string()],
                count: 100,
            }];
            assert_eq!(
                policy.validate_cohorts(&cohort),
                Err(MinimizationError::UnsafeCohortKey)
            );
        }
    }

    #[test]
    fn test_aggregate_cohorts_computes_counts_from_rows() {
        let cohorts = aggregate_cohorts([
            vec!["age:20-30".to_string(), "region:east".to_string()],
            vec!["age:20-30".to_string(), "region:east".to_string()],
            vec!["age:30-40".to_string(), "region:west".to_string()],
        ]);

        assert_eq!(
            cohorts,
            vec![
                CohortRecord {
                    keys: vec!["age:20-30".to_string(), "region:east".to_string()],
                    count: 2,
                },
                CohortRecord {
                    keys: vec!["age:30-40".to_string(), "region:west".to_string()],
                    count: 1,
                },
            ]
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
