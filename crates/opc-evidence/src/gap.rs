use serde::{Deserialize, Serialize};
use time::Date;

use crate::{ConformanceStatus, EvidenceError};

mod date_serde {
    use once_cell::sync::Lazy;
    use serde::{self, Deserialize, Deserializer, Serializer};
    use time::{format_description::FormatItem, Date};

    const FORMAT: &str = "[year]-[month]-[day]";

    static FORMAT_DESCRIPTION: Lazy<Vec<FormatItem<'static>>> =
        Lazy::new(|| time::format_description::parse(FORMAT).expect("valid date format string"));

    pub fn serialize<S>(date: &Date, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = date
            .format(&FORMAT_DESCRIPTION)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Date, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Date::parse(&s, &FORMAT_DESCRIPTION).map_err(serde::de::Error::custom)
    }
}

/// Severity of a known gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GapSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Lifecycle state of a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GapStatus {
    Open,
    Closed,
    Deferred,
}

/// Failure modes for `Gap` construction and validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GapError {
    /// A gap record has invalid construction-time data (blank id, title, owner, etc.).
    #[error("invalid gap: {0}")]
    InvalidGap(String),
}

/// Optional fields for gap construction.
///
/// Groups the optional fields to keep [`Gap::new`] under the clippy argument limit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GapOptions {
    /// Owner responsible for resolving the gap.
    pub owner: Option<String>,
    /// Target release in which the gap is expected to be resolved.
    pub target_release: Option<String>,
    /// Mitigation strategy or `"no mitigation"` rationale.
    pub mitigation: Option<String>,
    /// Description of security impact, required for Critical severity.
    pub security_impact: Option<String>,
    /// Security team approval for Critical severity gaps.
    pub security_approval: Option<String>,
    /// Description of performance impact.
    pub performance_impact: Option<String>,
}

/// Structured record for a known conformance gap.
///
/// Callers should prefer [`Gap::new`] over direct struct construction to ensure
/// field validity (e.g., non-blank invariants). However, the fields are public
/// to maintain backward compatibility with downstream usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gap {
    pub id: String,
    pub title: String,
    pub status: GapStatus,
    pub severity: GapSeverity,
    pub applies_to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(with = "date_serde")]
    pub created: Date,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_approval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub performance_impact: Option<String>,
}

/// Deserializes a `Gap` from JSON, routing through the same validation as
/// [`Gap::new`] to ensure `id`, `title`, and `owner` are non-blank.
///
/// Returns a deserialization error (via `serde::de::Error::custom`) if any required field is blank,
/// analogous to the `InvalidGap` check in `Gap::new`.
impl<'de> serde::Deserialize<'de> for Gap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct GapProxy {
            id: String,
            title: String,
            status: GapStatus,
            severity: GapSeverity,
            applies_to: Vec<String>,
            owner: Option<String>,
            #[serde(with = "date_serde")]
            created: Date,
            target_release: Option<String>,
            mitigation: Option<String>,
            security_impact: Option<String>,
            security_approval: Option<String>,
            performance_impact: Option<String>,
        }

        let proxy = GapProxy::deserialize(deserializer)?;

        let options = GapOptions {
            owner: proxy.owner,
            target_release: proxy.target_release,
            mitigation: proxy.mitigation,
            security_impact: proxy.security_impact,
            security_approval: proxy.security_approval,
            performance_impact: proxy.performance_impact,
        };

        Gap::new(
            proxy.id,
            proxy.title,
            proxy.status,
            proxy.severity,
            proxy.applies_to,
            proxy.created,
            options,
        )
        .map_err(|e| match e {
            GapError::InvalidGap(msg) => serde::de::Error::custom(msg),
        })
    }
}

fn parse_version(s: &str) -> Option<Vec<u64>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for part in s.split('.') {
        let clean: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if clean.is_empty() {
            return None;
        }
        parts.push(clean.parse::<u64>().ok()?);
    }
    Some(parts)
}

fn is_version_older(target: &str, current: &str) -> bool {
    let t_parsed = parse_version(target);
    let c_parsed = parse_version(current);
    match (t_parsed, c_parsed) {
        (Some(t), Some(c)) => {
            let max_len = std::cmp::max(t.len(), c.len());
            for i in 0..max_len {
                let t_val = t.get(i).copied().unwrap_or(0);
                let c_val = c.get(i).copied().unwrap_or(0);
                if t_val < c_val {
                    return true;
                } else if t_val > c_val {
                    return false;
                }
            }
            false
        }
        _ => target < current,
    }
}

impl Gap {
    /// Constructs a `Gap` from validated components.
    ///
    /// Validates that `id`, `title`, and `owner` are not blank (empty or whitespace-only),
    /// matching the constraints in
    /// `schemas/rfc006/v1/gap-record.schema.json`.
    ///
    /// Callers should prefer this constructor over direct struct construction to ensure
    /// field validity.
    ///
    /// Returns [`GapError::InvalidGap`] if any required field is blank.
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        status: GapStatus,
        severity: GapSeverity,
        applies_to: Vec<String>,
        created: Date,
        options: GapOptions,
    ) -> Result<Self, GapError> {
        let id = id.into();
        let title = title.into();

        if id.trim().is_empty() {
            return Err(GapError::InvalidGap("id cannot be blank".into()));
        }
        if title.trim().is_empty() {
            return Err(GapError::InvalidGap("title cannot be blank".into()));
        }
        if options
            .owner
            .as_ref()
            .is_some_and(|owner_val| owner_val.trim().is_empty())
        {
            return Err(GapError::InvalidGap("owner cannot be blank".into()));
        }

        Ok(Gap {
            id: id.trim().to_string(),
            title: title.trim().to_string(),
            status,
            severity,
            applies_to,
            created,
            owner: options.owner.map(|s| s.trim().to_string()),
            target_release: options.target_release,
            mitigation: options.mitigation,
            security_impact: options.security_impact,
            security_approval: options.security_approval,
            performance_impact: options.performance_impact,
        })
    }

    /// Returns the gap identifier (e.g., `"GAP-000001"`).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the human-readable title of the gap.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the lifecycle status of the gap.
    pub fn status(&self) -> GapStatus {
        self.status
    }

    /// Returns the severity level of the gap.
    pub fn severity(&self) -> GapSeverity {
        self.severity
    }

    /// Returns the list of requirement IDs this gap applies to.
    pub fn applies_to(&self) -> &[String] {
        &self.applies_to
    }

    /// Returns the owner responsible for resolving the gap, if set.
    pub fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    /// Returns the creation date of the gap.
    pub fn created(&self) -> Date {
        self.created
    }

    /// Returns the target release, if set.
    pub fn target_release(&self) -> Option<&str> {
        self.target_release.as_deref()
    }

    /// Returns the mitigation strategy or `"no mitigation"` rationale, if set.
    pub fn mitigation(&self) -> Option<&str> {
        self.mitigation.as_deref()
    }

    /// Returns the security impact description, if set.
    pub fn security_impact(&self) -> Option<&str> {
        self.security_impact.as_deref()
    }

    /// Returns the security approval, if set.
    pub fn security_approval(&self) -> Option<&str> {
        self.security_approval.as_deref()
    }

    /// Returns the performance impact description, if set.
    pub fn performance_impact(&self) -> Option<&str> {
        self.performance_impact.as_deref()
    }

    /// Validates that the gap meets release-gate criteria.
    ///
    /// Gates (from RFC 006 §6.2):
    /// - Must have an owner.
    /// - Must have a mitigation or an explicit `"no mitigation"` rationale.
    /// - Target release must not be empty if present.
    /// - Target release must not be overdue (older than current_release).
    /// - Critical severity gaps must document security impact and have security approval.
    pub fn validate_gate(&self, current_release: &str) -> Result<(), EvidenceError> {
        if self
            .owner
            .as_ref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(EvidenceError::GapGateFailed(format!(
                "gap {} has no owner",
                self.id
            )));
        }

        let has_mitigation = self
            .mitigation
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !has_mitigation {
            return Err(EvidenceError::GapGateFailed(format!(
                "gap {} lacks mitigation or explicit 'no mitigation' rationale",
                self.id
            )));
        }

        if let Some(ref target) = self.target_release {
            if target.trim().is_empty() {
                return Err(EvidenceError::GapGateFailed(format!(
                    "gap {} has empty target_release",
                    self.id
                )));
            }
            if self.status != GapStatus::Closed && is_version_older(target, current_release) {
                return Err(EvidenceError::GapGateFailed(format!(
                    "gap {} target release '{}' is overdue (current release is '{}')",
                    self.id, target, current_release
                )));
            }
        }

        let has_security_impact = self
            .security_impact
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let has_security_approval = self
            .security_approval
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if self.severity == GapSeverity::Critical {
            if !has_security_impact {
                return Err(EvidenceError::GapGateFailed(format!(
                    "critical gap {} lacks security impact documentation",
                    self.id
                )));
            }
            if !has_security_approval {
                return Err(EvidenceError::GapGateFailed(format!(
                    "critical gap {} lacks security approval",
                    self.id
                )));
            }
        }

        Ok(())
    }
}

/// Validates that a claimed [`ConformanceStatus`] is consistent with the
/// actual gap records present in the evidence store.
///
/// Per RFC 006 §5.4:
///
/// - `Full` and `ImplementedUntested` are only valid when there are **no active
///   gaps** (neither `Open` nor `Deferred`) in the `gaps` slice.
/// - `Partial` and `NotImplemented` are permitted with active gaps (they are the
///   expected calculated outcomes in those cases).
///
/// This function should be called after [`crate::calculate_status`] derives a status,
/// to catch callers who pass a stale `has_gap = false` while active gaps are
/// present in the store.
pub fn validate_status_for_gaps(
    gaps: &[Gap],
    status: ConformanceStatus,
) -> Result<(), EvidenceError> {
    let has_active = gaps.iter().any(|g| g.status != GapStatus::Closed);

    if !has_active {
        return Ok(());
    }

    match status {
        // Fully satisfied; no active gaps may exist.
        ConformanceStatus::Full | ConformanceStatus::ImplementedUntested => {
            let active_count = gaps
                .iter()
                .filter(|g| g.status != GapStatus::Closed)
                .count();
            Err(EvidenceError::GapGateFailed(format!(
                "status {status:?} is inconsistent with {active_count} active gap(s) in the evidence store"
            )))
        }
        // Partial / NotImplemented may coexist with active gaps (expected outcomes).
        ConformanceStatus::Partial
        | ConformanceStatus::NotImplemented
        | ConformanceStatus::Implemented
        | ConformanceStatus::Tested
        | ConformanceStatus::NotApplicable
        | ConformanceStatus::Waived
        | ConformanceStatus::Gap => Ok(()),
    }
}
