//! OpenPacketCore Alarm Subsystem
//!
//! Alarm model, severity taxonomy, probable causes, deduplication/update/clear
//! manager, and in-memory alarm store per RFC 013.
//!
//! ## Design Overview
//!
//! - [`model`] — Alarm structs, severity levels, probable-cause taxonomy,
//!   affected-object naming, dedup key, and readiness impact policy.
//! - [`manager`] — Alarm manager (raise/update/clear/acknowledge/suppress)
//!   backed by a pluggable [`AlarmStore`] trait.
//!
//! ## Key Constraints (per RFC 010 and RFC 013)
//!
//! - Alarm text MUST be redacted before passing to the manager (use [`RedactedText::new`]).
//! - Affected objects MUST NOT contain raw subscriber identifiers.
//! - Dedup keys MUST be stable across identical fault inputs.
//! - Suppression and acknowledgement require authorization.
//! - Critical/major active alarms drive pod readiness per readiness impact policy.
//!
//! ## Example
//!
//! ```rust
//! use opc_alarm::prelude::*;
//!
//! let mut mgr = opc_alarm::AlarmManager::new(opc_alarm::InMemoryStore::new());
//!
//! let result = mgr.raise(
//!     AlarmType::new("link.down"),
//!     Severity::Major,
//!     ProbableCause::PeerUnreachable,
//!     AffectedObject::NfInstance {
//!         kind: "upf".to_string(),
//!         instance: "upf-1".to_string(),
//!     },
//!     None,
//!     None,
//!     None,
//!     RedactedText::new("Peer unreachable"), // caller redacts per RFC 010
//!     AlarmDetails::empty(),
//! );
//! ```
//!
//! ## Feature Gating
//!
//! When CNF models grow structured detail types, add feature flags here and gate
//! detail serialization behind them.

#![forbid(unsafe_code)]
#![warn(clippy::incompatible_msrv)]

pub mod manager;
pub mod model;
pub mod sink;

#[cfg(feature = "nacm")]
pub mod nacm_adapter;
#[cfg(feature = "nacm")]
pub use nacm_adapter::NacmAlarmAuthorizer;

#[cfg(feature = "persist")]
pub mod persist_adapter;
#[cfg(feature = "persist")]
pub use persist_adapter::PersistAlarmAuditSink;

// Re-export the most commonly used types at the crate root.
pub use manager::{
    AlarmAction, AlarmActionAuthorizer, AlarmActionContext, AlarmActionDenied, AlarmActionScope,
    AlarmAuditEvent, AlarmAuditOutcome, AlarmAuditSink, AlarmManager, AlarmOpResult, AlarmStore,
    InMemoryStore, SharedAlarmManager, SuppressionAuth,
};
pub use model::{
    AffectedObject, Alarm, AlarmDetails, AlarmId, AlarmState, AlarmType, DedupKey, InvalidRegionId,
    ParseProbableCauseError, ProbableCause, ReadinessImpact, RedactedText, RegionId, Severity,
    TAXONOMY_VERSION,
};
pub use sink::{
    AlarmSink, AlarmSinkError, BoundedAlarmSink, RecordingSink, SinkStatus, TracingSink,
};

/// Convenience re-exports for use with `use opc_alarm::prelude::*`.
pub mod prelude {
    pub use crate::manager::{
        AlarmAction, AlarmActionAuthorizer, AlarmActionContext, AlarmActionDenied,
        AlarmActionScope, AlarmAuditEvent, AlarmAuditOutcome, AlarmAuditSink, AlarmManager,
        AlarmOpResult, AlarmStore, InMemoryStore, SharedAlarmManager, SuppressionAuth,
    };
    pub use crate::model::{
        AffectedObject, Alarm, AlarmDetails, AlarmId, AlarmState, AlarmType, DedupKey,
        InvalidRegionId, ProbableCause, ReadinessImpact, RedactedText, RegionId, Severity,
        TAXONOMY_VERSION,
    };
    pub use crate::sink::{
        AlarmSink, AlarmSinkError, BoundedAlarmSink, RecordingSink, SinkStatus, TracingSink,
    };

    #[cfg(feature = "nacm")]
    pub use crate::nacm_adapter::NacmAlarmAuthorizer;

    #[cfg(feature = "persist")]
    pub use crate::persist_adapter::PersistAlarmAuditSink;
}
