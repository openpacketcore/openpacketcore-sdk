//! Normalized YANG path parsing and trie-backed NACM authorization decisions.
//!
//! The primary workflow is:
//! 1. Register module prefixes in a [`ModuleRegistry`].
//! 2. Normalize rule patterns and request paths into canonical module names.
//! 3. Build an immutable [`NacmPolicy`] and evaluate it through
//!    [`NacmEvaluator`] for default-deny decisions with policy-aware bounded
//!    caching.
//!
//! Rule evaluation follows RFC 8341 first-match rule-list semantics: if more
//! than one rule matches a path/action pair, the earliest rule inserted into the
//! policy wins even when a later rule is more specific.
//!
//! ```
//! use opc_nacm::{
//!     ModuleRegistry, NacmAction, NacmEvaluator, NacmPolicy, NacmRule, PolicyVersion, YangPath,
//!     YangPathPattern,
//! };
//!
//! let mut modules = ModuleRegistry::new();
//! modules.register_module("ietf-interfaces", "if")?;
//!
//! let path = YangPath::parse("/if:interfaces/interface/config/name", &modules)?;
//! let read_rule = NacmRule::allow(
//!     NacmAction::Read,
//!     YangPathPattern::parse("/if:interfaces/interface/config/**", &modules)?,
//! );
//!
//! let policy = NacmPolicy::builder(PolicyVersion::new(1))
//!     .add_rule(read_rule)
//!     .build();
//! let mut evaluator = NacmEvaluator::new();
//!
//! let decision = evaluator.evaluate(&policy, &path, NacmAction::Read);
//! assert!(decision.is_allowed());
//! # Ok::<(), opc_nacm::NacmError>(())
//! ```

#![forbid(unsafe_code)]

mod action;
mod error;
mod path;
mod policy;
mod trie;

pub use crate::action::NacmAction;
pub use crate::error::NacmError;
pub use crate::path::{
    ModuleRegistry, QualifiedNodeName, YangPath, YangPathPattern, YangPathPatternSegment,
};
pub use crate::policy::{
    AuthorizationDecision, NacmEffect, NacmEvaluator, NacmPolicy, NacmPolicyBuilder, NacmRule,
    PolicyVersion,
};
