//! # Operator Controller Crate
//!
//! Implements the Kubernetes operator execution layer:
//! - CRD conversion webhook helpers
//! - YANG/state migration orchestration
//! - Out-of-process drain execution client
//! - Multi-cluster rollout status model
//!
//! Leverages the primitives in `operator-lifecycle` for admission, phase, and plan validation.

#![forbid(unsafe_code)]

pub mod conversion;
pub mod drain;
pub mod migration;
pub mod multicluster;
