//! Quorum session-store public surface.
//!
//! [`QuorumSessionStore`] is the Openraft-backed
//! [`crate::ConsensusSessionStore`]. The former majority-visible-prefix
//! coordinator was removed because it independently assigned sequences,
//! inferred commitment, repaired replicas, and allocated lease authority. The
//! SDK has one production consensus engine; tests simulate transport faults at
//! the consensus peer boundary instead of running a second algorithm.
//!
//! The engine-level `probe_durable_readiness` method is retained for lab and
//! conformance evidence. Production traffic requires attested topology plus
//! a `ProductionTopologyAttested` report whose
//! `is_production_traffic_ready()` result is true from
//! `probe_production_durable_readiness`; a base-probe `Ready` result does not
//! carry platform-fact provenance.

use crate::backend::SessionBackend;
use crate::lease::SessionLeaseManager;

/// Combined backend trait retained for standalone stores and the explicitly
/// enabled legacy remote-backend compatibility transport.
///
/// Consensus topology is adapter-free and does not accept this trait object.
/// [`crate::ConsensusSessionStore`] receives one concrete local SQLite backend
/// while remote members are reached only through
/// [`crate::SessionConsensusPeer`]. Descriptor-only admission is lab-scoped;
/// production admission adds authenticated platform evidence.
pub trait SessionStoreBackend: SessionBackend + SessionLeaseManager {}
impl<T: SessionBackend + SessionLeaseManager> SessionStoreBackend for T {}

/// The sole quorum consensus engine, coordinated by Openraft.
///
/// Production use additionally requires authenticated topology admission and
/// the production capability/readiness methods.
pub type QuorumSessionStore = crate::consensus::ConsensusSessionStore;
