//! Quorum session-store public surface.
//!
//! [`QuorumSessionStore`] is the Openraft-backed
//! [`crate::ConsensusSessionStore`]. The former majority-visible-prefix
//! coordinator was removed because it independently assigned sequences,
//! inferred commitment, repaired replicas, and allocated lease authority. The
//! SDK has one production consensus engine; tests simulate transport faults at
//! the consensus peer boundary instead of running a second algorithm.

use crate::backend::SessionBackend;
use crate::lease::SessionLeaseManager;

/// Combined backend trait retained for standalone stores and the explicitly
/// enabled legacy remote-backend compatibility transport.
///
/// Production consensus topology is descriptor-only and does not accept this
/// trait object. [`crate::ConsensusSessionStore`] receives one concrete local
/// SQLite backend while remote members are reached only through
/// [`crate::SessionConsensusPeer`].
pub trait SessionStoreBackend: SessionBackend + SessionLeaseManager {}
impl<T: SessionBackend + SessionLeaseManager> SessionStoreBackend for T {}

/// The sole production quorum session store, coordinated by Openraft.
pub type QuorumSessionStore = crate::consensus::ConsensusSessionStore;
