//! Concrete retained NETCONF audit integration with the existing bounded worker.
mod channel;
mod event;
mod registry;
mod result;
mod store;
mod worker;

pub use channel::RequiredNetconfAudit;
pub(crate) use channel::{
    recover_in_worker, session_in_worker, RecoveryMessage, SessionMessage, WorkerAttachment,
    WorkerSignal,
};
/// SDK datastore identity used for retained lock preparation and leases.
pub use opc_persist::audit_authority::NetconfLockDatastore;
pub use result::{
    NetconfAppliedReceipt, NetconfMutationResult, NetconfRecoveryHandle, NetconfRejectedReceipt,
};
pub use session_lifetime::TransportSessionLifetime as NetconfSession;
pub use store::NetconfAuditStore;
pub(crate) use worker::TargetWorker;
pub(crate) use worker_join::{WorkerExit, WorkerJoin};
pub use worker_join::{WorkerExit as NetconfWorkerExit, WorkerLost as NetconfWorkerLost};

#[cfg(test)]
mod native_fixture;
mod session_lifetime;
#[cfg(test)]
mod session_lifetime_tests;
mod session_registry;
mod worker_join;

#[cfg(test)]
mod lock_tests;
