//! Coherent, locally retained scope views and their bounded work ownership.

pub(crate) mod activity;
pub(crate) mod admission;
pub(crate) mod backend;
mod codec;
pub(crate) mod cursor;
pub(crate) mod engine;
pub use cursor::ScopeScanCursor;
pub(crate) mod headers;
pub(crate) mod integrity;
mod limits;
mod position;
pub(crate) mod progress;
pub(crate) mod protocol;
pub(crate) mod replay;
pub use protocol::ScopeScanReply;
pub(crate) mod sources;
pub use limits::{ScopeScanLimits, ScopeScanLimitsError, ScopeScanMetrics};
pub(crate) mod registry;
pub(crate) mod runtime;

mod retry;
pub use retry::{
    ScopeRestoreStalled, ScopeScanRetryCause, ScopeScanRetryPolicy, ScopeScanRetryPolicyError,
};
mod client;
mod local_client;
pub use client::{
    ScopeScanClient, ScopeScanClientError, ScopeScanClientView, ScopeScanRequestFailure,
    ScopeScanSink, ScopeScanTransport,
};
pub use local_client::ScopeScanLocalTransport;

mod wire;
pub use wire::{
    ScopeScanOpenReply, ScopeScanRequest, ScopeScanResponse, ScopeScanViewToken,
    MAX_SCOPE_SCAN_REPLY_BYTES, MAX_SCOPE_SCAN_REQUEST_BYTES,
};

mod open;
pub use open::{ScopeScanOpenRequest, ScopeScanWireError, MAX_SCOPE_SCAN_OPEN_BYTES};

mod service;
pub use service::{
    ScopeCut, ScopeRestoreView, ScopeScanCheckpoint, ScopeScanError, ScopeScanHeaderFault,
    ScopeScanStore,
};

mod result;
pub use integrity::{
    ClaimHolder as ScopeScanClaimHolder, IntegrityFault as ScopeScanIntegrityFault,
    ItemDisposition as ScopeScanDisposition, ItemFailure as ScopeScanFailure,
    ItemKind as ScopeScanItemKind,
};
pub use result::{
    ScopeScanClaim, ScopeScanItem, ScopeScanLookup, ScopeScanLookupKey, ScopeScanPageLimits,
    ScopeScanPageStatus, ScopeScanSummary,
};
