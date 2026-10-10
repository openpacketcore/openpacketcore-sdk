//! Captures contain the retained cut, without owning a live backend lifetime.

#[cfg(target_os = "linux")]
use std::sync::Weak;

use super::protocol::PageProtocol;
use super::{ScopeScanCursor, ScopeScanError, ScopeScanLookup, ScopeScanLookupKey, ScopeScanReply};
#[cfg(target_os = "linux")]
use crate::sqlite::consensus::wal::{native::NativeScopeScan, Wal};
use crate::sqlite::scope_scan::SqliteScopeScan;
#[cfg(target_os = "linux")]
use std::io;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) enum CapturedBackend {
    #[cfg(target_os = "linux")]
    Native {
        owner: Weak<Wal>,
        capture: Box<NativeScopeScan>,
    },
    Sqlite(Box<SqliteScopeScan>),
}

// The runtime drops both the capture and protocol before returning retention
// credit. Keeping the outer view handle cannot retain an idle reply or secret.
pub(crate) struct CapturedScope {
    pub(crate) backend: CapturedBackend,
    pub(crate) protocol: PageProtocol,
}

pub(crate) enum ScopeRead {
    Page(ScopeScanCursor),
    Lookup(ScopeScanLookupKey),
}
pub(crate) enum ScopeReadResult {
    Page(Arc<ScopeScanReply>),
    Lookup(Box<ScopeScanLookup>),
}
impl ScopeRead {
    fn run<S: super::engine::InventorySource>(
        self,
        protocol: &mut PageProtocol,
        source: &mut S,
    ) -> Result<ScopeReadResult, ScopeScanError> {
        match self {
            Self::Page(cursor) => protocol.page(&cursor, source).map(ScopeReadResult::Page),
            Self::Lookup(key) => protocol
                .lookup(key, source)
                .map(Box::new)
                .map(ScopeReadResult::Lookup),
        }
    }
}
impl CapturedScope {
    pub(crate) fn read<C: Fn() -> bool + Clone + Send + 'static>(
        &mut self,
        request: ScopeRead,
        cancelled: C,
    ) -> Result<ScopeReadResult, ScopeScanError> {
        let protocol = &mut self.protocol;
        let result = match &self.backend {
            #[cfg(target_os = "linux")]
            CapturedBackend::Native { owner, capture } => {
                let owner = owner.upgrade().ok_or(ScopeScanError::RestartRequired)?;
                let check = || {
                    if cancelled() {
                        Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "scope scan ended",
                        ))
                    } else {
                        Ok(())
                    }
                };
                let deadline = Instant::now() + Duration::from_secs(1);
                let admission = || {
                    check()?;
                    if Instant::now() >= deadline {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "scope scan admission expired",
                        ))
                    } else {
                        Ok(())
                    }
                };
                owner.native_scope_read_bounded(capture, &admission, &check, |records, current| {
                    let deadline = Instant::now() + Duration::from_secs(1);
                    let exhausted = || Instant::now() >= deadline;
                    let mut source = super::sources::NativeSource {
                        capture: records,
                        check: current,
                        work_exhausted: &exhausted,
                    };
                    Ok(request.run(protocol, &mut source))
                })
            }
            CapturedBackend::Sqlite(capture) => {
                let deadline = Instant::now() + Duration::from_secs(1);
                capture.read_bounded(
                    cancelled,
                    move || Instant::now() >= deadline,
                    |connection, check, work_exhausted| {
                        let mut source = super::sources::SqliteSource {
                            connection,
                            check,
                            work_exhausted,
                        };
                        Ok(request.run(protocol, &mut source))
                    },
                )
            }
        };
        result.map_err(|_| ScopeScanError::Unavailable)?
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn lifecycle_fixture(backend: CapturedBackend) -> Self {
        // Lifecycle tests retain real backend resources without creating scope
        // business rows. The protocol is never used as an authority fixture.
        let first = crate::scope_authority::tests::admitted();
        let successor = first
            .transition(&crate::scope_authority::tests::successor(&first, 2))
            .unwrap();
        let stamp = successor.view.stamp().unwrap();
        let node = crate::SessionConsensusNodeId::new(1).unwrap();
        let cut = super::ScopeCut {
            namespace: stamp.namespace().clone(),
            authority_revision: stamp.revision(),
            batch_revision: 0,
            applied: opc_consensus::engine::LogId::new(
                opc_consensus::engine::CommittedLeaderId::new(1, node),
                1,
            ),
            epoch: 1,
            capture_id: [1; 16],
            serving_node: node,
        };
        let (protocol, _) =
            PageProtocol::new(cut, stamp, 0, super::progress::PageLimits::default()).unwrap();
        Self { backend, protocol }
    }
}

pub(crate) type ScopeViewRegistry = super::registry::ViewRegistry<Option<CapturedScope>>;
