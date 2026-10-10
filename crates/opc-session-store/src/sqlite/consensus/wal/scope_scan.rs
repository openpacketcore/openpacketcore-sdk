//! Retained scope records with short, checked native operation ownership.

use super::*;
use crate::consensus::native::ScopeRecordCapture;
use std::sync::Weak;

pub(crate) struct NativeScopeScan {
    capture: ScopeRecordCapture,
    owner: Weak<Shared>,
}

impl NativeScopeScan {
    pub(crate) fn applied(&self) -> Option<LogId<SessionConsensusNodeId>> {
        self.capture.applied()
    }

    #[cfg(test)]
    pub(crate) fn retained_bytes(&self) -> io::Result<usize> {
        self.capture.retained_bytes()
    }
}

impl Wal {
    pub(crate) fn native_scope_headers(
        &self,
        identity: SessionConsensusIdentity,
        namespace: &crate::scope_authority::ScopeNamespace,
        stamp: &crate::scope_authority::ScopeAuthorityStamp,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<
        Result<crate::scope_scan::headers::CapturedHeaders, crate::scope_scan::ScopeScanError>,
    > {
        let _permit = self.native_scope_operation(check)?;
        // Keep ordinary read outcomes inside the result, so invalid headers,
        // cancellation or loss of local authority never fence the store.
        let result = self.native_detached(|| {
            Ok((|| {
                let state = lock_state(&self.shared)?;
                check()?;
                ensure_native_public_owner(&state)?;
                state
                    .native
                    .as_ref()
                    .ok_or_else(|| invalid_data("native scope owner missing"))?
                    .scope_scan_headers(identity, namespace, stamp)
            })())
        })?;
        check()?;
        result
    }

    /// Preflight retains neither a root nor an installation-blocking permit.
    /// The opening worker must verify and reserve the same bounded charge below.
    pub(crate) fn native_scope_cost(
        &self,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<usize> {
        check()?;
        let state = lock_state(&self.shared)?;
        ensure_native_public_owner(&state)?;
        if state.snapshot.is_some() || state.native_install_pending {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native scope capture installation is pending",
            ));
        }
        state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native scope owner missing"))?
            .scope_record_bytes()
    }

    /// Reserve under the same State lock as root capture. The callback may
    /// adjust only its registry ticket; registry code never calls back into
    /// the WAL while holding its own mutex. A refused charge retains no root.
    pub(crate) fn native_scope_capture(
        &self,
        check: &dyn Fn() -> io::Result<()>,
        reserve: impl FnOnce(usize) -> io::Result<bool>,
    ) -> io::Result<Option<NativeScopeScan>> {
        let _permit = self.native_scope_operation(check)?;
        let capture = {
            let state = lock_state(&self.shared)?;
            check()?;
            ensure_native_public_owner(&state)?;
            let native = state
                .native
                .as_ref()
                .ok_or_else(|| invalid_data("native scope owner missing"))?;
            if !reserve(native.scope_record_bytes()?)? {
                return Ok(None);
            }
            native.capture_scope_records()?
        };
        check()?;
        Ok(Some(NativeScopeScan {
            capture,
            owner: Arc::downgrade(&self.shared),
        }))
    }

    pub(crate) fn native_scope_read<T>(
        &self,
        scan: &NativeScopeScan,
        check: &dyn Fn() -> io::Result<()>,
        read: impl FnOnce(&ScopeRecordCapture, &dyn Fn() -> io::Result<()>) -> io::Result<T>,
    ) -> io::Result<T> {
        self.native_scope_read_bounded(scan, check, check, read)
    }

    /// Admission has its own bounded wait. Once the read starts, exhaustion of
    /// item work may return a completed prefix; authority checks still apply.
    pub(crate) fn native_scope_read_bounded<T>(
        &self,
        scan: &NativeScopeScan,
        admission: &dyn Fn() -> io::Result<()>,
        check: &dyn Fn() -> io::Result<()>,
        read: impl FnOnce(&ScopeRecordCapture, &dyn Fn() -> io::Result<()>) -> io::Result<T>,
    ) -> io::Result<T> {
        if !std::ptr::eq(scan.owner.as_ptr(), Arc::as_ptr(&self.shared)) {
            return Err(invalid_data("native scope capture owner differs"));
        }
        let _permit = self.native_scope_operation(admission)?;
        let current = || {
            check()?;
            let state = lock_state(&self.shared)?;
            ensure_native_public_owner(&state)?;
            scan.capture.require_current_authority(
                state
                    .native
                    .as_ref()
                    .ok_or_else(|| invalid_data("native scope owner missing"))?,
            )
        };
        current()?;
        // Item faults and cancellation are ordinary read outcomes. Only an
        // unexpected panic crosses the existing detached-work fencing guard.
        let result = self.native_detached(|| Ok(read(&scan.capture, &current)))?;
        current()?;
        result
    }

    fn native_scope_operation(
        &self,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<OperationPermit> {
        check()?;
        let mut state = lock_state(&self.shared)?;
        while (state.snapshot.is_some() || state.native_install_pending)
            && state.status == Status::Running
        {
            check()?;
            (state, _) = self
                .shared
                .ready
                .wait_timeout(state, Duration::from_millis(20))
                .map_err(|_| io::Error::other("native scope admission poisoned"))?;
        }
        check()?;
        ensure_native_public_owner(&state)?;
        if state.snapshot.is_some() || state.native_install_pending {
            return Err(invalid_data("native scope installation is closing"));
        }
        state.native_operations = state
            .native_operations
            .checked_add(1)
            .ok_or_else(|| invalid_data("native scope operation count exhausted"))?;
        Ok(OperationPermit(Arc::clone(&self.shared)))
    }
}
