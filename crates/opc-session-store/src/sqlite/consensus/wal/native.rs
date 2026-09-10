//! Native business/log authority under the existing WAL owner. File framing,
//! intent/cut publication, callback retirement and tail repair are shared with
//! the SQL candidate. The retained SQL root is an immutable cold import
//! template; none of this route's live log/apply/read operations queries it.

use super::*;
use crate::consensus::native::{
    ApplicationCapture, NativeState, NativeStorage, ReceiptCopies, ReceiptReads, ResolvedReceipts,
};
use crate::consensus::verified_snapshot::{PortableSnapshot, VerifiedFile};

fn ensure_native_application_owner(state: &State) -> io::Result<()> {
    ensure_readable(state)?;
    if !matches!(state.status, Status::Running | Status::Closing) {
        return Err(io::Error::other("native application owner is closed"));
    }
    Ok(())
}

fn ensure_native_public_owner(state: &State) -> io::Result<()> {
    ensure_readable(state)?;
    if state.status != Status::Running {
        return Err(invalid_data("native public read owner is not running"));
    }
    Ok(())
}

// Installation drains accepted applications and detached reads before its
// capture or old-generation reclamation. New operations wait while existing
// work finishes against its pinned predecessor. Permits retire outside State.
struct OperationPermit(Arc<Shared>);
impl Drop for OperationPermit {
    fn drop(&mut self) {
        let mut state = match self.0.state.lock() {
            Ok(state) => state,
            Err(poison) => poison.into_inner(),
        };
        match state.native_operations.checked_sub(1) {
            Some(count) => state.native_operations = count,
            None => application::fence(&mut state),
        }
        self.0.ready.notify_all();
    }
}

pub(super) fn cold_basis(directory: &Path, binding: Binding) -> io::Result<Connection> {
    let mut conn = Connection::open_in_memory().map_err(db_error)?;
    copy_cold_basis(directory, binding, &mut conn)?;
    Ok(conn)
}

fn copy_cold_basis(directory: &Path, binding: Binding, conn: &mut Connection) -> io::Result<()> {
    let path = directory.join("basis.sqlite");
    let portable =
        PortableSnapshot::capture(crate::sqlite::open_regular_read_nofollow(&path)?, MAX_BASIS)?;
    if portable.source.digest() != binding.basis {
        return Err(invalid_data("native cold root digest differs"));
    }
    let source = Connection::open_with_flags(
        portable.sqlite_uri(),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(db_error)?;
    // A cold, read-only compatibility template only. The verified VFS binds
    // every page actually copied to the admitted descriptor/digest. Live
    // native state is exclusively NativeStorage's Rust maps, never this copy.
    Backup::new(&source, conn)
        .map_err(db_error)?
        .run_to_completion(128, Duration::ZERO, None)
        .map_err(db_error)?;
    conn.pragma_update(None, "query_only", true)
        .map_err(db_error)?;
    validate_basis(conn, binding.identity)?;
    Ok(())
}

// Only the cancellation check below can construct this private marker. An
// Interrupted I/O error, corruption, owner failure or panic must still fence
// the WAL; a concurrent shutdown flag must never mask an unrelated failure.
#[derive(Debug)]
struct SnapshotExportCancelled;

impl std::fmt::Display for SnapshotExportCancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native snapshot export cancelled during shutdown")
    }
}

impl std::error::Error for SnapshotExportCancelled {}

pub(super) fn validate_roster_root(
    conn: &Connection,
    expected: Option<&RosterAttestationTrustRootV1>,
) -> io::Result<()> {
    let stored = super::super::read_roster_attestation_trust_root_sync(conn)
        .map_err(|_| invalid_data("native cold roster trust root is corrupt"))?;
    if stored.as_ref() != expected {
        return Err(invalid_data(
            "native configured roster trust root differs from cold basis",
        ));
    }
    Ok(())
}

pub(super) fn from_pristine_basis(
    conn: &Connection,
    binding: Binding,
    authority: &Authority,
    roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
) -> io::Result<NativeStorage> {
    validate_roster_root(conn, roster_root.as_deref())?;
    if !binding.native
        || authority.profile != ConsensusAuthorityProfile::FixedImmutable
        || !matches!(authority.members.len(), 3 | 5)
        || authority.placement.is_none()
        || read_applied_sync(conn, binding.identity)?.is_some()
        || read_committed_sync(conn, binding.identity)?.is_some()
        || last_log_sync(conn, binding.identity)?.is_some()
        || read_vote_sync(conn, binding.identity)?.is_some()
    {
        return Err(invalid_data(
            "native private construction requires a pristine fixed authority",
        ));
    }
    let machine = super::super::read_machine_sync(conn, binding.identity)?;
    if machine.0 != 0
        || machine.1 != crate::consensus::SessionConsensusEntryDigest::GENESIS
        || machine.2.is_some()
        || machine.3 != 0
    {
        return Err(invalid_data("native pristine root has application history"));
    }
    // Fresh native initialization cannot erase rows written through another
    // public backend surface. Existing SQLite state has no migration path.
    for table in [
        "session_records",
        "leases",
        "key_fences",
        "session_replication_log",
        "consensus_request_outcomes",
    ] {
        let count: u64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .map_err(db_error)?;
        if count != 0 {
            return Err(invalid_data(
                "native pristine root has retained business rows",
            ));
        }
    }
    let globals: u64 = conn.query_row("SELECT COUNT(*) FROM lease_globals WHERE (key = 'next_fence' OR key = 'next_credential_id') AND val = 1", [], |row| row.get(0)).map_err(db_error)?;
    let revision: u64 = conn
        .query_row(
            "SELECT revision FROM restore_scan_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if globals != 2 || revision != 0 {
        return Err(invalid_data("native pristine root counters differ"));
    }
    NativeStorage::empty_with_roster_root(binding.identity, authority.members.clone(), roster_root)
}

pub(in crate::sqlite::consensus) struct Opening {
    directory: PathBuf,
    directory_pin: Arc<File>,
    binding: Binding,
    limits: Limits,
    control: IoControl,
    conn: Connection,
    lock: File,
    native: NativeStorage,
    selected: Option<native_basis::Selected>,
    audit: Option<RecoveryAudit>,
    pending_origin: Option<checkpoint::Anchor>,
    roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
}

fn audit_native_recovery(
    directory: &Path,
    binding: Binding,
    limits: Limits,
    anchor: Option<checkpoint::Anchor>,
    native: &mut NativeStorage,
) -> io::Result<RecoveryAudit> {
    if binding.persistence == SessionPersistenceMode::Async {
        let selected = anchor
            .as_ref()
            .ok_or_else(|| invalid_data("asynchronous recovery lacks its completed generation"))?;
        if selected.async_cut.is_none() {
            return Err(invalid_data("asynchronous recovery cut is absent"));
        }
        // Audit the immutable initial WAL header independently. No WAL entry,
        // pending intent or tail can be replayed into an asynchronous cut.
        let audit =
            audit_recovery_projected(directory, binding, limits, anchor, false, None, |_| {
                Err(invalid_data("asynchronous root contains a WAL operation"))
            })?;
        if audit.end != CutPosition::initial()
            || audit.cut != 0
            || audit.stage.is_some()
            || audit.history_bytes != 0
            || audit.segments.len() != 1
            || audit
                .segments
                .get(&0)
                .is_none_or(|(_, len)| *len != SEGMENT_HEADER as u64)
        {
            return Err(invalid_data("asynchronous root contains a WAL suffix"));
        }
        return Ok(audit);
    }
    let frozen = anchor.as_ref().and_then(checkpoint::Anchor::native_applied);
    audit_recovery_projected(
        directory,
        binding,
        limits,
        anchor,
        false,
        native.log.committed,
        |operation| native.log.project(operation, &native.business, frozen),
    )
}

impl Opening {
    pub(in crate::sqlite::consensus) fn new(
        directory: &Path,
        binding: Binding,
        roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
        limits: Limits,
        control: IoControl,
    ) -> io::Result<Self> {
        let limits = limits.validate()?;
        if !binding.native || !fs::symlink_metadata(directory)?.is_dir() {
            return Err(invalid_data("native WAL directory or format differs"));
        }
        let directory_pin = owner::pin_directory(directory)?;
        let pinned_path = owner::directory_path(&directory_pin);
        let directory = pinned_path.as_path();
        let lock = file_read(&directory.join("LOCK"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        let conn = cold_basis(directory, binding)?;
        let authority = Authority::load(&conn, binding.identity)?;
        let mut native = from_pristine_basis(&conn, binding, &authority, roster_root.clone())?;
        let mut selected = None;
        let anchor = checkpoint::read(directory, binding, limits)?;
        if binding.persistence == SessionPersistenceMode::Async && anchor.is_none() {
            return Err(invalid_data("asynchronous selected generation is missing"));
        }
        if anchor
            .as_ref()
            .is_some_and(|anchor| anchor.native_snapshots.is_some())
        {
            // No selected state or WAL suffix is usable until the caller admits
            // the retained incoming envelope and supplies its original raw source.
            return Ok(Self {
                directory: directory.to_path_buf(),
                directory_pin,
                binding,
                limits,
                control,
                conn,
                lock,
                native,
                selected: None,
                audit: None,
                pending_origin: anchor,
                roster_root,
            });
        }
        if let Some(anchor) = &anchor {
            let path = anchor.basis_path(directory);
            if let Some(prefix) = anchor.native_prefix()? {
                let cut_binding = anchor.native_cut_binding()?;
                let (append, catalog) = crate::consensus::native::generation::Catalog::open(
                    &path,
                    prefix,
                    MAX_BASIS,
                    binding.identity,
                    &authority.members,
                    roster_root.clone(),
                    cut_binding,
                    &|| Ok(()),
                )?;
                if catalog.identity() != prefix || catalog.cut_binding() != cut_binding {
                    return Err(invalid_data("native selected catalog binding differs"));
                }
                (control.hook)(Point::AfterNativeBasisAdmission)?;
                native = catalog.into_storage(&|| Ok(()))?;
                selected = Some(native_basis::Selected::admitted(append, &native)?);
                // Track the complete unpublished WAL suffix from this exact
                // selected process version, before projecting or replaying it.
                native.begin_changes()?;
            } else {
                if roster_root.is_some() {
                    return Err(invalid_data(
                        "native legacy full image cannot carry a configured roster root",
                    ));
                }
                let source = VerifiedFile::capture(
                    crate::sqlite::open_regular_read_nofollow(&path)?,
                    MAX_BASIS,
                )?;
                if source.length() != anchor.basis_bytes || source.digest() != anchor.basis {
                    return Err(invalid_data(
                        "native selected basis extent or digest differs",
                    ));
                }
                (control.hook)(Point::AfterNativeBasisAdmission)?;
                native = NativeStorage::read_image(
                    &mut io::BufReader::with_capacity(64 * 1024, source.reader()),
                    binding.digest()?,
                    anchor.position.sequence,
                    binding.identity,
                )?;
            }
            if native.business.members() != &authority.members
                || native.business.applied() != anchor.native_applied()
                || native.log.committed != anchor.native_committed()
            {
                return Err(invalid_data(
                    "native selected image pointers differ from selector",
                ));
            }
        }
        let audit = audit_native_recovery(directory, binding, limits, anchor, &mut native)?;
        // The audit sees only complete published cuts. Replay the exact committed
        // prefix before file repair, selection stabilization or owner exposure.
        native.replay_committed()?;
        native.validate_image()?;
        Ok(Self {
            directory: directory.to_path_buf(),
            directory_pin,
            binding,
            limits,
            control,
            conn,
            lock,
            native,
            selected,
            audit: Some(audit),
            pending_origin: None,
            roster_root,
        })
    }

    pub(in crate::sqlite::consensus) fn snapshots(&self) -> Vec<super::super::CurrentSnapshot> {
        match self
            .pending_origin
            .as_ref()
            .and_then(|anchor| anchor.native_snapshots.as_ref())
        {
            Some(snapshots) => snapshots.retained(),
            None => self
                .native
                .business
                .current_snapshot()
                .into_iter()
                .collect(),
        }
    }

    pub(in crate::sqlite::consensus) fn install_candidate(
        &self,
    ) -> Option<super::super::CurrentSnapshot> {
        self.pending_origin
            .as_ref()
            .and_then(|anchor| anchor.native_snapshots.as_ref())
            .map(|snapshots| snapshots.origin.clone())
    }

    fn admit_origin(mut self, source: Option<&snapshot::InstallSource>) -> io::Result<Self> {
        let Some(anchor) = self.pending_origin.take() else {
            return Ok(self);
        };
        let snapshots = anchor
            .native_snapshots
            .as_ref()
            .ok_or_else(|| invalid_data("native recovery source metadata missing"))?;
        let source = source
            .filter(|source| source.candidate() == &snapshots.origin)
            .ok_or_else(|| {
                invalid_data("native recovery requires the exact original incoming source")
            })?;
        let authority = Authority::load(&self.conn, self.binding.identity)?;
        let prefix = anchor
            .native_prefix()?
            .ok_or_else(|| invalid_data("native installed generation missing"))?;
        let path = anchor.basis_path(&self.directory);
        let cut_binding = anchor.native_cut_binding()?;
        let incarnation = crate::consensus::native::generation::Catalog::read_native_incarnation(
            &path,
            prefix,
            MAX_BASIS,
            self.binding.identity,
            &authority.members,
            &|| Ok(()),
        )?;
        let predecessor = cold_basis(&self.directory, self.binding)?;
        let origin = source.apply_native_original(
            &predecessor,
            self.binding,
            self.roster_root.as_deref(),
            &incarnation,
            &|| Ok(()),
        )?;
        drop(predecessor);
        let (append, catalog) = crate::consensus::native::generation::Catalog::open_with_origin(
            &path,
            prefix,
            MAX_BASIS,
            self.binding.identity,
            &authority.members,
            self.roster_root.clone(),
            Some(origin),
            cut_binding,
            &|| Ok(()),
        )?;
        if catalog.identity() != prefix || catalog.cut_binding() != cut_binding {
            return Err(invalid_data("native installed catalog binding differs"));
        }
        (self.control.hook)(Point::AfterNativeBasisAdmission)?;
        self.native = catalog.into_storage(&|| Ok(()))?;
        if self.native.business.members() != &authority.members
            || self.native.business.applied() != anchor.native_applied()
            || self.native.log.committed != anchor.native_committed()
            || self.native.business.current_snapshot().as_ref() != Some(&snapshots.current)
        {
            return Err(invalid_data(
                "native installed image differs from selected source and cut",
            ));
        }
        self.selected = Some(native_basis::Selected::admitted(append, &self.native)?);
        self.native.begin_changes()?;
        self.audit = Some(audit_native_recovery(
            &self.directory,
            self.binding,
            self.limits,
            Some(anchor),
            &mut self.native,
        )?);
        self.native.replay_committed()?;
        self.native.validate_image()?;
        source.verify()?;
        Ok(self)
    }

    pub(in crate::sqlite::consensus) fn finish(
        self,
        verify: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Wal> {
        self.finish_with_install_source(None, verify)
    }

    pub(in crate::sqlite::consensus) fn finish_with_install_source(
        self,
        source: Option<&snapshot::InstallSource>,
        verify: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Wal> {
        let Self {
            directory,
            directory_pin,
            binding,
            limits,
            control,
            conn,
            lock,
            native,
            mut selected,
            audit,
            ..
        } = self.admit_origin(source)?;
        let audit = audit.ok_or_else(|| invalid_data("native recovery audit missing"))?;
        // All referenced strict descriptors are admitted and rechecked before
        // the audit is allowed to repair files or stabilize a selector.
        verify()?;
        if let Some(selected) = &mut selected {
            let anchor = audit
                .anchor
                .as_ref()
                .ok_or_else(|| invalid_data("native admitted generation lacks its selector"))?;
            selected.repair(&anchor.basis_path(&directory), &|| Ok(()))?;
        }
        let (mut disk, history_bytes) = audit.finish(&directory, lock, &control)?;
        let (native, selected, history_bytes) = match selected {
            Some(selected) => (native, selected, history_bytes),
            None => {
                let (native, selected) =
                    native_basis::bootstrap(native, &mut disk, binding, limits, &control)?;
                (native, selected, 0)
            }
        };
        let mut state = State::recovered(
            binding,
            conn,
            history_bytes,
            disk.position(),
            disk.anchor.as_ref(),
            disk.cuts.clone(),
            Some(native),
        )?;
        state.authority.frozen_applied = disk
            .anchor
            .as_ref()
            .and_then(checkpoint::Anchor::native_applied);
        let mut wal = Wal::start_state(binding, limits, state, disk, control, Some(selected))?;
        wal.directory_pin = Some(directory_pin);
        Ok(wal)
    }
}

pub(super) fn open(
    directory: &Path,
    binding: Binding,
    roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
    limits: Limits,
    control: IoControl,
) -> io::Result<Wal> {
    Opening::new(directory, binding, roster_root, limits, control)?.finish(|| Ok(()))
}

/// Only the joined-owner audit below creates this view, while it holds the
/// directory lock and all strict snapshot admissions. Receipt I/O therefore
/// operates on one immutable, completely admitted state outside live State.
pub(crate) struct NativeAudit<'a> {
    state: &'a NativeState,
}

impl std::ops::Deref for NativeAudit<'_> {
    type Target = NativeState;
    fn deref(&self) -> &Self::Target {
        self.state
    }
}

impl NativeAudit<'_> {
    pub(crate) fn status(
        &self,
        request: &crate::FencedTransitionV2Request,
    ) -> io::Result<crate::FencedTransitionV2Status> {
        let reads = self
            .state
            .capture_receipt_reads(std::slice::from_ref(request))?;
        if reads.is_empty() {
            return self
                .state
                .status(request)
                .map_err(|_| invalid_data("native audit receipt status failed"));
        }
        let resolved = reads.resolve(&|| Ok(()))?;
        let copies = resolved.copy_current(self.state)?;
        self.state
            .status_with_receipts(request, &copies)
            .map_err(|_| invalid_data("native audit selected receipt status failed"))
    }
}

impl Wal {
    fn native_operation(&self) -> io::Result<OperationPermit> {
        let mut state = self.wait_for_snapshot(lock_state(&self.shared)?)?;
        if state.snapshot.is_some() || state.native_install_pending {
            return Err(invalid_data("native operation installation is closing"));
        }
        state.native_operations = state
            .native_operations
            .checked_add(1)
            .ok_or_else(|| invalid_data("native operation owner count exhausted"))?;
        Ok(OperationPermit(Arc::clone(&self.shared)))
    }

    pub(in crate::sqlite::consensus) fn create_native(
        directory: &Path,
        basis: &Connection,
        identity: SessionConsensusIdentity,
        generation: [u8; 32],
        limits: Limits,
        control: IoControl,
    ) -> io::Result<Self> {
        Self::create_native_with_root(
            directory, basis, identity, generation, None, limits, control,
        )
    }

    pub(in crate::sqlite::consensus) fn create_native_with_root(
        directory: &Path,
        basis: &Connection,
        identity: SessionConsensusIdentity,
        generation: [u8; 32],
        roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
        limits: Limits,
        control: IoControl,
    ) -> io::Result<Self> {
        Self::create_native_with_persistence(
            directory,
            basis,
            identity,
            generation,
            roster_root,
            limits,
            control,
            SessionPersistenceMode::Durable,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::sqlite::consensus) fn create_native_with_persistence(
        directory: &Path,
        basis: &Connection,
        identity: SessionConsensusIdentity,
        generation: [u8; 32],
        roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
        limits: Limits,
        control: IoControl,
        persistence: SessionPersistenceMode,
    ) -> io::Result<Self> {
        Self::create_with_format(
            directory,
            basis,
            identity,
            generation,
            limits,
            control,
            true,
            roster_root,
            persistence,
        )
    }

    pub(crate) fn is_native(&self) -> bool {
        self.binding.native
    }

    /// Reconstruct only the published durable state after its writer joined.
    /// Keep the strict snapshot admissions alive during the evidence read.
    /// Unlike Opening::finish, this never repairs files or starts a writer.
    pub(crate) fn native_audit_closed<T, P>(
        &self,
        admit_snapshots: impl FnOnce(
            Vec<super::super::CurrentSnapshot>,
            Option<super::super::CurrentSnapshot>,
        ) -> io::Result<P>,
        install_source: impl FnOnce(&P) -> Option<&snapshot::InstallSource>,
        verify: impl Fn(&P) -> io::Result<()>,
        read: impl FnOnce(&NativeAudit<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        let writer = self
            .writer
            .lock()
            .map_err(|_| invalid_data("native audit join owner poisoned"))?;
        if writer.is_some() || lock_state(&self.shared)?.status != Status::Closed {
            return Err(invalid_data("native audit requires a joined closed writer"));
        }
        let opening = Opening::new(
            &self.directory,
            self.binding,
            self.configured_roster_root.clone(),
            self.limits,
            IoControl::default(),
        )?;
        let admitted = admit_snapshots(opening.snapshots(), opening.install_candidate())?;
        let opening = opening.admit_origin(install_source(&admitted))?;
        verify(&admitted)?;
        let result = read(&NativeAudit {
            state: &opening.native.business,
        });
        verify(&admitted)?;
        drop(admitted);
        result
    }

    pub(crate) fn native_snapshot_id(&self) -> io::Result<String> {
        self.with_native_read(|_| {
            Ok(format!(
                "{}{}",
                crate::consensus::native::snapshot_prefix(self.binding.digest()?),
                uuid::Uuid::new_v4()
            ))
        })
    }

    pub(crate) fn native_retained_snapshots(
        &self,
    ) -> io::Result<Vec<super::super::CurrentSnapshot>> {
        self.with_native_read(|native| Ok(native.retained_snapshots()))
    }

    #[cfg(test)]
    pub(in crate::sqlite::consensus) fn native_install_waiting_for_test(&self) -> io::Result<bool> {
        let state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        Ok(state.native_install_pending || state.snapshot.is_some())
    }

    #[cfg(test)]
    pub(crate) fn native_export_snapshot(&self) -> io::Result<Connection> {
        self.native_export(false, None, &|| false)?
            .map(|(conn, _)| conn)
            .ok_or_else(|| invalid_data("uncancelled native export returned no image"))
    }

    pub(crate) fn native_export_snapshot_into(
        &self,
        destination: &crate::consensus::snapshot::PinnedSqliteFile,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<Option<(Connection, super::super::ConsensusAppliedMembership)>> {
        self.native_export(false, Some(destination), cancelled)
    }

    #[cfg(test)]
    pub(crate) fn native_snapshot_publication_pending_for_test(&self) -> io::Result<bool> {
        Ok(lock_state(&self.shared)?.native_snapshot_pending.is_some())
    }

    #[cfg(test)]
    pub(in crate::sqlite::consensus) fn native_export_install_base_for_test(
        &self,
    ) -> io::Result<Connection> {
        self.native_export(true, None, &|| false)?
            .map(|(conn, _)| conn)
            .ok_or_else(|| invalid_data("uncancelled native export returned no image"))
    }

    fn native_export(
        &self,
        install_base: bool,
        destination: Option<&crate::consensus::snapshot::PinnedSqliteFile>,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<Option<(Connection, super::super::ConsensusAppliedMembership)>> {
        let _permit = self.native_operation()?;
        // Bounded immutable root capture. Every file read, row decode and SQL
        // output operation runs on this capture after releasing State.
        let capture = {
            let mut state = lock_state(&self.shared)?;
            ensure_readable(&state)?;
            match state
                .native
                .as_ref()
                .ok_or_else(|| invalid_data("native snapshot owner missing"))?
                .capture_snapshot()
            {
                Ok(capture) => capture,
                Err(error) => {
                    application::record_failure(
                        &mut state,
                        SessionStorageFailure::from_io(
                            SessionStorageFailureStage::SnapshotExport,
                            &error,
                        ),
                    );
                    application::fence(&mut state);
                    self.shared.ready.notify_all();
                    return Err(error);
                }
            }
        };
        let captured_cut = (
            capture.storage.business.applied(),
            capture.storage.business.membership(),
        );
        let conn = self.native_detached_at(SessionStorageFailureStage::SnapshotExport, || {
            let check = || {
                {
                    let state = lock_state(&self.shared)?;
                    ensure_readable(&state)?;
                }
                if cancelled() {
                    return Err(io::Error::other(SnapshotExportCancelled));
                }
                Ok(())
            };
            let export = || -> io::Result<Connection> {
                (self.control.hook)(Point::BeforeNativeSnapshotRead)?;
                check()?;
                let conn = if let Some(destination) = destination {
                    destination.verify_linked_identity()?;
                    let mut conn = super::super::open_pinned_snapshot_database(destination)?;
                    copy_cold_basis(&self.directory, self.binding, &mut conn)?;
                    // Backup can copy the template's journal/page settings.
                    // Restore the original bounded staging policy before the
                    // first receipt insertion into this exact owned inode.
                    conn.pragma_update(None, "query_only", false)
                        .map_err(db_error)?;
                    super::super::disable_snapshot_database_journal_sync(&conn)?;
                    super::super::install_snapshot_database_extent_guard_sync(&conn)?;
                    super::super::verify_pinned_snapshot_descriptor(destination, &conn)?;
                    conn
                } else {
                    cold_basis(&self.directory, self.binding)?
                };
                if install_base {
                    capture
                        .storage
                        .export_cold_install_base_checked(&conn, &check)?;
                } else {
                    capture
                        .storage
                        .export_cold_snapshot_checked(&conn, &check)?;
                }
                if let Some(destination) = destination {
                    super::super::snapshot_database_extent_sync(&conn)?;
                    super::super::verify_pinned_snapshot_descriptor(destination, &conn)?;
                    destination.verify_linked_identity()?;
                }
                check()?;
                Ok(conn)
            };
            match export() {
                Ok(conn) => Ok(Some(conn)),
                Err(error)
                    if error
                        .get_ref()
                        .is_some_and(|cause| cause.is::<SnapshotExportCancelled>()) =>
                {
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        })?;
        let mut state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        if let Err(error) = capture.require_current_authority(
            state
                .native
                .as_ref()
                .ok_or_else(|| invalid_data("native snapshot owner missing"))?,
        ) {
            application::fence(&mut state);
            self.shared.ready.notify_all();
            return Err(error);
        }
        Ok(conn.map(|conn| (conn, captured_cut)))
    }

    pub(crate) fn native_publish_snapshot(
        &self,
        candidate: super::super::CurrentSnapshot,
    ) -> io::Result<()> {
        let mut state = self.wait_for_snapshot(lock_state(&self.shared)?)?;
        ensure_readable(&state)?;
        if state.status != Status::Running
            || state.native_snapshot_pending.is_some()
            || state.snapshot.is_some()
        {
            return Err(invalid_data("native snapshot publisher unavailable"));
        }
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native snapshot publisher missing"))?;
        native.validate_snapshot(&candidate)?;
        if !candidate
            .0
            .snapshot_id
            .starts_with(&crate::consensus::native::snapshot_prefix(
                self.binding.digest()?,
            ))
        {
            return Err(invalid_data("native snapshot generation differs"));
        }
        #[cfg(feature = "test-control")]
        if state.volatile_experiment.is_some() {
            // The original snapshot worker already wrote and authenticated the
            // fs-verity candidate. Publish its validated resident metadata here;
            // no WAL drain, CURRENT selection or disk wait owns this mutex.
            state
                .native
                .as_mut()
                .ok_or_else(|| invalid_data("volatile snapshot owner missing"))?
                .business
                .set_current_snapshot(candidate.clone())?;
            state.authority.frozen_applied = candidate.0.last_log_id;
            volatile_experiment::snapshot_published(&mut state);
            self.shared.ready.notify_all();
            return Ok(());
        }
        state.native_snapshot_pending = Some(candidate.clone());
        state.checkpoint_requested = true;
        async_persistence::dirty(&mut state);
        self.shared.ready.notify_all();
        while state
            .native
            .as_ref()
            .and_then(|native| native.business.current_snapshot())
            .as_ref()
            != Some(&candidate)
        {
            if state.status != Status::Running
                || state
                    .asynchronous
                    .as_ref()
                    .is_some_and(|progress| progress.failure.is_some())
            {
                return Err(invalid_data("native snapshot publication failed"));
            }
            state = self
                .shared
                .ready
                .wait(state)
                .map_err(|_| io::Error::other("native snapshot publication wait poisoned"))?;
        }
        ensure_readable(&state)?;
        if state
            .native
            .as_ref()
            .and_then(|native| native.business.current_snapshot())
            .as_ref()
            != Some(&candidate)
        {
            return Err(invalid_data("native selected snapshot readback differs"));
        }
        Ok(())
    }

    pub(crate) fn reject_native_sql_fallback<T>(&self) -> io::Result<T> {
        let mut state = lock_state(&self.shared)?;
        state.native_sql_fallbacks = state.native_sql_fallbacks.saturating_add(1);
        Err(invalid_data("native owner rejects a live SQL fallback"))
    }

    pub(crate) fn native_sql_fallback_count(&self) -> io::Result<u64> {
        let state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        Ok(state.native_sql_fallbacks)
    }

    pub(crate) fn native_fixed_scope_snapshot(
        &self,
        identity: SessionConsensusIdentity,
    ) -> io::Result<(
        ConsensusAuthorityProfile,
        Option<PlacementResiliencePolicy>,
        super::super::MembershipValidationScope,
        opc_consensus::engine::StoredMembership<
            SessionConsensusNodeId,
            opc_consensus::engine::EmptyNode,
        >,
    )> {
        let state = lock_state(&self.shared)?;
        ensure_native_public_owner(&state)?;
        let native = state
            .native
            .as_ref()
            .filter(|native| native.business.identity() == identity)
            .ok_or_else(|| invalid_data("native fixed scope identity differs"))?;
        Ok((
            state.authority.profile,
            state.authority.placement,
            state.authority.scope.clone(),
            native.business.membership(),
        ))
    }

    pub(crate) fn native_fixed_read<T>(
        &self,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        placement: PlacementResiliencePolicy,
        pristine: bool,
        database_path: Option<&Path>,
        read: impl FnOnce(&NativeState, bool) -> io::Result<T>,
    ) -> io::Result<T> {
        let state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        let exact = self.native_fixed_exact(
            &state,
            identity,
            members,
            bindings,
            placement,
            pristine,
            database_path,
        )?;
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native authority owner missing"))?;
        read(&native.business, exact)
    }

    fn native_fixed_exact(
        &self,
        state: &State,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        placement: PlacementResiliencePolicy,
        pristine: bool,
        database_path: Option<&Path>,
    ) -> io::Result<bool> {
        ensure_native_public_owner(state)?;
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native authority owner missing"))?;
        // The private native slice admits only a pristine recovery state.
        // Re-read its filesystem latch on every application authority check;
        // a terminal or active latch requires the later native recovery path.
        if let Some(path) = database_path {
            if super::super::read_operator_recovery_latch_sync(path)?.is_some() {
                return Err(invalid_data("native application recovery latch is active"));
            }
        }
        let scope = &state.authority.scope;
        let membership = native.business.membership();
        Ok(
            state.authority.profile == ConsensusAuthorityProfile::FixedImmutable
                && self.binding.identity == identity
                && native.business.identity() == identity
                && &state.authority.members == members
                && &state.authority.bindings == bindings
                && state.authority.placement == Some(placement)
                && scope.current_identity == identity
                && &scope.current_members == members
                && &scope.current_bindings == bindings
                && scope.application_authority_epoch == identity.configuration_epoch()
                && &scope.application_authority_members == members
                && scope.predecessor.is_none()
                && scope.history.is_empty()
                && scope.terminal_history.is_empty()
                && scope.pending.is_none()
                && scope.terminal.is_none()
                && (membership.log_id().is_some() || pristine),
        )
    }

    pub(crate) fn native_fixed_receipt_read<T>(
        &self,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        placement: PlacementResiliencePolicy,
        pristine: bool,
        database_path: Option<&Path>,
        requests: &[crate::FencedTransitionV2Request],
        read: impl FnOnce(&NativeState, bool, Option<&ReceiptCopies>) -> io::Result<T>,
    ) -> io::Result<T> {
        self.native_receipt_read(
            requests,
            |state| {
                self.native_fixed_exact(
                    state,
                    identity,
                    members,
                    bindings,
                    placement,
                    pristine,
                    database_path,
                )
            },
            read,
        )
    }

    pub(crate) fn with_native_receipt_read<T>(
        &self,
        requests: &[crate::FencedTransitionV2Request],
        read: impl FnOnce(&NativeState, Option<&ReceiptCopies>) -> io::Result<T>,
    ) -> io::Result<T> {
        self.native_receipt_read(requests, ensure_readable, |state, (), receipts| {
            read(state, receipts)
        })
    }

    pub(crate) fn with_native_public_receipt_read<T>(
        &self,
        requests: &[crate::FencedTransitionV2Request],
        read: impl FnOnce(&NativeState, Option<&ReceiptCopies>) -> io::Result<T>,
    ) -> io::Result<T> {
        self.native_receipt_read(
            requests,
            ensure_native_public_owner,
            |state, (), receipts| read(state, receipts),
        )
    }

    fn native_detached<T>(&self, work: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        self.native_detached_at(SessionStorageFailureStage::Storage, work)
    }

    fn native_detached_at<T>(
        &self,
        stage: SessionStorageFailureStage,
        work: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        // State has already been released. Keep all captures and decoder
        // guards inside this unwind boundary, then fence the existing owner
        // and wake queue retirement before propagating the original panic.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
        let failure = match &result {
            Ok(Err(error)) => Some(SessionStorageFailure::from_io(stage, error)),
            Err(_) => Some(SessionStorageFailure::panic(stage)),
            Ok(Ok(_)) => None,
        };
        if let Some(failure) = failure {
            let mut state = match self.shared.state.lock() {
                Ok(state) => state,
                Err(poison) => poison.into_inner(),
            };
            application::record_failure(&mut state, failure);
            application::fence(&mut state);
            self.shared.ready.notify_all();
        }
        match result {
            Ok(resolved) => resolved,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn native_resolve_receipts(
        &self,
        reads: ReceiptReads,
        previous: Option<ResolvedReceipts>,
    ) -> io::Result<ResolvedReceipts> {
        self.native_detached(|| {
            (self.control.hook)(Point::BeforeNativeReceiptRead)?;
            let additional = reads.resolve(&|| {
                let state = lock_state(&self.shared)?;
                ensure_readable(&state)
            })?;
            match previous {
                Some(mut previous) => {
                    previous.extend(additional)?;
                    Ok(previous)
                }
                None => Ok(additional),
            }
        })
    }

    fn native_receipt_read<T, C>(
        &self,
        requests: &[crate::FencedTransitionV2Request],
        validate: impl Fn(&State) -> io::Result<C>,
        read: impl FnOnce(&NativeState, C, Option<&ReceiptCopies>) -> io::Result<T>,
    ) -> io::Result<T> {
        let _permit = self.native_operation()?;
        let mut state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        let context = validate(&state)?;
        let captured = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native receipt owner missing"))?
            .business
            .capture_receipt_reads(requests);
        let reads = match captured {
            Ok(reads) => reads,
            Err(error) => {
                application::fence(&mut state);
                self.shared.ready.notify_all();
                return Err(error);
            }
        };
        if reads.is_empty() {
            return read(
                &state
                    .native
                    .as_ref()
                    .ok_or_else(|| invalid_data("native receipt owner missing"))?
                    .business,
                context,
                None,
            );
        }
        drop(state);
        let mut resolved = self.native_resolve_receipts(reads, None)?;
        loop {
            let mut state = lock_state(&self.shared)?;
            ensure_readable(&state)?;
            // The complete live predicate, including Recovery, runs again
            // after each detached pass. Missing IDs can bind and relocate
            // during that pass; capture those exact current revisions before
            // deciding the entire cohort under this one final State guard.
            let context = validate(&state)?;
            let missing = resolved.capture_missing(
                &state
                    .native
                    .as_ref()
                    .ok_or_else(|| invalid_data("native receipt owner missing"))?
                    .business,
                requests,
            );
            let missing = match missing {
                Ok(missing) => missing,
                Err(error) => {
                    application::fence(&mut state);
                    self.shared.ready.notify_all();
                    return Err(error);
                }
            };
            if !missing.is_empty() {
                drop(state);
                resolved = self.native_resolve_receipts(missing, Some(resolved))?;
                continue;
            }
            let copied = resolved.copy_current(
                &state
                    .native
                    .as_ref()
                    .ok_or_else(|| invalid_data("native receipt owner missing"))?
                    .business,
            );
            let copies = match copied {
                Ok(copies) => copies,
                Err(error) => {
                    application::fence(&mut state);
                    self.shared.ready.notify_all();
                    return Err(error);
                }
            };
            return read(
                &state
                    .native
                    .as_ref()
                    .ok_or_else(|| invalid_data("native receipt owner missing"))?
                    .business,
                context,
                Some(&copies),
            );
        }
    }

    pub(crate) fn with_native_read<T>(
        &self,
        read: impl FnOnce(&NativeState) -> io::Result<T>,
    ) -> io::Result<T> {
        let state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native read owner missing"))?;
        read(&native.business)
    }

    /// Public scalar reads linearize under State and require the live owner.
    /// Internal inspection may still use with_native_read after joining.
    pub(crate) fn native_public_scalar_read<T>(
        &self,
        read: impl FnOnce(&NativeState) -> io::Result<T>,
    ) -> io::Result<T> {
        let state = lock_state(&self.shared)?;
        ensure_native_public_owner(&state)?;
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native read owner missing"))?;
        read(&native.business)
    }

    /// Linearize at an immutable capture after the caller's quorum barrier.
    /// Install drains the permit; unrelated application can advance while
    /// the worker verifies selected rows. No SQL or carrier work holds State.
    pub(crate) fn native_public_read<T>(
        &self,
        check: &dyn Fn() -> io::Result<()>,
        read: impl FnOnce(&NativeState, &dyn Fn() -> io::Result<()>) -> Result<T, crate::StoreError>,
    ) -> io::Result<Result<T, crate::StoreError>> {
        let require_owner = ensure_native_public_owner;
        check()?;
        let _permit = {
            let mut state = lock_state(&self.shared)?;
            while (state.snapshot.is_some() || state.native_install_pending)
                && state.status == Status::Running
            {
                check()?;
                (state, _) = self
                    .shared
                    .ready
                    .wait_timeout(state, Duration::from_millis(20))
                    .map_err(|_| io::Error::other("native public read admission poisoned"))?;
            }
            check()?;
            require_owner(&state)?;
            if state.snapshot.is_some() || state.native_install_pending {
                return Err(invalid_data("native public read installation is closing"));
            }
            state.native_operations = state
                .native_operations
                .checked_add(1)
                .ok_or_else(|| invalid_data("native public read count exhausted"))?;
            OperationPermit(Arc::clone(&self.shared))
        };
        let capture = {
            let state = lock_state(&self.shared)?;
            require_owner(&state)?;
            state
                .native
                .as_ref()
                .ok_or_else(|| invalid_data("native public read owner missing"))?
                .capture_snapshot()?
        };
        let check_owner = || {
            check()?;
            let state = lock_state(&self.shared)?;
            require_owner(&state)
        };
        check_owner()?;
        let result = self.native_detached(|| {
            (self.control.hook)(Point::BeforeNativePublicRead)?;
            Ok(match check_owner() {
                Ok(()) => read(&capture.storage.business, &check_owner),
                Err(_) => Err(crate::StoreError::BackendUnavailable(
                    "native session state is unavailable".into(),
                )),
            })
        })?;
        check()?;
        let state = lock_state(&self.shared)?;
        require_owner(&state)?;
        capture.require_current_authority(
            state
                .native
                .as_ref()
                .ok_or_else(|| invalid_data("native public read owner missing"))?,
        )?;
        Ok(result)
    }

    pub(crate) fn native_apply_committed(
        &self,
        entries: &[Entry<SessionRaftTypeConfig>],
    ) -> io::Result<super::super::AppliedBatch> {
        let started = Instant::now();
        let _permit = self.native_operation()?;
        let mut lock_wait = Duration::ZERO;
        let mut preflight = Duration::ZERO;
        let mut apply = Duration::ZERO;
        loop {
            let waiting = Instant::now();
            let mut state = lock_state(&self.shared)?;
            lock_wait += waiting.elapsed();
            ensure_native_application_owner(&state)?;
            let checking = Instant::now();
            let captured: io::Result<ApplicationCapture> = (|| {
                let native = state
                    .native
                    .as_ref()
                    .ok_or_else(|| invalid_data("native application owner missing"))?;
                native.log.require_committed_entries(
                    &native.business,
                    state.committed_for_application(),
                    entries,
                )?;
                native.business.capture_application()
            })();
            preflight += checking.elapsed();
            let captured = match captured {
                Ok(captured) => captured,
                Err(error) => {
                    application::fence(&mut state);
                    self.shared.ready.notify_all();
                    return Err(error);
                }
            };
            drop(state);
            let preparing = Instant::now();
            let prepared = self.native_detached(move || {
                (self.control.hook)(Point::BeforeNativeApplyPrepare)?;
                let prepared = captured.prepare(
                    entries,
                    &|| {
                        let state = lock_state(&self.shared)?;
                        ensure_native_application_owner(&state)
                    },
                    || (self.control.hook)(Point::BeforeNativeReceiptRead),
                )?;
                (self.control.hook)(Point::BeforeNativeApplyPublish)?;
                Ok(prepared)
            })?;
            apply += preparing.elapsed();
            let waiting = Instant::now();
            let mut state = lock_state(&self.shared)?;
            lock_wait += waiting.elapsed();
            ensure_native_application_owner(&state)?;
            let checking = Instant::now();
            let current = (|| {
                let native = state
                    .native
                    .as_ref()
                    .ok_or_else(|| invalid_data("native application owner missing"))?;
                // The durable cut and complete exact input are checked again
                // on every pass, including metadata-only predecessor retries.
                native.log.require_committed_entries(
                    &native.business,
                    state.committed_for_application(),
                    entries,
                )?;
                prepared.is_current(&native.business)
            })();
            preflight += checking.elapsed();
            let current = match current {
                Ok(current) => current,
                Err(error) => {
                    application::fence(&mut state);
                    self.shared.ready.notify_all();
                    return Err(error);
                }
            };
            if !current {
                // Snapshot selection or initial tracking may advance while
                // preparation runs. Discard detached work outside State and
                // capture that valid new predecessor without fencing it.
                drop(state);
                drop(prepared);
                continue;
            }
            let publishing = Instant::now();
            let result = prepared.publish(
                &mut state
                    .native
                    .as_mut()
                    .ok_or_else(|| invalid_data("native application owner missing"))?
                    .business,
            );
            apply += publishing.elapsed();
            let applied = match result {
                Ok(applied) => applied,
                Err(error) => {
                    application::fence(&mut state);
                    self.shared.ready.notify_all();
                    return Err(error);
                }
            };
            #[cfg(feature = "test-control")]
            if state.volatile_experiment.is_some() {
                volatile_experiment::dirty(&mut state);
                self.shared.ready.notify_all();
            }
            if state.asynchronous.is_some() {
                async_persistence::dirty(&mut state);
                self.shared.ready.notify_all();
            }
            state.application_costs.lock_wait += lock_wait;
            state.application_costs.preflight += preflight;
            state.application_costs.native_apply += apply;
            state.application_costs.total += started.elapsed();
            if !entries.is_empty() {
                state.application_costs.successful_nonempty_batches += 1;
                state.application_costs.entries += entries.len() as u64;
            }
            return Ok(super::super::AppliedBatch {
                responses: applied.responses,
                notifications: applied.notifications,
            });
        }
    }

    pub(crate) fn native_log_read(
        &self,
        start: u64,
        end: Option<u64>,
        limit: Option<usize>,
    ) -> io::Result<Vec<Entry<SessionRaftTypeConfig>>> {
        let _permit = self.native_operation()?;
        let mut state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        let capture = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native log owner missing"))?
            .capture_log_read();
        let capture = match capture {
            Ok(capture) => capture,
            Err(error) => {
                application::fence(&mut state);
                self.shared.ready.notify_all();
                return Err(error);
            }
        };
        drop(state);
        // This immutable range linearizes at capture. A concurrent valid
        // truncation/reappend does not require retry or invalidate its rows.
        let rows = self.native_detached(|| {
            (self.control.hook)(Point::BeforeNativeLogRead)?;
            capture.resolve(start, end, limit, &|| {
                let state = lock_state(&self.shared)?;
                ensure_readable(&state)
            })
        })?;
        let mut state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        if let Err(error) = capture.require_current_authority(
            state
                .native
                .as_ref()
                .ok_or_else(|| invalid_data("native log owner missing"))?,
        ) {
            application::fence(&mut state);
            self.shared.ready.notify_all();
            return Err(error);
        }
        Ok(rows.into_entries())
    }

    pub(crate) fn native_log_state(
        &self,
    ) -> io::Result<opc_consensus::engine::LogState<SessionRaftTypeConfig>> {
        let state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native log owner missing"))?;
        Ok(opc_consensus::engine::LogState {
            last_purged_log_id: native.log.purged,
            last_log_id: native.log.last(),
        })
    }
}
