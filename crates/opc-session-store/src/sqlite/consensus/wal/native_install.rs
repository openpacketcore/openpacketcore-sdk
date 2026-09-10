//! One native install handoff under the sole WAL writer. The complete original
//! transaction runs on a disposable predecessor, then a new base is streamed,
//! synced and independently admitted. CURRENT precedes resident replacement
//! and reclamation. No live SQL cache participates in native authority.

use super::*;
use crate::consensus::native::generation::{Catalog, SqlitePreparedBase, Version};
use crate::consensus::verified_snapshot::VerificationMemory;

impl Wal {
    pub(in crate::sqlite::consensus::wal::snapshot) fn native_install_snapshot(
        &self,
        installation: Arc<Installation>,
    ) -> io::Result<()> {
        let mut owner = HandoffOwner {
            shared: Arc::clone(&self.shared),
            completed: true,
        };
        let result =
            (|| {
                let mut state = lock_state(&self.shared)?;
                while (state.native_install_pending || state.snapshot.is_some())
                    && state.status == Status::Running
                {
                    state =
                        self.shared.ready.wait(state).map_err(|_| {
                            io::Error::other("native install ownership wait poisoned")
                        })?;
                }
                if state.status != Status::Running {
                    return Err(invalid_data("native install owner is fenced"));
                }
                owner.completed = false;
                state.native_install_pending = true;
                self.shared.ready.notify_all();
                while state.native_operations != 0
                    || state.native_basis_active
                    || state.native_basis_ready
                    || state.native_relocations_pending
                    || state.native_snapshot_pending.is_some()
                    || state.native_checkpoint_target.is_some()
                    || state.checkpoint_requested
                    || state
                        .asynchronous
                        .as_ref()
                        .is_some_and(|progress| !progress.caught_up())
                {
                    if state.status != Status::Running
                        || state
                            .asynchronous
                            .as_ref()
                            .is_some_and(|progress| progress.failure.is_some())
                    {
                        return Err(invalid_data("native install predecessor drain failed"));
                    }
                    state = self.shared.ready.wait(state).map_err(|_| {
                        io::Error::other("native install predecessor wait poisoned")
                    })?;
                }
                if state.status != Status::Running {
                    return Err(invalid_data("native install owner closed during drain"));
                }
                state.snapshot = Some(Handoff {
                    candidate: installation.source.candidate.clone(),
                    transform: Transform::Install,
                    installation: Some(Arc::clone(&installation)),
                    phase: Phase::Requested,
                });
                state.native_install_pending = false;
                self.shared.ready.notify_all();
                while state.snapshot.is_some() && state.status == Status::Running {
                    state = self.shared.ready.wait(state).map_err(|_| {
                        io::Error::other("native install publication wait poisoned")
                    })?;
                }
                if state.status != Status::Running {
                    return Err(invalid_data("native install publication failed"));
                }
                Ok(())
            })();
        if result.is_ok() {
            owner.completed = true;
        }
        result
    }
}

fn require_live(
    state: &State,
    disk: &Disk,
    old: &checkpoint::Anchor,
    installation: &Arc<Installation>,
    version: &Version,
) -> io::Result<()> {
    ensure_readable(state)?;
    let handoff = state
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid_data("native install handoff disappeared"))?;
    if state.status != Status::Running
        || state.outstanding != 0
        || !state.queue.is_empty()
        || state.sequence
            != if state.asynchronous.is_some() {
                old.native_sequence()
            } else {
                disk.sequence
            }
        || state.native_operations != 0
        || state.native_install_pending
        || state.native_basis_active
        || state.native_basis_ready
        || state.native_relocations_pending
        || state.native_snapshot_pending.is_some()
        || state.native_checkpoint_target.is_some()
        || state.checkpoint_requested
        || state.application_marker.is_some()
        || state.checkpoint_epoch != old.epoch
        || state.base_sequence != old.native_sequence()
        || disk.anchor.as_ref() != Some(old)
        || handoff.transform != Transform::Install
        || !matches!(handoff.phase, Phase::Requested)
        || handoff.candidate != installation.source.candidate
        || !handoff
            .installation
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, installation))
    {
        return Err(invalid_data(
            "native installation no longer owns its drained predecessor",
        ));
    }
    let native = state
        .native
        .as_ref()
        .ok_or_else(|| invalid_data("native install resident owner missing"))?;
    if let Some(progress) = &state.asynchronous {
        if !progress.caught_up()
            || progress.failure.is_some()
            || Some(progress.completed) != old.async_cut
            || progress.completed.sequence != state.sequence
            || progress.completed.committed != native.log.committed
            || progress.completed.applied != native.business.applied()
        {
            return Err(invalid_data("asynchronous install predecessor cut differs"));
        }
        return version.require_current(native);
    }
    let cut = state
        .durable_cuts
        .get(&disk.sequence)
        .filter(|cut| {
            cut.chain == disk.chain
                && cut.committed == state.durable_committed
                && cut.committed == native.log.committed
        })
        .ok_or_else(|| invalid_data("native install durable predecessor cut differs"))?;
    if disk.cuts.get(&disk.sequence) != Some(cut) {
        return Err(invalid_data("native install disk and resident cuts differ"));
    }
    version.require_current(native)
}

pub(in crate::sqlite::consensus::wal) fn advance(
    shared: &Arc<Shared>,
    disk: &mut Disk,
    basis: &mut native_basis::Owner,
    binding: Binding,
    limits: Limits,
    control: &IoControl,
) -> io::Result<()> {
    let result = advance_inner(shared, disk, basis, binding, limits, control);
    if let Err(error) = &result {
        let mut state = lock_state(shared)?;
        application::record_failure(
            &mut state,
            SessionStorageFailure::from_io(SessionStorageFailureStage::SnapshotInstall, error),
        );
        application::fence(&mut state);
        shared.ready.notify_all();
    }
    result
}

fn advance_inner(
    shared: &Arc<Shared>,
    disk: &mut Disk,
    basis: &mut native_basis::Owner,
    binding: Binding,
    limits: Limits,
    control: &IoControl,
) -> io::Result<()> {
    let started = Instant::now();
    let _memory = VerificationMemory::reserve(256 * 1024)?;
    let old = disk
        .anchor
        .clone()
        .ok_or_else(|| invalid_data("native install selected predecessor absent"))?;
    basis.require_install_owner(&old)?;
    let (installation, capture, version) = {
        let state = lock_state(shared)?;
        let installation = Arc::clone(
            state
                .snapshot
                .as_ref()
                .and_then(|handoff| handoff.installation.as_ref())
                .ok_or_else(|| invalid_data("native install original source absent"))?,
        );
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("native install state absent"))?;
        let version = Version::capture(native)?;
        require_live(&state, disk, &old, &installation, &version)?;
        (installation, native.capture_snapshot()?, version)
    };
    let check = || {
        let state = lock_state(shared)?;
        require_live(&state, disk, &old, &installation, &version)
    };
    installation.source.verify()?;
    let mut conn = native::cold_basis(&disk.directory, binding)?;
    capture
        .storage
        .export_cold_install_base_checked(&conn, &check)?;
    let root = capture.storage.business.roster_root().cloned();
    let members = capture.storage.business.members().clone();
    drop(capture);
    let origin = installation.source.apply_native_original(
        &conn,
        binding,
        root.as_deref(),
        &installation.incarnation,
        &check,
    )?;
    let authority = Authority::load(&conn, binding.identity)?;
    let placement = authority
        .placement
        .ok_or_else(|| invalid_data("native install fixed placement missing"))?;
    let epoch = old
        .epoch
        .checked_add(1)
        .filter(|epoch| *epoch != u64::MAX)
        .ok_or_else(|| invalid_data("native install checkpoint epoch exhausted"))?;
    let file_epoch = old
        .file_epoch()
        .checked_add(1)
        .filter(|epoch| *epoch != u64::MAX)
        .ok_or_else(|| invalid_data("native install file epoch exhausted"))?;
    let position = disk.position();
    let candidate = &installation.source.candidate;
    let cut = DurableCut {
        chain: position.chain,
        committed: candidate.0.last_log_id,
        installed: Some(InstalledCut::new(epoch, candidate)?),
    };
    let async_cut = old
        .async_cut
        .map(|previous| {
            Ok::<_, io::Error>(checkpoint::AsyncCut {
                generation: previous
                    .generation
                    .checked_add(1)
                    .filter(|generation| *generation != u64::MAX)
                    .ok_or_else(|| invalid_data("asynchronous install generation exhausted"))?,
                sequence: previous.sequence,
                committed: candidate.0.last_log_id,
                applied: candidate.0.last_log_id,
            })
        })
        .transpose()?;
    let mut anchor = checkpoint::Anchor {
        root: binding.digest()?,
        epoch,
        basis: [0; 32],
        basis_bytes: 64 * 1024,
        position,
        cut: disk.cut,
        cut_chain: disk.cut_chain,
        prefix: checkpoint::hash_prefix(
            &disk
                .directory
                .join(format!("segment-{:020}.wal", position.segment)),
            position.offset,
        )?,
        applied: if async_cut.is_some() {
            None
        } else {
            candidate.0.last_log_id
        },
        marker: None,
        cuts: if async_cut.is_some() {
            old.cuts.clone()
        } else {
            BTreeMap::from([(position.sequence, cut)])
        },
        native: true,
        native_generation: Some(checkpoint::NativeGeneration {
            file_epoch,
            block_bytes: 64 * 1024,
            frontiers: [0; 32],
        }),
        native_snapshots: Some(checkpoint::NativeSnapshots {
            origin: candidate.clone(),
            current: candidate.clone(),
        }),
        async_cut,
    };
    let cut_binding = anchor.native_cut_binding()?;
    let preparing = disk
        .directory
        .join(format!("basis-{file_epoch:020}.preparing"));
    let final_path = anchor.basis_path(&disk.directory);
    check()?;
    (control.hook)(Point::BeforeBasisCreate)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&preparing)?;
    (control.hook)(Point::AfterBasisCreate)?;
    let prefix = {
        let prepared = SqlitePreparedBase::prepare_with_origin(
            &mut conn,
            binding.identity,
            &members,
            &authority.bindings,
            placement,
            root.as_deref(),
            Some(Arc::clone(&origin)),
            binding.digest()?,
            file_epoch,
            epoch,
            anchor.native_sequence(),
            cut_binding,
            64 * 1024,
            MAX_BASIS,
            &check,
        )?;
        let mut output = io::BufWriter::with_capacity(64 * 1024, &mut file);
        let prefix = prepared.write_to(&mut output, &check)?;
        output.flush()?;
        prefix
    };
    (control.hook)(Point::BeforeBasisSync)?;
    file.sync_all()?;
    (control.hook)(Point::AfterBasisSync)?;
    drop(file);
    drop(conn);
    anchor.basis = prefix.digest;
    anchor.basis_bytes = prefix.length;
    anchor.native_generation = Some(checkpoint::NativeGeneration {
        file_epoch,
        block_bytes: prefix.block_bytes,
        frontiers: prefix.frontiers,
    });
    anchor.validate(binding, limits)?;
    crate::consensus::snapshot::rename_noreplace_in_directory(
        &File::open(&disk.directory)?,
        preparing
            .file_name()
            .ok_or_else(|| invalid_data("native install preparation name absent"))?,
        final_path
            .file_name()
            .ok_or_else(|| invalid_data("native install final name absent"))?,
    )?;
    (control.hook)(Point::AfterBasisRename)?;
    File::open(&disk.directory)?.sync_all()?;
    (control.hook)(Point::AfterBasisDirectorySync)?;
    let (append, catalog) = Catalog::open_with_origin(
        &final_path,
        prefix,
        MAX_BASIS,
        binding.identity,
        &members,
        root,
        Some(origin),
        cut_binding,
        &check,
    )?;
    if catalog.identity() != prefix || catalog.cut_binding() != cut_binding {
        return Err(invalid_data("native install complete catalog differs"));
    }
    (control.hook)(Point::AfterNativeBasisAdmission)?;
    let mut native = catalog.into_storage(&check)?;
    let mut selected = native_basis::Selected::admitted(append, &native)?;
    selected.repair(&final_path, &check)?;
    native.begin_changes()?;
    installation.source.verify()?;
    check()?;
    checkpoint::select(&disk.directory, &anchor, control)?;
    installation.source.verify()?;
    check()?;
    // All fallible predecessor checks finish before replacing the resident
    // roots. Admissions remain held until durable reclamation also completes.
    let (retired, old_selected) = {
        let mut state = lock_state(shared)?;
        require_live(&state, disk, &old, &installation, &version)?;
        let old_selected = basis.replace_for_install(&old, selected)?;
        let retired = state.native.replace(native);
        state.base_sequence = anchor.native_sequence();
        state.history_bytes = 0;
        state.checkpoint_epoch = epoch;
        state.durable_committed = candidate.0.last_log_id;
        state.durable_cuts = anchor.cuts.clone();
        state.authority.frozen_applied = candidate.0.last_log_id;
        if let Some(progress) = &mut state.asynchronous {
            let cut = anchor
                .async_cut
                .ok_or_else(|| invalid_data("asynchronous installed selection is absent"))?;
            progress.generation = cut.generation;
            progress.completed(cut, anchor.basis_bytes);
        }
        disk.cuts = anchor.cuts.clone();
        disk.anchor = Some(anchor.clone());
        (retired, old_selected)
    };
    drop(retired);
    drop(old_selected);
    checkpoint::reclaim_covered(disk, &anchor, control)?;
    installation.source.verify()?;
    let retired_handoff = {
        let mut state = lock_state(shared)?;
        ensure_readable(&state)?;
        if state.status != Status::Running
            || disk.anchor.as_ref() != Some(&anchor)
            || !state
                .snapshot
                .as_ref()
                .and_then(|handoff| handoff.installation.as_ref())
                .is_some_and(|current| Arc::ptr_eq(current, &installation))
        {
            return Err(invalid_data("native install completion owner differs"));
        }
        let elapsed = started.elapsed();
        state.checkpoint_costs.completed += 1;
        state.checkpoint_costs.elapsed += elapsed;
        state.checkpoint_costs.maximum = state.checkpoint_costs.maximum.max(elapsed);
        state.checkpoint_costs.native_basis_count += 1;
        state.checkpoint_costs.native_basis_bytes += prefix.length;
        state.snapshot.take()
    };
    drop(retired_handoff);
    shared.ready.notify_all();
    Ok(())
}
