//! A complete, selected basis replaces an acknowledged WAL prefix. Selection
//! becomes durable before a single covered file is reclaimed. The root binding
//! and operation sequence do not change, including application-marker lineage.

use super::*;

pub(super) const SELECTOR_LIMIT: u64 = 8192;
const SELECTOR_MAGIC: &[u8; 8] = b"OPCWBAS1";

/// An append generation has one physical file and many logical checkpoints.
/// All fields are persisted comparisons; cold admission creates the actual
/// prefix owner. Older selectors omit this field and retain their exact wire
/// encoding and full-image interpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeGeneration {
    pub(super) file_epoch: u64,
    pub(super) block_bytes: usize,
    pub(super) frontiers: [u8; 32],
}

/// Retain the incoming origin after later locally produced snapshots replace
/// the current export. These comparisons grant no authority until the opener
/// re-runs the original installer on that independently admitted origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeSnapshots {
    pub(super) origin: super::super::CurrentSnapshot,
    pub(super) current: super::super::CurrentSnapshot,
}

impl NativeSnapshots {
    fn validate(&self) -> io::Result<()> {
        for candidate in [&self.origin, &self.current] {
            let _memory = crate::consensus::native::generation::reserve_install_metadata(
                candidate,
                Path::new(&candidate.1),
            )?;
        }
        if self.origin.1 == self.current.1 && self.origin != self.current {
            return Err(invalid_data(
                "native retained snapshot name has conflicting metadata",
            ));
        }
        Ok(())
    }

    pub(super) fn retained(&self) -> Vec<super::super::CurrentSnapshot> {
        if self.origin == self.current {
            vec![self.origin.clone()]
        } else {
            vec![self.origin.clone(), self.current.clone()]
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Anchor {
    pub(super) root: [u8; 32],
    pub(super) epoch: u64,
    pub(super) basis: [u8; 32],
    pub(super) basis_bytes: u64,
    pub(super) position: CutPosition,
    pub(super) cut: u64,
    pub(super) cut_chain: [u8; 32],
    pub(super) prefix: [u8; 32],
    pub(super) applied: Option<LogId<SessionConsensusNodeId>>,
    pub(super) marker: Option<application::Marker>,
    pub(super) cuts: BTreeMap<u64, DurableCut>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) native: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) native_generation: Option<NativeGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) native_snapshots: Option<NativeSnapshots>,
}

impl Anchor {
    fn encode(&self) -> io::Result<Vec<u8>> {
        let mut bytes = SELECTOR_MAGIC.to_vec();
        bytes.extend_from_slice(&encode_json(self)?);
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        if bytes.len() as u64 > SELECTOR_LIMIT {
            return Err(invalid_data("private WAL basis selector exceeds limit"));
        }
        Ok(bytes)
    }

    pub(super) fn validate(&self, binding: Binding, limits: Limits) -> io::Result<()> {
        if self.root != binding.digest()?
            || self.native != binding.native
            || self.epoch == 0
            || self.epoch == u64::MAX
            || self.basis_bytes == 0
            || self.basis_bytes > MAX_BASIS
            || self.position.offset < SEGMENT_HEADER as u64
            || self.position.offset > limits.segment_bytes as u64
            || self.position.segment > u64::MAX - limits.segments as u64
            || self.position.sequence > u64::MAX - limits.history_count as u64
            || self.cut > self.position.sequence
            || (self.cut == 0) != (self.position.sequence == 0)
            || (self.cut == 0
                && (self.position != CutPosition::initial() || self.cut_chain != [0; 32]))
            || self.cuts.is_empty()
            || self.cuts.len() > 2
            || self
                .cuts
                .keys()
                .any(|sequence| *sequence > self.position.sequence)
        {
            return Err(invalid_data(
                "private WAL basis selector identity or bounds differ",
            ));
        }
        if let Some(generation) = self.native_generation {
            if !self.native
                || generation.file_epoch > self.epoch
                || self.marker.is_some()
                || self.cuts.len() != 1
            {
                return Err(invalid_data("native generation selector lineage differs"));
            }
            self.native_prefix()?
                .ok_or_else(|| invalid_data("native generation selector absent"))?
                .validate(MAX_BASIS)?;
        }
        let current = self
            .cuts
            .get(&self.position.sequence)
            .filter(|cut| cut.chain == self.position.chain)
            .ok_or_else(|| invalid_data("private WAL basis omits its acknowledged cut"))?;
        if let Some(snapshots) = &self.native_snapshots {
            if !self.native || self.native_generation.is_none() {
                return Err(invalid_data("native snapshot source lacks a generation"));
            }
            snapshots.validate()?;
            if let Some(installed) = current.installed {
                if installed != snapshot::InstalledCut::new(installed.epoch, &snapshots.origin)? {
                    return Err(invalid_data(
                        "native installed cut differs from retained origin",
                    ));
                }
            }
        } else if self.native_generation.is_some() && current.installed.is_some() {
            return Err(invalid_data(
                "native installed cut lacks its retained origin",
            ));
        }
        for (sequence, cut) in &self.cuts {
            if cut.installed.is_some_and(|origin| {
                origin.epoch == 0
                    || origin.epoch > self.epoch
                    || (origin.epoch == self.epoch && *sequence != self.position.sequence)
            }) {
                return Err(invalid_data("private WAL installed cut epoch differs"));
            }
            if let Some(committed) = cut.committed {
                let current_committed = current
                    .committed
                    .ok_or_else(|| invalid_data("private WAL basis committed cut regressed"))?;
                super::super::ensure_log_id_not_after(
                    &committed,
                    &current_committed,
                    "private WAL basis committed cut regressed",
                )?;
            }
        }
        if let Some(applied) = self.applied {
            let committed = current.committed.ok_or_else(|| {
                invalid_data("private WAL basis applied state lacks committed durability")
            })?;
            super::super::ensure_log_id_not_after(
                &applied,
                &committed,
                "private WAL basis applied state exceeds committed durability",
            )?;
        }
        match &self.marker {
            Some(marker) => {
                if marker.binding != self.root || Some(marker.applied) != self.applied {
                    return Err(invalid_data("private WAL basis application marker differs"));
                }
                let cut = self
                    .cuts
                    .get(&marker.cut_sequence)
                    .filter(|cut| cut.chain == marker.cut_chain)
                    .ok_or_else(|| invalid_data("private WAL basis application cut differs"))?;
                let committed = cut.committed.ok_or_else(|| {
                    invalid_data("private WAL basis application cut is uncommitted")
                })?;
                super::super::ensure_log_id_not_after(
                    &marker.applied,
                    &committed,
                    "private WAL basis application marker exceeds committed durability",
                )?;
                if self.cuts.keys().any(|sequence| {
                    *sequence != self.position.sequence && *sequence != marker.cut_sequence
                }) {
                    return Err(invalid_data("private WAL basis contains an unrelated cut"));
                }
            }
            None if self.cuts.len() == 1 => {}
            None => {
                return Err(invalid_data(
                    "private WAL basis has an unexplained application cut",
                ))
            }
        }
        Ok(())
    }

    pub(super) fn basis_path(&self, directory: &Path) -> PathBuf {
        directory.join(format!(
            "basis-{:020}.{}",
            self.file_epoch(),
            if self.native { "native" } else { "sqlite" }
        ))
    }

    pub(super) fn file_epoch(&self) -> u64 {
        self.native_generation
            .map_or(self.epoch, |generation| generation.file_epoch)
    }

    pub(super) fn native_prefix(
        &self,
    ) -> io::Result<Option<crate::consensus::native::prefix::PrefixIdentity>> {
        let Some(generation) = self.native_generation else {
            return Ok(None);
        };
        if !self.native {
            return Err(invalid_data("SQL selector contains a native generation"));
        }
        Ok(Some(crate::consensus::native::prefix::PrefixIdentity {
            binding: self.root,
            file_epoch: generation.file_epoch,
            checkpoint_epoch: self.epoch,
            operation_sequence: self.position.sequence,
            frontiers: generation.frontiers,
            length: self.basis_bytes,
            block_bytes: generation.block_bytes,
            digest: self.basis,
        }))
    }

    /// Bind the complete WAL cut and its generation/checkpoint axes into the
    /// generation transaction. The transaction's own length/hash/frontier hash
    /// cannot hash themselves; they are compared separately by native_prefix.
    /// This bounded codec work belongs outside State.
    pub(super) fn native_cut_binding(&self) -> io::Result<[u8; 32]> {
        let generation = self
            .native_generation
            .filter(|_| self.native)
            .ok_or_else(|| invalid_data("native cut binding lacks a generation"))?;
        let _memory = crate::consensus::verified_snapshot::VerificationMemory::reserve(
            2 * SELECTOR_LIMIT as usize,
        )?;
        let bytes = encode_json(&(
            self.root,
            self.epoch,
            generation.file_epoch,
            generation.block_bytes,
            self.position,
            self.cut,
            self.cut_chain,
            self.prefix,
            self.applied,
            &self.marker,
            &self.cuts,
        ))?;
        if bytes.len() as u64 > SELECTOR_LIMIT {
            return Err(invalid_data("native cut binding exceeds selector bound"));
        }
        let mut hash = Sha256::new();
        hash.update(if self.native_snapshots.is_some() {
            b"OPC-native-WAL-cut-v2\0"
        } else {
            b"OPC-native-WAL-cut-v1\0"
        });
        hash.update(&bytes);
        if let Some(snapshots) = &self.native_snapshots {
            let snapshots = encode_json(snapshots)?;
            if bytes
                .len()
                .checked_add(snapshots.len())
                .is_none_or(|length| length as u64 > SELECTOR_LIMIT)
            {
                return Err(invalid_data(
                    "native snapshot cut binding exceeds selector bound",
                ));
            }
            hash.update(&snapshots);
        }
        Ok(hash.finalize().into())
    }

    pub(super) fn load_basis(&self, directory: &Path, binding: Binding) -> io::Result<Connection> {
        if self.native {
            return Err(invalid_data("native basis cannot be opened as SQL"));
        }
        let path = self.basis_path(directory);
        if file_read(&path)?.metadata()?.len() != self.basis_bytes {
            return Err(invalid_data("private WAL selected basis extent differs"));
        }
        let conn = load_basis_image(&path, binding.identity, self.basis)?;
        if read_applied_sync(&conn, binding.identity)? != self.applied
            || read_committed_sync(&conn, binding.identity)?
                != self.cuts[&self.position.sequence].committed
        {
            return Err(invalid_data("private WAL selected basis pointers differ"));
        }
        if let Some(origin) = self.cuts[&self.position.sequence]
            .installed
            .filter(|origin| origin.epoch == self.epoch)
        {
            let snapshot = super::super::read_current_snapshot_sync(&conn, binding.identity)?
                .ok_or_else(|| invalid_data("private WAL installed basis omits its source"))?;
            if origin != snapshot::InstalledCut::new(self.epoch, &snapshot)?
                || snapshot.0.last_log_id != self.applied
                || self.cuts[&self.position.sequence].committed != self.applied
                || self.marker != snapshot::installed_marker(binding, self.position, self.applied)?
                || self.cuts.len() != 1
            {
                return Err(invalid_data("private WAL installed basis source differs"));
            }
        }
        Ok(conn)
    }

    pub(super) fn validate_prefix(&self, directory: &Path, binding: Binding) -> io::Result<()> {
        let path = directory.join(format!("segment-{:020}.wal", self.position.segment));
        if hash_prefix(&path, self.position.offset)? != self.prefix {
            return Err(invalid_data(
                "private WAL retained basis segment prefix differs",
            ));
        }
        let mut header = [0; SEGMENT_HEADER];
        file_read(&path)?.read_exact(&mut header)?;
        if header[..48] != segment_header(self.position.segment, binding.digest()?, [0; 32])[..48] {
            return Err(invalid_data(
                "private WAL retained basis segment binding differs",
            ));
        }
        Ok(())
    }
}

pub(super) fn read(
    directory: &Path,
    binding: Binding,
    limits: Limits,
) -> io::Result<Option<Anchor>> {
    let mut file = match file_read(&directory.join("CURRENT")) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let len = file.metadata()?.len();
    if !(40..=SELECTOR_LIMIT).contains(&len) {
        return Err(invalid_data("private WAL basis selector length differs"));
    }
    let mut bytes = vec![0; len as usize];
    file.read_exact(&mut bytes)?;
    if &bytes[..8] != SELECTOR_MAGIC
        || bytes[bytes.len() - 32..] != Sha256::digest(&bytes[..bytes.len() - 32])[..]
    {
        return Err(invalid_data("private WAL basis selector checksum differs"));
    }
    let anchor: Anchor = decode_json(&bytes[8..bytes.len() - 32])?;
    if anchor.encode()? != bytes {
        return Err(invalid_data("private WAL basis selector is not canonical"));
    }
    anchor.validate(binding, limits)?;
    Ok(Some(anchor))
}

pub(super) fn hash_prefix(path: &Path, len: u64) -> io::Result<[u8; 32]> {
    let mut file = file_read(path)?;
    if file.metadata()?.len() < len {
        return Err(invalid_data(
            "private WAL retained basis segment is truncated",
        ));
    }
    let mut hash = Sha256::new();
    let mut remaining = len;
    let mut buffer = [0; 16 * 1024];
    while remaining != 0 {
        let size = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..size])?;
        hash.update(&buffer[..size]);
        remaining -= size as u64;
    }
    Ok(hash.finalize().into())
}

impl Wal {
    #[cfg(test)]
    pub(in crate::sqlite::consensus) fn checkpoint_pending_for_test(&self) -> io::Result<bool> {
        Ok(lock_state(&self.shared)?.checkpoint_requested)
    }

    /// Wait for a selected basis covering this operation and applied cut.
    /// Native admission continues while its immutable capture is prepared.
    pub(crate) fn checkpoint(&self) -> io::Result<u64> {
        let mut state = lock_state(&self.shared)?;
        while (state.snapshot.is_some() || state.native_install_pending)
            && state.status == Status::Running
        {
            state = self
                .shared
                .ready
                .wait(state)
                .map_err(|_| io::Error::other("private WAL snapshot wait poisoned"))?;
        }
        if state.status != Status::Running {
            return Err(io::Error::other("private WAL checkpoint owner is fenced"));
        }
        #[cfg(feature = "test-control")]
        if state.volatile_experiment.is_some() {
            // Diagnostic-only request: mark a new coalesced generation without
            // claiming a selected durable basis or joining background I/O.
            volatile_experiment::dirty(&mut state);
            self.shared.ready.notify_all();
            return Ok(state.checkpoint_epoch);
        }
        let epoch = state.checkpoint_epoch;
        let native_target = if self.binding.native {
            Some(native_basis::Target::requested(&state)?)
        } else {
            None
        };
        if let Some(target) = native_target {
            state.native_checkpoint_target = Some(target);
        }
        state.checkpoint_requested = true;
        self.shared.ready.notify_all();
        while native_target.map_or(state.checkpoint_epoch == epoch, |target| {
            !target.satisfied(&state)
        }) {
            if state.status != Status::Running {
                return Err(io::Error::other("private WAL checkpoint failed"));
            }
            state = self
                .shared
                .ready
                .wait(state)
                .map_err(|_| io::Error::other("private WAL checkpoint wait poisoned"))?;
        }
        ensure_readable(&state)?;
        Ok(state.checkpoint_epoch)
    }
}

pub(super) fn publish(
    state: &mut State,
    disk: &mut Disk,
    binding: Binding,
    limits: Limits,
    control: &IoControl,
) -> io::Result<()> {
    let anchor = prepare(state, disk, binding, limits, control)?;
    select(&disk.directory, &anchor, control)?;
    finish(state, disk, anchor, control)
}

/// Publish the complete image without selecting it. A snapshot handoff keeps
/// both images until its cache transaction and pending-proof retirement finish.
pub(super) fn prepare(
    state: &mut State,
    disk: &Disk,
    binding: Binding,
    limits: Limits,
    control: &IoControl,
) -> io::Result<Anchor> {
    if state.native.is_some() {
        return Err(invalid_data(
            "native basis requires its owned preparation worker",
        ));
    }
    if state.outstanding != 0
        || !state.queue.is_empty()
        || state.sequence != disk.sequence
        || !state.conn.is_autocommit()
        || read_committed_sync(&state.conn, binding.identity)? != state.durable_committed
    {
        return Err(invalid_data(
            "private WAL basis contains outstanding operations",
        ));
    }
    application::validate_applied_prefix(state, binding)?;
    state.authority.validate(&state.conn, binding.identity)?;
    validate_basis(&state.conn, binding.identity)?;
    let source_image = application::full_image_digest(&state.conn)?;
    let epoch = state
        .checkpoint_epoch
        .checked_add(1)
        .ok_or_else(|| invalid_data("private WAL basis epoch exhausted"))?;
    let mut cuts = BTreeMap::from([(
        disk.sequence,
        *state
            .durable_cuts
            .get(&disk.sequence)
            .filter(|cut| cut.chain == disk.chain && cut.committed == state.durable_committed)
            .ok_or_else(|| invalid_data("private WAL basis lacks exact acknowledged cut"))?,
    )]);
    if let Some(marker) = &state.application_marker {
        cuts.insert(
            marker.cut_sequence,
            *state
                .durable_cuts
                .get(&marker.cut_sequence)
                .filter(|cut| cut.chain == marker.cut_chain)
                .ok_or_else(|| {
                    invalid_data("private WAL basis lacks its application marker cut")
                })?,
        );
    }
    let preparing = disk.directory.join(format!("basis-{epoch:020}.preparing"));
    let final_path = disk.directory.join(format!("basis-{epoch:020}.sqlite"));
    (control.hook)(Point::BeforeBasisCreate)?;
    file_create(&preparing)?;
    (control.hook)(Point::AfterBasisCreate)?;
    let mut frozen = Connection::open(&preparing).map_err(db_error)?;
    // This unselected file is disposable until fully copied, closed, synced,
    // and selected. No journal sidecar can become unexplained recovery state.
    frozen
        .pragma_update(None, "journal_mode", "OFF")
        .map_err(db_error)?;
    Backup::new(&state.conn, &mut frozen)
        .map_err(db_error)?
        .run_to_completion(128, Duration::ZERO, None)
        .map_err(db_error)?;
    frozen.close().map_err(|(_, error)| db_error(error))?;
    (control.hook)(Point::BeforeBasisSync)?;
    file_read(&preparing)?.sync_all()?;
    (control.hook)(Point::AfterBasisSync)?;
    let frozen = Connection::open_with_flags(&preparing, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(db_error)?;
    validate_basis(&frozen, binding.identity)?;
    if application::full_image_digest(&frozen)? != source_image {
        return Err(invalid_data(
            "private WAL copied basis differs from acknowledged image",
        ));
    }
    frozen.close().map_err(|(_, error)| db_error(error))?;
    let anchor = Anchor {
        root: binding.digest()?,
        epoch,
        basis: hash_file(&preparing, MAX_BASIS)?,
        basis_bytes: file_read(&preparing)?.metadata()?.len(),
        position: disk.position(),
        cut: disk.cut,
        cut_chain: disk.cut_chain,
        prefix: hash_prefix(
            &disk
                .directory
                .join(format!("segment-{:020}.wal", disk.segment)),
            disk.offset,
        )?,
        applied: read_applied_sync(&state.conn, binding.identity)?,
        marker: state.application_marker.clone(),
        cuts,
        native: false,
        native_generation: None,
        native_snapshots: None,
    };
    anchor.validate(binding, limits)?;
    // create_new above and an otherwise clean namespace prevent replacement
    // of another candidate. Recovery removes any interrupted next epoch first.
    crate::consensus::snapshot::rename_noreplace_in_directory(
        &File::open(&disk.directory)?,
        preparing
            .file_name()
            .ok_or_else(|| invalid_data("private WAL basis preparation name missing"))?,
        final_path
            .file_name()
            .ok_or_else(|| invalid_data("private WAL basis final name missing"))?,
    )?;
    (control.hook)(Point::AfterBasisRename)?;
    File::open(&disk.directory)?.sync_all()?;
    (control.hook)(Point::AfterBasisDirectorySync)?;
    Ok(anchor)
}

pub(super) fn select(directory: &Path, anchor: &Anchor, control: &IoControl) -> io::Result<()> {
    (control.hook)(Point::BeforeBasisSelector)?;
    let selector_path = directory.join("CURRENT.preparing");
    let mut selector = file_create(&selector_path)?;
    selector.write_all(&anchor.encode()?)?;
    (control.hook)(Point::BeforeBasisSelectorSync)?;
    selector.sync_all()?;
    (control.hook)(Point::AfterBasisSelectorSync)?;
    fs::rename(&selector_path, directory.join("CURRENT"))?;
    (control.hook)(Point::AfterBasisSelectorRename)?;
    (control.hook)(Point::BeforeBasisPublicationSync)?;
    File::open(directory)?.sync_all()?;
    (control.hook)(Point::AfterBasisPublicationSync)?;
    Ok(())
}

pub(super) fn finish(
    state: &mut State,
    disk: &mut Disk,
    anchor: Anchor,
    control: &IoControl,
) -> io::Result<()> {
    if state.native.is_some() {
        return Err(invalid_data(
            "native basis requires suffix-preserving selection",
        ));
    }
    reclaim_covered(disk, &anchor, control)?;
    state.base_sequence = anchor.position.sequence;
    state.history_bytes = 0;
    state.checkpoint_epoch = anchor.epoch;
    state.durable_cuts = anchor.cuts.clone();
    // Only the original applied image has moved the purge recovery boundary.
    state.authority.frozen_applied = anchor.applied;
    disk.cuts = anchor.cuts.clone();
    disk.anchor = Some(anchor);
    Ok(())
}

pub(super) fn reclaim_covered(disk: &Disk, anchor: &Anchor, control: &IoControl) -> io::Result<()> {
    // Do not report completion if cleanup fails. A subsequent owner verifies
    // and stabilizes the selected basis before retrying these exact removals.
    let mut retired = Vec::new();
    let mut namespace = Namespace::default();
    for entry in fs::read_dir(&disk.directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(invalid_data("private WAL basis namespace is not regular"));
        }
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| invalid_data("private WAL basis filename invalid"))?;
        if let Some(number) = numbered_name(name, "segment-", ".wal") {
            if number < anchor.position.segment {
                retired.push(entry.path());
            }
        } else if let Some(number) = numbered_name(name, "cut-", ".cut") {
            if number <= anchor.cut {
                retired.push(entry.path());
            }
        } else if !namespace.visit(
            name,
            entry.path(),
            entry.metadata()?.len(),
            Some(anchor),
            &mut retired,
        )? {
            return Err(invalid_data("private WAL basis has an unexplained file"));
        }
    }
    reclaim(&disk.directory, &retired, control)
}

/// One selected image, at most one previous image during cleanup, and one
/// unselected next image. Initial basis.sqlite stays as the immutable root.
#[derive(Default)]
pub(super) struct Namespace {
    basis_files: usize,
    next_basis_files: usize,
    previous_basis_files: usize,
}

impl Namespace {
    pub(super) fn visit(
        &mut self,
        name: &str,
        path: PathBuf,
        len: u64,
        anchor: Option<&Anchor>,
        retired: &mut Vec<PathBuf>,
    ) -> io::Result<bool> {
        let epoch = anchor.map_or(0, Anchor::file_epoch);
        if name == "ROOT" {
            if len != super::owner::ROOT_BYTES || !anchor.is_some_and(|anchor| anchor.native) {
                return Err(invalid_data(
                    "native root namespace extent or format differs",
                ));
            }
            return Ok(true);
        }
        if name == "basis.sqlite" && len > MAX_BASIS {
            return Err(invalid_data("private WAL root basis exceeds limit"));
        }
        if name == "LOCK" || name == "basis.sqlite" || (name == "CURRENT" && anchor.is_some()) {
            return Ok(true);
        }
        if name == "CURRENT.preparing" {
            if len > SELECTOR_LIMIT {
                return Err(invalid_data(
                    "private WAL staged basis selector exceeds limit",
                ));
            }
            retired.push(path);
            return Ok(true);
        }
        let preparing = numbered_name(name, "basis-", ".preparing");
        let native = numbered_name(name, "basis-", ".native");
        let sqlite = numbered_name(name, "basis-", ".sqlite");
        if anchor.is_some_and(|anchor| {
            (native.is_some() && !anchor.native) || (sqlite.is_some() && anchor.native)
        }) {
            return Err(invalid_data(
                "private WAL basis format differs from selected authority",
            ));
        }
        let Some(number) = preparing.or(native).or(sqlite) else {
            return Ok(false);
        };
        if (number == 0 && anchor.is_none_or(|anchor| anchor.native_generation.is_none()))
            || number > epoch + 1
            || len > MAX_BASIS
            || (preparing.is_some() && number != epoch + 1)
        {
            return Err(invalid_data(
                "private WAL basis namespace exceeds selected range",
            ));
        }
        self.basis_files += 1;
        self.next_basis_files += usize::from(number == epoch + 1);
        self.previous_basis_files += usize::from(number < epoch);
        if self.basis_files > 3 || self.next_basis_files > 1 || self.previous_basis_files > 1 {
            return Err(invalid_data(
                "private WAL basis namespace exceeds file bounds",
            ));
        }
        if number != epoch {
            retired.push(path);
        }
        Ok(true)
    }
}

pub(super) fn reclaim(
    directory: &Path,
    retired: &[PathBuf],
    control: &IoControl,
) -> io::Result<()> {
    if retired.is_empty() {
        return Ok(());
    }
    (control.hook)(Point::BeforeBasisReclaim)?;
    for path in retired {
        fs::remove_file(path)?;
        (control.hook)(Point::AfterBasisReclaimFile)?;
    }
    (control.hook)(Point::BeforeBasisReclaimSync)?;
    File::open(directory)?.sync_all()?;
    (control.hook)(Point::AfterBasisReclaimSync)?;
    Ok(())
}
