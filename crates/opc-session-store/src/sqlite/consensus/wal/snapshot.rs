//! Exact two-image publication of snapshot metadata and covered-log compaction.
//! The primary SQLite connection stays with its owner; Disk and its flock stay
//! with the sole WAL writer. A bounded pending proof bridges their commits.

#[cfg(test)]
use super::super::BackendCapabilities;
use super::*;
use crate::consensus::snapshot::{PinnedSqliteFile, SNAPSHOT_ENVELOPE_FOOTER_BYTES};
use crate::sqlite::consensus::{self, CurrentSnapshot};
use crate::sqlite::ops::RestoreScanIncarnation;
use rusqlite::Transaction;
#[cfg(test)]
use rusqlite::TransactionBehavior;

#[path = "native_install.rs"]
mod native_install;
pub(super) use native_install::advance as advance_native;

const PROOF_MAGIC: &[u8; 8] = b"OPCWSNP1";
const PROOF_LIMIT: u64 = 2 * checkpoint::SELECTOR_LIMIT + 2048;

/// A snapshot installation is an explicit durable source at an unchanged WAL
/// position. Later ordinary WAL cuts do not inherit this field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstalledCut {
    pub(super) epoch: u64,
    snapshot_metadata_sha256: [u8; 32],
}

impl InstalledCut {
    pub(super) fn new(epoch: u64, candidate: &CurrentSnapshot) -> io::Result<Self> {
        Ok(Self {
            epoch,
            snapshot_metadata_sha256: Sha256::digest(encode_json(candidate)?).into(),
        })
    }
}

pub(super) fn installed_marker(
    binding: Binding,
    position: CutPosition,
    applied: Option<LogId<SessionConsensusNodeId>>,
) -> io::Result<Option<application::Marker>> {
    let root = binding.digest()?;
    Ok(applied.map(|applied| application::Marker {
        binding: root,
        cut_sequence: position.sequence,
        cut_chain: position.chain,
        applied,
    }))
}

/// The raw input and published envelope are distinct continuously pinned
/// immutable files. In recovery, RAW is derived again from the retained
/// envelope; the proposed installed basis is never treated as incoming data.
pub(crate) struct InstallSource {
    candidate: CurrentSnapshot,
    raw: PinnedSqliteFile,
    published: PinnedSqliteFile,
    published_path: PathBuf,
    _metadata_memory: Option<crate::consensus::verified_snapshot::VerificationMemory>,
}

impl InstallSource {
    pub(crate) fn candidate(&self) -> &CurrentSnapshot {
        &self.candidate
    }

    /// Borrowed metadata is bounded and charged before the native caller owns
    /// any clone. Retain that charge through all source pins and early errors.
    pub(crate) fn new_native(
        meta: &opc_consensus::engine::SnapshotMeta<
            SessionConsensusNodeId,
            opc_consensus::engine::EmptyNode,
        >,
        name: &str,
        checksum: [u8; 32],
        length: u64,
        raw: PinnedSqliteFile,
        published: PinnedSqliteFile,
        path: &Path,
    ) -> io::Result<Self> {
        let memory = crate::consensus::native::generation::reserve_install_metadata_parts(
            meta, name, checksum, length, path,
        )?;
        let mut source = Self::new(
            (meta.clone(), name.to_owned(), checksum, length),
            raw,
            published,
            path.to_path_buf(),
        )?;
        source._metadata_memory = Some(memory);
        Ok(source)
    }

    pub(crate) fn new(
        candidate: CurrentSnapshot,
        raw: PinnedSqliteFile,
        published: PinnedSqliteFile,
        published_path: PathBuf,
    ) -> io::Result<Self> {
        let source = Self {
            candidate,
            raw,
            published,
            published_path,
            _metadata_memory: None,
        };
        source.verify()?;
        source.raw.verify_payload_checksum(source.candidate.2)?;
        Ok(source)
    }

    pub(crate) fn verify(&self) -> io::Result<()> {
        self.raw.verify_identity()?;
        self.raw.verify_immutable_generation()?;
        if self
            .raw
            .file()
            .metadata()?
            .len()
            .checked_add(SNAPSHOT_ENVELOPE_FOOTER_BYTES)
            != Some(self.candidate.3)
            || self.published_path.file_name() != Some(std::ffi::OsStr::new(&self.candidate.1))
        {
            return Err(invalid_data(
                "private WAL install source extent or name differs",
            ));
        }
        self.published
            .verify_bound_immutable_snapshot_envelope(&self.published_path, self.candidate.3)
    }

    fn apply_original(
        &self,
        conn: &Connection,
        binding: Binding,
        incarnation: &RestoreScanIncarnation,
        before_write: impl FnOnce(&Transaction<'_>) -> io::Result<()>,
        before_commit: impl FnOnce(&Transaction<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.verify()?;
        let authority = Authority::load(conn, binding.identity)?;
        let outcome =
            consensus::install_snapshot_database_from_pinned_with_authority_and_hooks_sync(
                conn,
                binding.identity,
                authority.profile,
                Some(&authority.members),
                Some(&authority.bindings),
                authority.placement,
                self.raw.try_clone()?,
                Some((&self.published, &self.published_path)),
                &self.candidate.0,
                &self.candidate.1,
                self.candidate.2,
                self.candidate.3,
                before_write,
                |tx| {
                    incarnation.rotate_sync(tx).map_err(|_| {
                        invalid_data("installed session snapshot restore metadata failed")
                    })
                },
                |tx| {
                    // Original install first validates the complete retained log
                    // and publishes the exact incoming logical purge floor.
                    // Compact only its covered physical rows on BOTH images.
                    if let Some(through) = self.candidate.0.last_log_id.as_ref() {
                        let (_, index) = consensus::validate_log_id(through)?;
                        tx.execute("DELETE FROM consensus_log WHERE log_index <= ?1", [index])
                            .map_err(db_error)?;
                    }
                    before_commit(tx)
                },
            )?;
        if outcome != consensus::SnapshotInstallPublicationOutcome::Clean {
            return Err(io::Error::other(
                "private WAL install committed with attached source",
            ));
        }
        self.verify()
    }

    /// Run the complete original installer on a disposable local predecessor.
    /// Only this transaction can supply missing native snapshot/log witnesses;
    /// neither a selector nor an already-proposed native image can mint them.
    pub(in crate::sqlite::consensus) fn apply_native_original(
        &self,
        conn: &Connection,
        binding: Binding,
        root: Option<&RosterAttestationTrustRootV1>,
        incarnation: &RestoreScanIncarnation,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Arc<NativeSnapshotAuthority>> {
        check()?;
        let memory = crate::consensus::native::generation::reserve_install_metadata(
            &self.candidate,
            &self.published_path,
        )?;
        self.verify()?;
        if !binding.native {
            return Err(invalid_data(
                "native snapshot origin requires native local authority",
            ));
        }
        let authority_memory = consensus::native_snapshot::reserve_input(conn, check)?;
        let authority = Authority::load(conn, binding.identity)?;
        let placement = authority
            .placement
            .ok_or_else(|| invalid_data("native snapshot placement absent"))?;
        if authority.profile != ConsensusAuthorityProfile::FixedImmutable {
            return Err(invalid_data("native snapshot requires fixed authority"));
        }
        let (_, local_memory) = consensus::native_snapshot::validate(
            conn,
            binding.identity,
            &authority.members,
            &authority.bindings,
            placement,
            root,
            check,
        )?;
        drop(authority_memory);
        // The verified immutable VFS/proc descriptor is the original incoming
        // payload. It is distinct from this disposable installed predecessor.
        let incoming = Connection::open_with_flags(
            consensus::pinned_snapshot_uri(&self.raw, true),
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(db_error)?;
        let incoming_tx = incoming.unchecked_transaction().map_err(db_error)?;
        let incoming_memory = consensus::native_snapshot::reserve_input(&incoming_tx, check)?;
        conn.pragma_update(None, "query_only", false)
            .map_err(db_error)?;
        self.apply_original(conn, binding, incarnation, |_| check(), |_| check())?;
        drop(incoming_tx);
        drop(incoming);
        drop(incoming_memory);
        drop(local_memory);
        let (_, installed_memory) = consensus::native_snapshot::validate(
            conn,
            binding.identity,
            &authority.members,
            &authority.bindings,
            placement,
            root,
            check,
        )?;
        let installed_incarnation = RestoreScanIncarnation::from_installed_sync(conn)
            .map_err(|_| invalid_data("native installed restore identity invalid"))?;
        let cut = self.candidate.0.last_log_id;
        if installed_incarnation.native_image() != incarnation.native_image()
            || consensus::read_current_snapshot_sync(conn, binding.identity)?.as_ref()
                != Some(&self.candidate)
            || read_applied_sync(conn, binding.identity)? != cut
            || read_committed_sync(conn, binding.identity)? != cut
            || consensus::read_purged_sync(conn, binding.identity)? != cut
            || consensus::read_membership_sync(conn, binding.identity)?
                != self.candidate.0.last_membership
        {
            return Err(invalid_data(
                "native installed origin differs from original transaction",
            ));
        }
        self.verify()?;
        check()?;
        let proof = Arc::new(NativeSnapshotAuthority {
            candidate: self.candidate.clone(),
            binding: binding.digest()?,
            identity: binding.identity,
            members: authority.members,
            roster_root: root.map(RosterAttestationTrustRootV1::fingerprint),
            incarnation: installed_incarnation,
            published: self.published.try_clone()?,
            published_path: self.published_path.clone(),
            _memory: memory,
        });
        drop(installed_memory);
        Ok(proof)
    }
}

/// Process-local authority from the complete original install transaction.
/// Its constructor and fields are private; serialized metadata never grants
/// an exception to native retained-log or configured-root validation.
pub(crate) struct NativeSnapshotAuthority {
    candidate: CurrentSnapshot,
    binding: [u8; 32],
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
    roster_root: Option<[u8; 32]>,
    incarnation: RestoreScanIncarnation,
    published: PinnedSqliteFile,
    published_path: PathBuf,
    _memory: crate::consensus::verified_snapshot::VerificationMemory,
}

impl NativeSnapshotAuthority {
    pub(crate) fn candidate(&self) -> &CurrentSnapshot {
        &self.candidate
    }

    pub(crate) fn incarnation(&self) -> &RestoreScanIncarnation {
        &self.incarnation
    }

    pub(crate) fn verify(&self) -> io::Result<()> {
        self.published.verify_identity()?;
        self.published
            .verify_bound_immutable_snapshot_envelope(&self.published_path, self.candidate.3)
    }

    pub(crate) fn require_scope(
        &self,
        binding: [u8; 32],
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        root: Option<&RosterAttestationTrustRootV1>,
    ) -> io::Result<()> {
        if self.binding != binding
            || self.identity != identity
            || &self.members != members
            || self.roster_root != root.map(RosterAttestationTrustRootV1::fingerprint)
        {
            return Err(invalid_data(
                "native snapshot origin independent authority differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn matches_snapshot(&self, candidate: &CurrentSnapshot) -> bool {
        self.candidate == *candidate
    }

    /// Missing retained rows may be witnessed by the exact incoming envelope
    /// or a later local export of the same full LogId and membership. This
    /// never admits altered foreign metadata as the original install source.
    pub(crate) fn matches_snapshot_lineage(&self, candidate: &CurrentSnapshot) -> bool {
        if self.matches_snapshot(candidate) {
            return true;
        }
        if candidate
            .0
            .last_log_id
            .is_none_or(|cut| !self.matches_cut(cut))
            || !self.matches_membership(&candidate.0.last_membership)
        {
            return false;
        }
        let Some(suffix) = candidate.0.snapshot_id.as_bytes().strip_prefix(b"native-") else {
            return false;
        };
        if suffix.get(64) != Some(&b'-') {
            return false;
        }
        // Compare the fixed generation prefix without allocating on each
        // subsequent log/frontier admission after local snapshot publication.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        suffix[..64]
            .as_chunks::<2>()
            .0
            .iter()
            .zip(self.binding)
            .all(|(pair, byte)| {
                pair[0] == HEX[usize::from(byte >> 4)] && pair[1] == HEX[usize::from(byte & 15)]
            })
    }

    pub(crate) fn matches_cut(&self, cut: LogId<SessionConsensusNodeId>) -> bool {
        self.candidate.0.last_log_id == Some(cut)
    }

    pub(crate) fn matches_membership(
        &self,
        membership: &opc_consensus::engine::StoredMembership<
            SessionConsensusNodeId,
            opc_consensus::engine::EmptyNode,
        >,
    ) -> bool {
        self.candidate.0.last_membership == *membership
    }
}

struct Installation {
    source: InstallSource,
    incarnation: RestoreScanIncarnation,
    _native_memory: Option<crate::consensus::verified_snapshot::VerificationMemory>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
enum Transform {
    #[default]
    Metadata,
    Compact,
    Install,
}

impl Transform {
    fn is_metadata(&self) -> bool {
        *self == Self::Metadata
    }

    fn finish_metadata_tx(
        self,
        tx: &Transaction<'_>,
        binding: Binding,
        candidate: &CurrentSnapshot,
    ) -> io::Result<()> {
        if let (Self::Compact, Some(through)) = (self, candidate.0.last_log_id.as_ref()) {
            let (_, index) = consensus::validate_log_id(through)?;
            consensus::purge_logs_in_tx(tx, binding.identity, through, index)?;
            // The original validator preserves a stronger logical floor
            // by returning early for a delayed purge. This handoff still
            // deletes that snapshot-covered physical prefix on BOTH images.
            // Later rows and the stronger exact full LogId remain intact.
            tx.execute("DELETE FROM consensus_log WHERE log_index <= ?1", [index])
                .map_err(db_error)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    old: checkpoint::Anchor,
    new: checkpoint::Anchor,
    old_application: [u8; 32],
    new_application: [u8; 32],
    // Missing preserves the byte-exact original metadata-only proof encoding.
    // Older readers reject an explicit Compact through deny_unknown_fields.
    #[serde(default, skip_serializing_if = "Transform::is_metadata")]
    transform: Transform,
}

impl Pending {
    fn encode(&self) -> io::Result<Vec<u8>> {
        let mut bytes = PROOF_MAGIC.to_vec();
        bytes.extend_from_slice(&encode_json(self)?);
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        if bytes.len() as u64 > PROOF_LIMIT {
            return Err(invalid_data("private WAL snapshot proof exceeds limit"));
        }
        Ok(bytes)
    }

    fn validate(&self, binding: Binding, limits: Limits) -> io::Result<()> {
        self.old.validate(binding, limits)?;
        self.new.validate(binding, limits)?;
        let mut same_frontier = self.new.clone();
        same_frontier.epoch = self.old.epoch;
        same_frontier.basis = self.old.basis;
        same_frontier.basis_bytes = self.old.basis_bytes;
        if self.transform == Transform::Install {
            let current = self
                .new
                .cuts
                .get(&self.new.position.sequence)
                .ok_or_else(|| invalid_data("private WAL install omits its cut"))?;
            if self.new.cuts.len() != 1
                || current
                    .installed
                    .is_none_or(|origin| origin.epoch != self.new.epoch)
                || current.committed != self.new.applied
                || self.new.marker
                    != installed_marker(binding, self.new.position, self.new.applied)?
            {
                return Err(invalid_data(
                    "private WAL install frontier relation differs",
                ));
            }
            same_frontier.applied = self.old.applied;
            same_frontier.marker = self.old.marker.clone();
            same_frontier.cuts = self.old.cuts.clone();
        }
        if same_frontier != self.old
            || self.new.epoch != self.old.epoch + 1
            || self.old_application == self.new_application
        {
            return Err(invalid_data("private WAL snapshot basis relation differs"));
        }
        Ok(())
    }

    fn load_images(
        &self,
        directory: &Path,
        binding: Binding,
        limits: Limits,
        install_source: Option<&InstallSource>,
        require_install_source: bool,
    ) -> io::Result<(Connection, Connection)> {
        self.validate(binding, limits)?;
        let old = self.old.load_basis(directory, binding)?;
        let new = self.new.load_basis(directory, binding)?;
        if application::application_digest(&old)? != self.old_application
            || application::application_digest(&new)? != self.new_application
        {
            return Err(invalid_data(
                "private WAL snapshot application digest differs",
            ));
        }
        let candidate = consensus::read_current_snapshot_sync(&new, binding.identity)?
            .ok_or_else(|| invalid_data("private WAL snapshot new basis omits metadata"))?;
        // Re-run the declared original transaction on a separately
        // verified old image. Every schema object and every physical row in
        // the result must equal the proposed new basis, including WAL logs.
        let transformed = self.old.load_basis(directory, binding)?;
        if self.transform == Transform::Install {
            let Some(source) = install_source else {
                if require_install_source {
                    return Err(invalid_data(
                        "private WAL recovery requires its incoming snapshot source",
                    ));
                }
                // Preliminary read-only open only. No cache, selector or proof
                // mutation, and no usable owner, precedes the complete replay.
                return Ok((old, new));
            };
            if source.candidate != candidate {
                return Err(invalid_data("private WAL incoming snapshot source differs"));
            }
            let incarnation = RestoreScanIncarnation::from_installed_sync(&new)
                .map_err(|_| invalid_data("private WAL installed restore metadata is invalid"))?;
            source.apply_original(&transformed, binding, &incarnation, |_| Ok(()), |_| Ok(()))?;
        } else {
            save_original(&transformed, binding, &candidate, self.transform)?;
        }
        if application::full_image_digest(&transformed)? != application::full_image_digest(&new)? {
            return Err(invalid_data(
                "private WAL snapshot changed more than its declared original transaction",
            ));
        }
        Ok((old, new))
    }

    fn publish(&self, directory: &Path, control: &IoControl) -> io::Result<()> {
        (control.hook)(Point::BeforeSnapshotProof)?;
        let mut file = file_create(&directory.join("SNAPSHOT.preparing"))?;
        (control.hook)(Point::AfterSnapshotProofCreate)?;
        file.write_all(&self.encode()?)?;
        (control.hook)(Point::BeforeSnapshotProofSync)?;
        file.sync_all()?;
        (control.hook)(Point::AfterSnapshotProofSync)?;
        crate::consensus::snapshot::rename_noreplace_in_directory(
            &File::open(directory)?,
            std::ffi::OsStr::new("SNAPSHOT.preparing"),
            std::ffi::OsStr::new("SNAPSHOT.pending"),
        )?;
        (control.hook)(Point::AfterSnapshotProofRename)?;
        File::open(directory)?.sync_all()?;
        (control.hook)(Point::AfterSnapshotProofDirectorySync)
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg(test)]
enum Proof {
    Absent,
    Preparing(Vec<u8>),
    Pending(Box<Pending>),
}

pub(super) fn is_proof_file(name: &str, len: u64) -> io::Result<bool> {
    if !matches!(name, "SNAPSHOT.preparing" | "SNAPSHOT.pending") {
        return Ok(false);
    }
    if len > PROOF_LIMIT {
        return Err(invalid_data(
            "private WAL snapshot proof file exceeds limit",
        ));
    }
    Ok(true)
}

#[cfg(test)]
fn read_proof(directory: &Path, binding: Binding, limits: Limits) -> io::Result<Proof> {
    let read = |name: &str| -> io::Result<Option<Vec<u8>>> {
        let mut file = match file_read(&directory.join(name)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let len = file.metadata()?.len();
        is_proof_file(name, len)?;
        let mut bytes = vec![0; len as usize];
        file.read_exact(&mut bytes)?;
        Ok(Some(bytes))
    };
    let preparing = read("SNAPSHOT.preparing")?;
    let pending = read("SNAPSHOT.pending")?;
    match (preparing, pending) {
        (Some(_), Some(_)) => Err(invalid_data("private WAL snapshot has two proof stages")),
        (Some(bytes), None) => Ok(Proof::Preparing(bytes)),
        (None, None) => Ok(Proof::Absent),
        (None, Some(bytes)) => {
            if bytes.len() < 40
                || &bytes[..8] != PROOF_MAGIC
                || bytes[bytes.len() - 32..] != Sha256::digest(&bytes[..bytes.len() - 32])[..]
            {
                return Err(invalid_data("private WAL snapshot proof checksum differs"));
            }
            let proof: Pending = decode_json(&bytes[8..bytes.len() - 32])?;
            if proof.encode()? != bytes {
                return Err(invalid_data("private WAL snapshot proof is not canonical"));
            }
            proof.validate(binding, limits)?;
            Ok(Proof::Pending(Box::new(proof)))
        }
    }
}

fn save_original(
    conn: &Connection,
    binding: Binding,
    candidate: &CurrentSnapshot,
    transform: Transform,
) -> io::Result<()> {
    if transform == Transform::Install {
        return Err(invalid_data(
            "private WAL install requires its original incoming source",
        ));
    }
    let authority = Authority::load(conn, binding.identity)?;
    consensus::save_current_snapshot_with_authority_and_hooks_sync(
        conn,
        binding.identity,
        authority.profile,
        &authority.members,
        &authority.bindings,
        authority.placement,
        &candidate.0,
        &candidate.1,
        candidate.2,
        candidate.3,
        |_| Ok(()),
        |tx| transform.finish_metadata_tx(tx, binding, candidate),
    )
}

pub(super) struct Handoff {
    candidate: CurrentSnapshot,
    transform: Transform,
    installation: Option<Arc<Installation>>,
    phase: Phase,
}

enum Phase {
    Requested,
    Prepared(Pending),
    Committed(Pending),
}

impl Handoff {
    pub(super) fn writer_ready(&self) -> bool {
        !matches!(self.phase, Phase::Prepared(_))
    }
}

struct HandoffOwner {
    shared: Arc<Shared>,
    completed: bool,
}

impl Drop for HandoffOwner {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = match self.shared.state.lock() {
                Ok(state) => state,
                Err(poison) => poison.into_inner(),
            };
            application::fence(&mut state);
            self.shared.ready.notify_all();
        }
    }
}

impl Wal {
    #[cfg(test)]
    pub(in crate::sqlite::consensus) fn snapshot_pending_for_test(&self) -> io::Result<bool> {
        Ok(lock_state(&self.shared)?.snapshot.is_some())
    }

    #[cfg(test)]
    pub(crate) fn snapshot_source_cut_for_test(&self) -> io::Result<()> {
        (self.control.hook)(Point::AfterSnapshotSourceCut)
    }

    pub(super) fn wait_for_snapshot<'a>(
        &'a self,
        mut state: MutexGuard<'a, State>,
    ) -> io::Result<MutexGuard<'a, State>> {
        while (state.snapshot.is_some() || state.native_install_pending)
            && state.status == Status::Running
        {
            state =
                self.shared.ready.wait(state).map_err(|_| {
                    io::Error::other("private WAL application handoff wait poisoned")
                })?;
        }
        ensure_readable(&state)?;
        Ok(state)
    }

    /// Called while the original snapshot gate and primary cache connection
    /// are held. The caller must retain its external candidate before entry:
    /// even a proof rename/sync error can leave recovery needing that file.
    #[cfg(test)]
    pub(crate) fn publish_snapshot(
        &self,
        conn: &Connection,
        candidate: CurrentSnapshot,
    ) -> io::Result<()> {
        self.publish_snapshot_with_transform(conn, candidate, Transform::Metadata, None)
    }

    pub(crate) fn publish_compacting_snapshot(
        &self,
        conn: &Connection,
        candidate: CurrentSnapshot,
    ) -> io::Result<()> {
        if self.is_native() {
            return self.native_publish_snapshot(candidate);
        }
        self.publish_snapshot_with_transform(conn, candidate, Transform::Compact, None)
    }

    pub(crate) fn install_snapshot(
        &self,
        conn: &Connection,
        source: InstallSource,
    ) -> io::Result<()> {
        source.verify()?;
        let native_memory = if self.is_native() {
            Some(
                crate::consensus::native::generation::reserve_install_metadata(
                    &source.candidate,
                    &source.published_path,
                )?,
            )
        } else {
            None
        };
        let candidate = source.candidate.clone();
        let installation = Arc::new(Installation {
            source,
            incarnation: RestoreScanIncarnation::new()
                .map_err(|_| invalid_data("private WAL install restore incarnation failed"))?,
            _native_memory: native_memory,
        });
        if self.is_native() {
            return self.native_install_snapshot(installation);
        }
        self.publish_snapshot_with_transform(
            conn,
            candidate,
            Transform::Install,
            Some(installation),
        )
    }

    fn publish_snapshot_with_transform(
        &self,
        conn: &Connection,
        candidate: CurrentSnapshot,
        transform: Transform,
        installation: Option<Arc<Installation>>,
    ) -> io::Result<()> {
        // The native route has its own exact metadata publisher. The SQL
        // install/transform authority is unavailable there, including while a
        // native worker owns the next epoch. Never enter its SQL handoff.
        if self.is_native() {
            return self.reject_native_sql_fallback();
        }
        let mut state = lock_state(&self.shared)?;
        while (state.checkpoint_requested || state.snapshot.is_some())
            && state.status == Status::Running
        {
            state = self
                .shared
                .ready
                .wait(state)
                .map_err(|_| io::Error::other("private WAL snapshot handoff wait poisoned"))?;
        }
        if state.status != Status::Running {
            return Err(io::Error::other("private WAL snapshot owner is fenced"));
        }
        if let Err(error) = application::validate_live_cache(conn, &state, self.binding) {
            application::fence(&mut state);
            self.shared.ready.notify_all();
            return Err(error);
        }
        state.snapshot = Some(Handoff {
            candidate: candidate.clone(),
            transform,
            installation: installation.clone(),
            phase: Phase::Requested,
        });
        let mut owner = HandoffOwner {
            shared: Arc::clone(&self.shared),
            completed: false,
        };
        self.shared.ready.notify_all();
        // Drop the mutex before an error can drop the phase owner and fence.
        drop(state);
        let result = (|| {
            let mut state = lock_state(&self.shared)?;
            let pending = loop {
                if state.status != Status::Running {
                    return Err(io::Error::other("private WAL snapshot preparation failed"));
                }
                match state.snapshot.as_ref().map(|handoff| &handoff.phase) {
                    Some(Phase::Prepared(pending)) => break pending.clone(),
                    Some(Phase::Requested) => {}
                    _ => {
                        return Err(invalid_data(
                            "private WAL snapshot preparation phase differs",
                        ))
                    }
                }
                state = self.shared.ready.wait(state).map_err(|_| {
                    io::Error::other("private WAL snapshot preparation wait poisoned")
                })?;
            };
            let next_guard = std::cell::RefCell::new(None);
            (self.control.hook)(Point::BeforeSnapshotCacheWrite)?;
            let before_write = |tx: &Transaction<'_>| {
                application::validate_cache_guard(tx, &state)?;
                // The projection already contains NEW metadata. Compare
                // the OLD whole application digest before the first write.
                if application::application_digest(tx)? != pending.old_application {
                    return Err(invalid_data(
                        "private WAL snapshot cache changed before publication",
                    ));
                }
                Ok(())
            };
            let before_commit = |tx: &Transaction<'_>| {
                if transform == Transform::Install {
                    if let Some(marker) = &state.application_marker {
                        application::write_marker(tx, marker)?;
                    }
                } else {
                    transform.finish_metadata_tx(tx, self.binding, &candidate)?;
                }
                application::audit_snapshot_cache(
                    tx,
                    &state.conn,
                    self.binding,
                    &state.application_marker,
                )?;
                (self.control.hook)(Point::BeforeSnapshotCacheCommit)?;
                *next_guard.borrow_mut() = Some(application::capture_cache_guard(tx, &state)?);
                Ok(())
            };
            if let Some(installation) = &installation {
                installation.source.apply_original(
                    conn,
                    self.binding,
                    &installation.incarnation,
                    before_write,
                    before_commit,
                )?;
            } else {
                consensus::save_current_snapshot_with_authority_and_hooks_sync(
                    conn,
                    self.binding.identity,
                    state.authority.profile,
                    &state.authority.members,
                    &state.authority.bindings,
                    state.authority.placement,
                    &candidate.0,
                    &candidate.1,
                    candidate.2,
                    candidate.3,
                    before_write,
                    before_commit,
                )?;
            }
            (self.control.hook)(Point::AfterSnapshotCacheCommit)?;
            if let Some(installation) = &installation {
                installation.source.verify()?;
            }
            if consensus::read_current_snapshot_sync(conn, self.binding.identity)?.as_ref()
                != Some(&candidate)
            {
                return Err(invalid_data(
                    "private WAL snapshot metadata readback differs",
                ));
            }
            application::complete_snapshot_cache(
                &mut state,
                conn,
                self.binding,
                next_guard
                    .into_inner()
                    .ok_or_else(|| invalid_data("private WAL snapshot commit guard is missing"))?,
            )?;
            state.snapshot = Some(Handoff {
                candidate,
                transform,
                installation,
                phase: Phase::Committed(pending),
            });
            self.shared.ready.notify_all();
            while state.snapshot.is_some() {
                if state.status != Status::Running {
                    return Err(io::Error::other("private WAL snapshot selection failed"));
                }
                state = self.shared.ready.wait(state).map_err(|_| {
                    io::Error::other("private WAL snapshot selection wait poisoned")
                })?;
            }
            if state.status != Status::Running {
                return Err(io::Error::other("private WAL snapshot publication failed"));
            }
            application::validate_live_cache(conn, &state, self.binding)
        })();
        owner.completed = result.is_ok();
        result
    }
}

pub(super) fn advance(
    state: &mut State,
    disk: &mut Disk,
    binding: Binding,
    limits: Limits,
    control: &IoControl,
) -> io::Result<()> {
    if state.status != Status::Running || state.outstanding != 0 || !state.queue.is_empty() {
        return Err(invalid_data("private WAL snapshot handoff is not drained"));
    }
    let handoff = state
        .snapshot
        .take()
        .ok_or_else(|| invalid_data("private WAL snapshot handoff is missing"))?;
    match handoff.phase {
        Phase::Requested => {
            checkpoint::publish(state, disk, binding, limits, control)?;
            let old = disk
                .anchor
                .clone()
                .ok_or_else(|| invalid_data("private WAL snapshot old basis is missing"))?;
            let old_application = application::application_digest(&state.conn)?;
            application::validate_applied_prefix(state, binding)?;
            state.applied_prefix = None;
            if let Some(installation) = &handoff.installation {
                if handoff.transform != Transform::Install
                    || handoff.candidate != installation.source.candidate
                {
                    return Err(invalid_data("private WAL install request source differs"));
                }
                installation.source.apply_original(
                    &state.conn,
                    binding,
                    &installation.incarnation,
                    |_| Ok(()),
                    |_| Ok(()),
                )?;
                state.authority = Authority::load(&state.conn, binding.identity)?;
                state.durable_committed = read_committed_sync(&state.conn, binding.identity)?;
                if state.durable_committed != handoff.candidate.0.last_log_id
                    || read_applied_sync(&state.conn, binding.identity)?
                        != handoff.candidate.0.last_log_id
                {
                    return Err(invalid_data(
                        "private WAL install committed frontier differs",
                    ));
                }
                state.application_marker =
                    installed_marker(binding, disk.position(), handoff.candidate.0.last_log_id)?;
                state.durable_cuts = BTreeMap::from([(
                    disk.sequence,
                    DurableCut {
                        chain: disk.chain,
                        committed: state.durable_committed,
                        installed: Some(InstalledCut::new(old.epoch + 1, &handoff.candidate)?),
                    },
                )]);
            } else {
                save_original(&state.conn, binding, &handoff.candidate, handoff.transform)?;
            }
            let new = checkpoint::prepare(state, disk, binding, limits, control)?;
            let pending = Pending {
                old,
                new,
                old_application,
                new_application: application::application_digest(&state.conn)?,
                transform: handoff.transform,
            };
            pending.load_images(
                &disk.directory,
                binding,
                limits,
                handoff
                    .installation
                    .as_ref()
                    .map(|installation| &installation.source),
                true,
            )?;
            pending.publish(&disk.directory, control)?;
            state.snapshot = Some(Handoff {
                candidate: handoff.candidate,
                transform: handoff.transform,
                installation: handoff.installation,
                phase: Phase::Prepared(pending),
            });
        }
        Phase::Committed(pending) => {
            if let Some(installation) = &handoff.installation {
                installation.source.verify()?;
            }
            checkpoint::select(&disk.directory, &pending.new, control)?;
            if let Some(installation) = &handoff.installation {
                installation.source.verify()?;
            }
            retire_proof(&disk.directory, "SNAPSHOT.pending", control)?;
            checkpoint::finish(state, disk, pending.new, control)?;
        }
        Phase::Prepared(_) => {
            return Err(invalid_data(
                "private WAL snapshot cache commit was abandoned",
            ))
        }
    }
    Ok(())
}

fn retire_proof(directory: &Path, name: &str, control: &IoControl) -> io::Result<()> {
    (control.hook)(Point::BeforeSnapshotProofRetire)?;
    fs::remove_file(directory.join(name))?;
    (control.hook)(Point::AfterSnapshotProofUnlink)?;
    (control.hook)(Point::BeforeSnapshotProofRetireSync)?;
    File::open(directory)?.sync_all()?;
    (control.hook)(Point::AfterSnapshotProofRetireSync)
}

#[cfg(test)]
struct Image {
    conn: Connection,
    audit: RecoveryAudit,
}

/// An unusable opening owner. Its flock survives asynchronous immutable-file
/// checks in storage.rs, before snapshot scavenging or legacy reseeding runs.
#[cfg(test)]
pub(crate) struct Opening {
    directory: PathBuf,
    binding: Binding,
    limits: Limits,
    control: IoControl,
    lock: File,
    selected: Option<checkpoint::Anchor>,
    proof: Proof,
    snapshots: Vec<CurrentSnapshot>,
    install_candidate: Option<CurrentSnapshot>,
}

#[cfg(test)]
impl Opening {
    #[cfg(test)]
    pub(in crate::sqlite::consensus) fn new(
        directory: &Path,
        binding: Binding,
        limits: Limits,
        control: IoControl,
    ) -> io::Result<Self> {
        let limits = limits.validate()?;
        if !fs::symlink_metadata(directory)?.is_dir() {
            return Err(invalid_data("private WAL opening directory is invalid"));
        }
        let lock = file_read(&directory.join("LOCK"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        let mut opening = Self {
            directory: directory.to_path_buf(),
            binding,
            limits,
            control,
            lock,
            selected: checkpoint::read(directory, binding, limits)?,
            proof: read_proof(directory, binding, limits)?,
            snapshots: Vec::new(),
            install_candidate: None,
        };
        let (old, new) = opening.audit_images(None, false)?;
        if matches!(&opening.proof, Proof::Pending(pending) if pending.transform == Transform::Install)
        {
            opening.install_candidate = Some(
                consensus::read_current_snapshot_sync(
                    &new.as_ref()
                        .ok_or_else(|| invalid_data("private WAL install image is missing"))?
                        .conn,
                    binding.identity,
                )?
                .ok_or_else(|| invalid_data("private WAL install metadata is missing"))?,
            );
        }
        for image in std::iter::once(&old).chain(new.iter()) {
            if let Some(snapshot) =
                consensus::read_current_snapshot_sync(&image.conn, binding.identity)?
            {
                if !opening.snapshots.contains(&snapshot) {
                    opening.snapshots.push(snapshot);
                }
            }
        }
        Ok(opening)
    }

    #[cfg(test)]
    pub(crate) fn snapshots(&self) -> Vec<CurrentSnapshot> {
        self.snapshots.clone()
    }

    #[cfg(test)]
    pub(crate) fn install_candidate(&self) -> Option<CurrentSnapshot> {
        self.install_candidate.clone()
    }

    #[cfg(test)]
    fn audit_images(
        &self,
        install_source: Option<&InstallSource>,
        require_install_source: bool,
    ) -> io::Result<(Image, Option<Image>)> {
        if read_proof(&self.directory, self.binding, self.limits)? != self.proof
            || checkpoint::read(&self.directory, self.binding, self.limits)? != self.selected
        {
            return Err(invalid_data(
                "private WAL snapshot authority changed during open",
            ));
        }
        let image = |conn, anchor, pending| -> io::Result<Image> {
            let audit = audit_recovery(
                &self.directory,
                self.binding,
                self.limits,
                &conn,
                anchor,
                true,
            )?;
            if pending
                && (audit.stage.is_some()
                    || audit.history_bytes != 0
                    || audit.anchor.as_ref().is_none_or(|anchor| {
                        audit.end != anchor.position || audit.cut != anchor.cut
                    }))
            {
                return Err(invalid_data(
                    "private WAL snapshot proof crossed another WAL operation",
                ));
            }
            Ok(Image { conn, audit })
        };
        if let Proof::Pending(pending) = &self.proof {
            if self.selected.as_ref() != Some(&pending.old)
                && self.selected.as_ref() != Some(&pending.new)
            {
                return Err(invalid_data(
                    "private WAL snapshot selector is outside its proof",
                ));
            }
            let (old, new) = pending.load_images(
                &self.directory,
                self.binding,
                self.limits,
                install_source,
                require_install_source,
            )?;
            Ok((
                image(old, Some(pending.old.clone()), true)?,
                Some(image(new, Some(pending.new.clone()), true)?),
            ))
        } else {
            let conn = match &self.selected {
                Some(anchor) => anchor.load_basis(&self.directory, self.binding)?,
                None => load_basis(&self.directory, self.binding)?,
            };
            Ok((image(conn, self.selected.clone(), false)?, None))
        }
    }

    #[cfg(test)]
    pub(in crate::sqlite::consensus) fn finish(
        self,
        cache: &Connection,
        caps: &BackendCapabilities,
        verify_descriptors: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Wal> {
        self.finish_with_install_source(cache, caps, None, verify_descriptors)
    }

    #[cfg(test)]
    pub(in crate::sqlite::consensus) fn finish_with_install_source(
        self,
        cache: &Connection,
        caps: &BackendCapabilities,
        install_source: Option<&InstallSource>,
        verify_descriptors: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Wal> {
        let tx =
            Transaction::new_unchecked(cache, TransactionBehavior::Immediate).map_err(db_error)?;
        // Repeat the disk audit after asynchronous descriptor validation, with
        // the exact cache image now held under its write-exclusion transaction.
        let (old, new) = self.audit_images(install_source, true)?;
        let chosen = if let Proof::Pending(pending) = &self.proof {
            let observed = application::application_digest(&tx)?;
            let chosen = if observed == pending.old_application {
                if self.selected.as_ref() != Some(&pending.old) {
                    return Err(invalid_data(
                        "private WAL selected new snapshot has the old cache",
                    ));
                }
                old
            } else if observed == pending.new_application {
                new.ok_or_else(|| invalid_data("private WAL snapshot new image is missing"))?
            } else {
                return Err(invalid_data(
                    "private WAL snapshot cache matches neither bound image",
                ));
            };
            application::audit_snapshot_cache(
                &tx,
                &chosen.conn,
                self.binding,
                &chosen
                    .audit
                    .anchor
                    .as_ref()
                    .ok_or_else(|| invalid_data("private WAL chosen snapshot anchor is missing"))?
                    .marker,
            )?;
            chosen
        } else {
            old
        };
        let mut state = State::recovered(
            self.binding,
            chosen.conn,
            chosen.audit.history_bytes,
            chosen.audit.end,
            chosen.audit.anchor.as_ref(),
            chosen.audit.verified_cuts.clone(),
            None,
        )?;
        let restored = application::restore_transaction(&mut state, &tx, caps, self.binding)?;
        verify_descriptors()?;
        let audit = if let Proof::Pending(_) = &self.proof {
            let anchor =
                chosen.audit.anchor.as_ref().ok_or_else(|| {
                    invalid_data("private WAL snapshot resolved anchor is missing")
                })?;
            if self.selected.as_ref() != Some(anchor) {
                // A prior interrupted selector write is disposable only now,
                // after both bases, all WAL history, cache and pins passed.
                let preparation = self.directory.join("CURRENT.preparing");
                match fs::remove_file(&preparation) {
                    Ok(()) => File::open(&self.directory)?.sync_all()?,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                checkpoint::select(&self.directory, anchor, &self.control)?;
            }
            // CURRENT may already be the new name after an unsynced rename.
            // Stabilize it before unlinking proof in every resolution outcome.
            (self.control.hook)(Point::BeforeRecoveryPublicationSync)?;
            File::open(&self.directory)?.sync_all()?;
            (self.control.hook)(Point::AfterRecoveryPublicationSync)?;
            retire_proof(&self.directory, "SNAPSHOT.pending", &self.control)?;
            audit_recovery(
                &self.directory,
                self.binding,
                self.limits,
                &state.conn,
                Some(anchor.clone()),
                false,
            )?
        } else {
            if matches!(self.proof, Proof::Preparing(_)) {
                retire_proof(&self.directory, "SNAPSHOT.preparing", &self.control)?;
            }
            chosen.audit
        };
        let (disk, _) = audit.finish(&self.directory, self.lock, &self.control)?;
        tx.commit().map_err(db_error)?;
        application::finish_restore(&mut state, cache, self.binding, restored)?;
        Wal::start_state(self.binding, self.limits, state, disk, self.control, None)
    }
}
