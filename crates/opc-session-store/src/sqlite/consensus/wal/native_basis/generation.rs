//! Exclusive cold construction of the initial append generation. All native,
//! WAL-cut and strict-snapshot admission precedes this call. No live State or
//! writer exists yet, so complete base encoding/admission stays outside its
//! mutex and never overlaps a second decoded historical model.

use super::*;
use crate::consensus::native::generation::{Catalog, PreparedBase, Version};
use crate::consensus::native::prefix::VerifiedAppendOwner;
use crate::consensus::verified_snapshot::VerificationMemory;

pub(in crate::sqlite::consensus::wal) struct Selected {
    pub(super) append: VerifiedAppendOwner,
    pub(super) version: Version,
}

impl Selected {
    pub(in crate::sqlite::consensus::wal) fn admitted(
        append: VerifiedAppendOwner,
        native: &NativeStorage,
    ) -> io::Result<Self> {
        let version = Version::capture(native)?;
        if version.context_digest()? != append.current().identity().frontiers {
            return Err(invalid_data(
                "native selected process version differs from admitted prefix",
            ));
        }
        Ok(Self { append, version })
    }

    pub(in crate::sqlite::consensus::wal) fn repair(
        &mut self,
        path: &Path,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        self.append.repair_unselected_tail(path, check)
    }
}

pub(in crate::sqlite::consensus::wal) fn bootstrap(
    native: NativeStorage,
    disk: &mut Disk,
    binding: Binding,
    limits: Limits,
    control: &IoControl,
) -> io::Result<(NativeStorage, Selected)> {
    let epoch = disk
        .anchor
        .as_ref()
        .map_or(0, |anchor| anchor.epoch)
        .checked_add(1)
        .filter(|epoch| *epoch != u64::MAX)
        .ok_or_else(|| invalid_data("native bootstrap checkpoint epoch exhausted"))?;
    let file_epoch = disk
        .anchor
        .as_ref()
        .map_or(0, checkpoint::Anchor::file_epoch)
        .checked_add(1)
        .filter(|epoch| *epoch != u64::MAX)
        .ok_or_else(|| invalid_data("native bootstrap file epoch exhausted"))?;
    let position = disk.position();
    let durable_cut = *disk
        .cuts
        .get(&position.sequence)
        .filter(|cut| {
            cut.chain == position.chain
                && cut.committed == native.log.committed
                && cut.installed.is_none()
        })
        .ok_or_else(|| invalid_data("native bootstrap lacks its exact durable cut"))?;
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
        applied: native.business.applied(),
        marker: None,
        cuts: BTreeMap::from([(position.sequence, durable_cut)]),
        native: true,
        native_generation: Some(checkpoint::NativeGeneration {
            file_epoch,
            block_bytes: 64 * 1024,
            frontiers: [0; 32],
        }),
        native_snapshots: None,
    };
    let cut_binding = anchor.native_cut_binding()?;
    let preparing = disk
        .directory
        .join(format!("basis-{file_epoch:020}.preparing"));
    let final_path = anchor.basis_path(&disk.directory);
    (control.hook)(Point::BeforeBasisCreate)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&preparing)?;
    (control.hook)(Point::AfterBasisCreate)?;
    let identity = {
        let _io_memory = VerificationMemory::reserve(128 * 1024)?;
        let base = PreparedBase::prepare(
            &native,
            binding.digest()?,
            file_epoch,
            epoch,
            position.sequence,
            cut_binding,
            64 * 1024,
            MAX_BASIS,
            &|| Ok(()),
        )?;
        let mut output = io::BufWriter::with_capacity(64 * 1024, &mut file);
        let identity = base.write_to(&mut output, &|| Ok(()))?;
        output.flush()?;
        identity
    };
    (control.hook)(Point::BeforeBasisSync)?;
    file.sync_all()?;
    (control.hook)(Point::AfterBasisSync)?;
    drop(file);
    anchor.basis = identity.digest;
    anchor.basis_bytes = identity.length;
    anchor.native_generation = Some(checkpoint::NativeGeneration {
        file_epoch,
        block_bytes: identity.block_bytes,
        frontiers: identity.frontiers,
    });
    anchor.validate(binding, limits)?;
    crate::consensus::snapshot::rename_noreplace_in_directory(
        &File::open(&disk.directory)?,
        preparing
            .file_name()
            .ok_or_else(|| invalid_data("native bootstrap preparation name missing"))?,
        final_path
            .file_name()
            .ok_or_else(|| invalid_data("native bootstrap final name missing"))?,
    )?;
    (control.hook)(Point::AfterBasisRename)?;
    File::open(&disk.directory)?.sync_all()?;
    (control.hook)(Point::AfterBasisDirectorySync)?;
    let members = native.business.members().clone();
    let roster_root = native.business.roster_root().cloned();
    // The next reader reconstructs the sole prospective resident index. Keep
    // neither a decoded predecessor model nor its payload-bearing roots alive.
    drop(native);
    let (append, catalog) = Catalog::open(
        &final_path,
        identity,
        MAX_BASIS,
        binding.identity,
        &members,
        roster_root,
        cut_binding,
        &|| Ok(()),
    )?;
    if catalog.cut_binding() != cut_binding || catalog.identity() != identity {
        return Err(invalid_data("native bootstrap catalog binding differs"));
    }
    (control.hook)(Point::AfterNativeBasisAdmission)?;
    let mut native = catalog.into_storage(&|| Ok(()))?;
    let mut selected = Selected::admitted(append, &native)?;
    // Recheck all selected bytes and named descriptor after conversion before
    // publication, including an exact-length repeated cold recovery attempt.
    selected.repair(&final_path, &|| Ok(()))?;
    native.begin_changes()?;
    checkpoint::select(&disk.directory, &anchor, control)?;
    checkpoint::reclaim_covered(disk, &anchor, control)?;
    disk.cuts
        .retain(|sequence, _| *sequence >= position.sequence);
    disk.anchor = Some(anchor);
    Ok((native, selected))
}
