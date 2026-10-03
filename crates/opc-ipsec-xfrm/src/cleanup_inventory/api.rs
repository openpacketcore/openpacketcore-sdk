use std::{fmt, path::PathBuf};

use super::{
    filesystem::{DirectoryIo, OpenMode},
    node::{InventoryKey, NodeContext, NodeKind},
    store::{resource_bounds, SnapshotStore},
    tree::{ChildReference, FormatBudget, InventoryLimits, RootPage, COMPLETION_BYTES, FANOUT},
    InventoryError,
};
use crate::{
    NamespaceBoundLinuxXfrmBackend, XfrmObjectInstallRecoveryStore, XfrmObjectRecoveryProofKey,
    XfrmObjectRosterRecoveryProofKey, XfrmObjectRosterRecoveryStore,
    XfrmSaRelocationRecoveryProofKey, XfrmSaRelocationRecoveryStore,
};
use rand::{rngs::SysRng, TryRng};

/// Secret authenticating and encrypting one cleanup inventory.
///
/// Retain this key with the inventory across process restarts. Its bytes are
/// zeroized on drop and never included in debug output.
pub struct XfrmCleanupInventoryKey(pub(super) InventoryKey);

impl XfrmCleanupInventoryKey {
    /// Accept a nonzero, caller-provisioned 256-bit key.
    ///
    /// # Errors
    /// Returns an authentication error for the all-zero key.
    pub fn new(bytes: [u8; 32]) -> Result<Self, super::XfrmCleanupInventoryError> {
        if bytes == [0; 32] {
            return Err(InventoryError::Authentication);
        }
        Ok(Self(InventoryKey::new(bytes)))
    }
}

/// Whether an inventory must be absent or must already be authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmCleanupInventoryOpenMode {
    /// Exclusively create a new inventory directory; never adopt an existing one.
    CreateNew,
    /// Require an existing complete inventory and its exact transaction stores.
    Reopen,
}

/// Explicit capacity and logical allocation budgets for a cleanup inventory.
///
/// Counts include unresolved and orphaned records. Byte budgets exclude
/// filesystem metadata and block rounding, allocator metadata, thread stacks,
/// and other process memory; provision those separately. No session count or
/// default capacity is inferred.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XfrmCleanupInventoryLimits {
    /// Maximum concurrent object lifecycles.
    pub objects: u32,
    /// Maximum reserved candidate images across those objects.
    pub images: u32,
    /// Maximum retained transaction-coverage records.
    pub coverage: u32,
    /// Maximum changed records in one atomic publication.
    pub batch_records: u32,
    /// Content reservation including both node slots and interrupted staging.
    pub storage_bytes: u64,
    /// Budget for the fixed, keyed locator index.
    pub index_bytes: u64,
    /// Budget for bounded parser and publication values and allocations.
    pub working_bytes: u64,
}

impl From<XfrmCleanupInventoryLimits> for InventoryLimits {
    fn from(value: XfrmCleanupInventoryLimits) -> Self {
        Self {
            objects: value.objects,
            images: value.images,
            coverage: value.coverage,
            batch_records: value.batch_records,
            storage_bytes: value.storage_bytes,
            index_bytes: value.index_bytes,
            working_bytes: value.working_bytes,
        }
    }
}

/// Configuration for the encrypted, permanently leased inventory.
pub struct XfrmCleanupInventoryConfig {
    /// Absolute directory path with no symlink components.
    pub path: PathBuf,
    /// Secret retained across restarts of this inventory.
    pub key: XfrmCleanupInventoryKey,
    /// Explicit create or reopen intent.
    pub mode: XfrmCleanupInventoryOpenMode,
    /// Complete capacity and byte budgets, identical on reopen.
    pub limits: XfrmCleanupInventoryLimits,
}

/// Inventory and the complete set of transaction stores bound to its actor.
///
/// Reopen authenticates every configured store without initializing,
/// reconciling, trimming or settling it. The authenticated inventory must name
/// exactly this set of store incarnations.
///
/// The initial experimental inventory requires journal-backed roster stores.
/// Create-new initializes an absent roster directory; an existing directory
/// must already authenticate as a complete journal without repair. Legacy named
/// roster records remain supported by the ordinary recovery APIs, but are not
/// accepted or migrated by inventory binding. The inventory format is not yet
/// a qualified compatibility contract.
pub struct XfrmCleanupInventoryBindingConfig {
    /// Cleanup-inventory configuration.
    pub inventory: XfrmCleanupInventoryConfig,
    /// Optional durable single-object transaction store.
    pub object_recovery: Option<(PathBuf, XfrmObjectRecoveryProofKey)>,
    /// Optional durable SA-relocation transaction store.
    pub sa_relocation_recovery: Option<(PathBuf, XfrmSaRelocationRecoveryProofKey)>,
    /// Optional durable grouped-roster transaction store.
    pub roster_recovery: Option<(PathBuf, XfrmObjectRosterRecoveryProofKey)>,
}

/// A bound actor whose operational commands remain closed.
///
/// This prefix provides persistence and status only. It provides no cleanup,
/// journal settlement, completion seal or activation authority.
pub struct XfrmCleanupInventoryBinding {
    /// Actor shared by all clones; only its inventory status is available.
    pub backend: NamespaceBoundLinuxXfrmBackend,
    /// Configured object transaction store, if any.
    pub object_recovery: Option<XfrmObjectInstallRecoveryStore>,
    /// Configured relocation transaction store, if any.
    pub sa_relocation_recovery: Option<XfrmSaRelocationRecoveryStore>,
    /// Configured roster transaction store, if any.
    pub roster_recovery: Option<XfrmObjectRosterRecoveryStore>,
}

/// Authenticated inventory status. This is not traffic readiness.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmCleanupInventoryStatus {
    /// Exact removal is unavailable and every operational command is closed.
    ExactRemovalUnavailable,
}

macro_rules! redacted_debug {
    ($($value:ty),+ $(,)?) => {$(
        impl fmt::Debug for $value {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($value), "(<redacted>)"))
            }
        }
    )+};
}
redacted_debug!(
    XfrmCleanupInventoryKey,
    XfrmCleanupInventoryLimits,
    XfrmCleanupInventoryConfig,
    XfrmCleanupInventoryBindingConfig,
    XfrmCleanupInventoryBinding,
);

const FORMAT: FormatBudget = FormatBudget {
    record_bytes: 1024,
    manifest_bytes: 16384,
    root_bytes: 20480,
};

impl XfrmCleanupInventoryConfig {
    pub(crate) fn validate(&self) -> Result<(), InventoryError> {
        let limits: InventoryLimits = self.limits.into();
        let required = resource_bounds(limits, FORMAT)?;
        if required.content_bytes > limits.storage_bytes
            || required.index_bytes > limits.index_bytes
            || required.working_bytes > limits.working_bytes
        {
            return Err(InventoryError::Capacity);
        }
        Ok(())
    }
}

pub(crate) struct PendingInventory {
    io: DirectoryIo,
    key: InventoryKey,
    mode: XfrmCleanupInventoryOpenMode,
    context: NodeContext,
    limits: InventoryLimits,
}

pub(crate) struct BoundInventory(SnapshotStore<DirectoryIo>);

impl PendingInventory {
    pub(crate) fn open(
        config: XfrmCleanupInventoryConfig,
        namespace: [u8; 40],
    ) -> Result<Self, InventoryError> {
        config.validate()?;
        let limits = config.limits.into();
        let io = DirectoryIo::open(
            &config.path,
            match config.mode {
                XfrmCleanupInventoryOpenMode::CreateNew => OpenMode::CreateNew,
                XfrmCleanupInventoryOpenMode::Reopen => OpenMode::Reopen,
            },
            limits,
            FORMAT,
        )?;
        let (device, inode) = io.identity();
        let mut incarnation = [0; 16];
        if config.mode == XfrmCleanupInventoryOpenMode::CreateNew {
            SysRng
                .try_fill_bytes(&mut incarnation)
                .map_err(|_| InventoryError::Unavailable)?;
            if incarnation == [0; 16] {
                return Err(InventoryError::Unavailable);
            }
        }
        Ok(Self {
            io,
            key: config.key.0,
            mode: config.mode,
            context: NodeContext {
                namespace,
                incarnation,
                device,
                inode,
                generation: 1,
                revision: 1,
                kind: NodeKind::Root,
                position: 0,
                slot: 0,
            },
            limits,
        })
    }

    pub(crate) fn finish(
        self,
        stores: [Option<[u8; 16]>; 3],
    ) -> Result<BoundInventory, InventoryError> {
        let store = match self.mode {
            XfrmCleanupInventoryOpenMode::CreateNew => SnapshotStore::create(
                self.io,
                self.key,
                self.context,
                RootPage {
                    next_serial: 1,
                    limits: self.limits,
                    stores,
                    completion: [0; COMPLETION_BYTES],
                    children: [ChildReference::EMPTY; FANOUT],
                },
                FORMAT,
            )?,
            XfrmCleanupInventoryOpenMode::Reopen => {
                let mut store = SnapshotStore::reopen(
                    self.io,
                    self.key,
                    self.context,
                    self.limits,
                    stores,
                    FORMAT,
                )?;
                // A new actor generation uses the atomic publication protocol,
                // preserving all older child references and records.
                store.apply(Vec::new(), true)?;
                store
            }
        };
        Ok(BoundInventory(store))
    }
}

impl BoundInventory {
    pub(crate) fn status(
        &self,
        stores: [Option<[u8; 16]>; 3],
    ) -> Result<XfrmCleanupInventoryStatus, InventoryError> {
        self.0.check_store_bindings(stores)?;
        Ok(XfrmCleanupInventoryStatus::ExactRemovalUnavailable)
    }
}
