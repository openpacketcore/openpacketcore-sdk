//! Opt-in, numeric observations of original SDK encryption buffers.
//!
//! Callbacks run synchronously while the registered originals are borrowed or
//! owned. They may join other observations at that instant; saved receipts are
//! not proof of later liveness. No payload, key, provider object, or observation
//! clone of a payload owner is retained. Addresses are process-local identities
//! and must not be published in logs.
//!
//! The fixed inventory bounds observation metadata. These are Vec capacities
//! and Arc slice data extents, not allocator usable sizes, RSS, provider-private
//! storage, Arc headers, or allocator-internal realloc / Vec
//! to Arc conversion overlap. Borrowed rows retire immediately before releasing
//! their borrow; destructor tails are outside their measured interval. This
//! seam alone cannot establish a whole-operation capacity limit.

use std::future::Future;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

#[cfg(test)]
#[path = "capacity_observation_tests.rs"]
mod tests;

/// Maximum simultaneous distinct original-buffer rows per observer.
pub const MAX_BUFFER_ROWS: usize = 128;

/// Actual allocation site, independent of the request's logical byte limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferKind {
    /// Adapter's reserved zeroizing plaintext Vec.
    AdapterPlaintext,
    /// First bound-AAD encoding used to check the exact AAD ceiling.
    PreflightAad,
    /// SDK-owned principal JSON String in the typed AAD.
    AadPrincipal,
    /// SDK-owned store-kind String in the typed AAD.
    AadStoreKind,
    /// Tenant String owned by the typed AAD.
    AadTenant,
    /// Key identifier owned by the provider-returned handle.
    ProviderKeyId,
    /// Tenant String owned by the provider-returned handle.
    ProviderTenant,
    /// Key identifier cloned into the temporary envelope encoder.
    EnvelopeKeyId,
    /// Bound-AAD Vec passed to the cipher and then envelope encoding.
    BoundAad,
    /// HKDF salt Vec.
    KdfSalt,
    /// HKDF info Vec.
    KdfInfo,
    /// Ciphertext Vec, including its actual spare capacity after tag growth.
    Ciphertext,
    /// Owned nonce Vec used during envelope encoding.
    EnvelopeNonce,
    /// Encoded envelope Vec before conversion to Arc storage.
    EncodedEnvelope,
    /// Shared immutable envelope data; aliases occupy one allocation row.
    EnvelopeArc,
    /// Independent encrypted_blob Vec in the sealed datastore record.
    RecordBlob,
}

/// Opaque numeric identity of an original allocation. Equality and hashing can
/// join simultaneous receipts without exposing addresses in debug output.
/// Reused addresses after destruction do not identify the same lifetime.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllocationIdentity(usize);

impl AllocationIdentity {
    /// Read an identity from borrowed original storage without retaining it.
    pub fn of(original: &[u8]) -> Self {
        Self(original.as_ptr() as usize)
    }
}

impl std::fmt::Debug for AllocationIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AllocationIdentity(<redacted>)")
    }
}

/// Numeric receipt borrowed from an original allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferReceipt {
    /// Caller-selected operation identity, local to this observation scope.
    pub operation: u64,
    /// Allocation site.
    pub kind: BufferKind,
    /// Original data address; identity only, never dereferenced by the observer.
    pub identity: AllocationIdentity,
    /// Initialized bytes in the original owner at this observation.
    pub length: usize,
    /// Original Vec/String capacity, or exact Arc slice data extent.
    pub capacity: usize,
    /// Number of registered aliases of this same allocation.
    pub aliases: usize,
}

/// One simultaneous inventory, valid only during its synchronous callback.
#[derive(Clone, Copy, Debug)]
pub struct BufferSnapshot {
    /// Fixed storage; vacant entries are None.
    pub buffers: [Option<BufferReceipt>; MAX_BUFFER_ROWS],
    /// True if metadata overflowed; such an inventory is incomplete evidence.
    pub overflowed: bool,
    /// Monotonic observation event count, including registrations and releases.
    pub events: u64,
}

impl Default for BufferSnapshot {
    fn default() -> Self {
        Self {
            buffers: [None; MAX_BUFFER_ROWS],
            overflowed: false,
            events: 0,
        }
    }
}

impl BufferSnapshot {
    /// Sum the physical allocation identity union across all operation/role
    /// rows, including shared borrows and Arc aliases. Conflicting extents
    /// invalidate the snapshot at registration.
    pub fn data_capacity(&self) -> usize {
        self.unique_allocations().map(|row| row.capacity).sum()
    }

    /// Number of distinct physical identities across all operation/role rows.
    pub fn allocations(&self) -> usize {
        self.unique_allocations().count()
    }

    fn unique_allocations(&self) -> impl Iterator<Item = &BufferReceipt> {
        self.buffers.iter().enumerate().filter_map(|(index, row)| {
            row.as_ref().filter(|row| {
                !self.buffers[..index]
                    .iter()
                    .flatten()
                    .any(|previous| previous.identity == row.identity)
            })
        })
    }
}

/// Synchronous event at an original buffer lifetime boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferEvent {
    /// An original allocation or actual Arc alias was registered.
    Registered(BufferKind),
    /// A borrow ended, or an owned Arc alias was destroyed under the capture lock.
    Released(BufferKind),
    /// Named production checkpoint with all enclosing original borrows held.
    Checkpoint(&'static str),
    /// Actual destination-store reservation identity; no reservation is cloned.
    Reservation {
        /// Caller-selected operation identity.
        operation: u64,
        /// Address of the original shared reservation lease.
        identity: AllocationIdentity,
    },
}

type Callback = dyn Fn(BufferEvent, &BufferSnapshot) + Send + Sync;

/// Bounded inventory and callback port, shared only as observation metadata.
///
/// Callbacks execute under its capture/drop mutex. They must not reenter this
/// observer or block on a task that needs it. A callback can synchronously
/// capture independent native/transport observations with consistent lock order.
pub struct BufferObservation {
    state: Mutex<BufferSnapshot>,
    callback: Box<Callback>,
}

impl BufferObservation {
    /// Install a synchronous numeric-only callback.
    pub fn new(callback: impl Fn(BufferEvent, &BufferSnapshot) + Send + Sync + 'static) -> Self {
        Self {
            state: Mutex::new(BufferSnapshot::default()),
            callback: Box::new(callback),
        }
    }

    /// Inspect live rows under the same lock used to retire/destroy owners.
    /// No original is guaranteed to remain live after this callback returns.
    pub fn capture<R>(&self, inspect: impl FnOnce(&BufferSnapshot) -> R) -> R {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        inspect(&state)
    }

    /// Fixed observer storage, excluding the caller's callback capture and
    /// per-guard metadata (which does not contain payload storage).
    pub const fn fixed_metadata_bytes() -> usize {
        std::mem::size_of::<Self>()
    }

    fn event(&self, event: BufferEvent) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.events += 1;
        (self.callback)(event, &state);
    }
}

#[derive(Clone)]
struct Context {
    observation: Arc<BufferObservation>,
    operation: u64,
}

tokio::task_local! {
    static CURRENT: Context;
}

/// Observe one future with a local operation identity. Task-local context is
/// installed for each poll and for cancellation; spawned tasks need their own
/// scope. Wrapping a future creates no payload owners or preparation slots.
pub async fn scope<F: Future>(
    observation: Arc<BufferObservation>,
    operation: u64,
    future: F,
) -> F::Output {
    CURRENT
        .scope(
            Context {
                observation,
                operation,
            },
            future,
        )
        .await
}

/// Emit a synchronous checkpoint under all currently held original borrows.
pub fn checkpoint(name: &'static str) {
    let _ = CURRENT.try_with(|context| {
        context.observation.event(BufferEvent::Checkpoint(name));
    });
}

/// Inspect the current operation's observer synchronously. Originals remain
/// held for this callback; the result does not extend their lifetime.
pub fn capture_current<R>(inspect: impl FnOnce(&BufferSnapshot) -> R) -> Option<R> {
    CURRENT
        .try_with(|context| context.observation.capture(inspect))
        .ok()
}

/// Bind an event to the original destination-store preparation lease.
#[doc(hidden)]
pub fn reservation(identity: usize) {
    let _ = CURRENT.try_with(|context| {
        context.observation.event(BufferEvent::Reservation {
            operation: context.operation,
            identity: AllocationIdentity(identity),
        });
    });
}

struct Owner {
    context: Context,
    kind: BufferKind,
    address: usize,
}

impl Owner {
    fn new(kind: BufferKind, address: usize, length: usize, capacity: usize) -> Option<Self> {
        let context = CURRENT.try_with(Clone::clone).ok()?;
        Self::in_context(context, kind, address, length, capacity)
    }

    fn in_context(
        context: Context,
        kind: BufferKind,
        address: usize,
        length: usize,
        capacity: usize,
    ) -> Option<Self> {
        if capacity == 0 {
            return None;
        }
        {
            let mut state = context
                .observation
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Different operations can immutably borrow one original. Its
            // extent must agree even when the attribution roles differ.
            state.overflowed |= state.buffers.iter().flatten().any(|row| {
                row.identity == AllocationIdentity(address)
                    && (row.length != length || row.capacity != capacity)
            });
            if let Some(row) = state.buffers.iter_mut().flatten().find(|row| {
                row.operation == context.operation
                    && row.kind == kind
                    && row.identity == AllocationIdentity(address)
            }) {
                row.aliases += 1;
                let inconsistent = row.length != length || row.capacity != capacity;
                state.overflowed |= inconsistent;
            } else if let Some(slot) = state.buffers.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(BufferReceipt {
                    operation: context.operation,
                    kind,
                    identity: AllocationIdentity(address),
                    length,
                    capacity,
                    aliases: 1,
                });
            } else {
                state.overflowed = true;
            }
            state.events += 1;
            (context.observation.callback)(BufferEvent::Registered(kind), &state);
        }
        Some(Self {
            context,
            kind,
            address,
        })
    }

    fn release(self, destroy: impl FnOnce()) {
        let mut state = self
            .context
            .observation
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = state.buffers.iter_mut().find(|slot| {
            slot.is_some_and(|row| {
                row.operation == self.context.operation
                    && row.kind == self.kind
                    && row.identity == AllocationIdentity(self.address)
            })
        }) {
            if let Some(row) = slot.as_mut() {
                row.aliases -= 1;
                if row.aliases == 0 {
                    *slot = None;
                }
            }
        }
        // Arc destruction is inside the same lock used by capture. Numeric
        // observation metadata never keeps that original Arc alive.
        destroy();
        state.events += 1;
        (self.context.observation.callback)(BufferEvent::Released(self.kind), &state);
    }
}

/// RAII borrow of original byte storage. It cannot outlive or mutate its backing.
/// Cancellation unregisters before the borrowed owner can be destroyed.
pub struct BufferBorrow<'a> {
    owner: Option<Owner>,
    original: PhantomData<&'a [u8]>,
}

impl<'a> BufferBorrow<'a> {
    /// Register the original address, initialized length and allocation capacity.
    pub fn new(kind: BufferKind, original: &'a Vec<u8>) -> Self {
        Self::storage(kind, original, original.capacity())
    }

    fn storage(kind: BufferKind, original: &'a [u8], capacity: usize) -> Self {
        Self {
            owner: Owner::new(kind, original.as_ptr() as usize, original.len(), capacity),
            original: PhantomData,
        }
    }
}

/// Borrow the original typed Config AAD strings; no encoding or copies occur.
#[doc(hidden)]
pub fn borrow_config_aad(aad: &crate::EnvelopeAad) -> Option<[BufferBorrow<'_>; 3]> {
    let crate::EnvelopeMetadata::Config(metadata) = &aad.metadata else {
        return None;
    };
    Some([
        BufferBorrow::storage(
            BufferKind::AadPrincipal,
            metadata.principal.as_bytes(),
            metadata.principal.capacity(),
        ),
        BufferBorrow::storage(
            BufferKind::AadStoreKind,
            metadata.store_kind.as_bytes(),
            metadata.store_kind.capacity(),
        ),
        BufferBorrow::storage(
            BufferKind::AadTenant,
            aad.tenant.as_str().as_bytes(),
            aad.tenant.allocation_capacity(),
        ),
    ])
}

/// Borrow a real key identifier allocation without exposing its text.
#[doc(hidden)]
pub fn borrow_key_id(kind: BufferKind, key_id: &crate::KeyId) -> BufferBorrow<'_> {
    BufferBorrow::storage(
        kind,
        key_id.as_str().as_bytes(),
        key_id.allocation_capacity(),
    )
}

/// Borrow only provider-returned public metadata; no key material is observed.
#[doc(hidden)]
pub fn borrow_key_handle(handle: &crate::KeyHandle) -> [BufferBorrow<'_>; 2] {
    [
        borrow_key_id(BufferKind::ProviderKeyId, &handle.key_id),
        BufferBorrow::storage(
            BufferKind::ProviderTenant,
            handle.tenant.as_str().as_bytes(),
            handle.tenant.allocation_capacity(),
        ),
    ]
}

impl Drop for BufferBorrow<'_> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.release(|| {});
        }
    }
}

/// Internal immutable original owner used by the envelope and its real aliases.
/// The observation portion carries only numeric receipts and callback state.
#[doc(hidden)]
pub struct ObservedArc {
    original: Option<Arc<[u8]>>,
    owner: Option<Owner>,
}

impl From<Vec<u8>> for ObservedArc {
    fn from(original: Vec<u8>) -> Self {
        // Conversion internals are intentionally not claimed as a simultaneous
        // census. The old Vec has been consumed before this Arc is registered.
        let original: Arc<[u8]> = Arc::from(original);
        let owner = Owner::new(
            BufferKind::EnvelopeArc,
            original.as_ptr() as usize,
            original.len(),
            original.len(),
        );
        Self {
            original: Some(original),
            owner,
        }
    }
}

impl AsRef<[u8]> for ObservedArc {
    fn as_ref(&self) -> &[u8] {
        self.original.as_deref().unwrap_or_default()
    }
}

impl std::ops::Deref for ObservedArc {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl Clone for ObservedArc {
    fn clone(&self) -> Self {
        let original = self.original.clone();
        let owner = self.owner.as_ref().and_then(|owner| {
            Owner::in_context(
                owner.context.clone(),
                owner.kind,
                owner.address,
                self.len(),
                self.len(),
            )
        });
        Self { original, owner }
    }
}

impl Drop for ObservedArc {
    fn drop(&mut self) {
        let original = self.original.take();
        if let Some(owner) = self.owner.take() {
            owner.release(|| drop(original));
        }
    }
}
