use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    hash::Hash,
    sync::{Arc, Mutex, OnceLock, Weak},
};

use crate::recovery::profile::RecoveryProfile;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{Ikev2CanonicalError as Error, Ikev2CommittedWindowDomain};
use crate::{Ikev2AesGcmIvDomain, Ikev2EncryptionAlgorithm, Ikev2ProtectedPayloadDirection};

#[cfg(test)]
thread_local! {
    static KEY_COMPARISONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

// Full, domain-separated fingerprints are internal indexes, never encryption
// keys, nonces or persisted wire-format inputs. No usable SA keys enter a static.
#[derive(Clone, Copy)]
struct KeyFingerprint([u8; 32]);

impl KeyFingerprint {
    fn of(domain: &Ikev2AesGcmIvDomain) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"opc-ikev2-canonical-key-salt-v1\0");
        hash.update(domain.key_and_salt());
        Self(hash.finalize().into())
    }
}
impl Hash for KeyFingerprint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl PartialEq for KeyFingerprint {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(test)]
        KEY_COMPARISONS.with(|count| count.set(count.get() + 1));
        bool::from(self.0.ct_eq(&other.0))
    }
}
impl Eq for KeyFingerprint {}

#[derive(Clone, Copy)]
struct BindingFingerprint([u8; 32]);
impl BindingFingerprint {
    fn of(binding: &Ikev2CommittedWindowDomain) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"opc-ikev2-canonical-binding-v1\0");
        hash.update(KeyFingerprint::of(&binding.send).0);
        hash.update(KeyFingerprint::of(&binding.receive).0);
        hash.update(binding.send.initiator_spi().to_be_bytes());
        hash.update(binding.send.responder_spi().to_be_bytes());
        hash.update([match binding.send.direction() {
            Ikev2ProtectedPayloadDirection::InitiatorToResponder => 0,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator => 1,
        }]);
        hash.update([match binding.send.encryption() {
            Ikev2EncryptionAlgorithm::AesGcm16_128 => 1,
            Ikev2EncryptionAlgorithm::AesGcm16_192 => 2,
            Ikev2EncryptionAlgorithm::AesGcm16_256 => 3,
            _ => 0, // Validated epoch domains cannot contain another algorithm.
        }]);
        hash.update(match binding.canonical_format {
            None => [0, 0],
            Some(value) => [1, value],
        });
        Self(hash.finalize().into())
    }
}
impl PartialEq for BindingFingerprint {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}
impl Eq for BindingFingerprint {}

#[derive(Default)]
pub(super) struct Entry {
    pub(super) attempts: u8,
    pub(super) released: bool,
    pub(super) bytes: Option<super::buffer::CanonicalBytes>,
}

pub(super) struct Ledger {
    binding: BindingFingerprint,
    pub(super) closed_through: Option<u32>,
    pub(super) entries: BTreeMap<u32, Entry>,
    owner: Weak<()>,
    revoked: bool,
}

impl Ledger {
    pub(super) fn owns(&self, instance: &Arc<()>) -> bool {
        self.owner.ptr_eq(&Arc::downgrade(instance))
    }

    pub(super) fn check_instance(&self, instance: &Arc<()>) -> Result<(), Error> {
        if self.revoked || !self.owns(instance) {
            Err(Error::Invalidated)
        } else {
            Ok(())
        }
    }

    pub(super) fn retire_through(&mut self, message_id: u32) {
        let floor = self
            .closed_through
            .map_or(message_id, |old| old.max(message_id));
        self.closed_through = Some(floor);
        self.entries = match floor.checked_add(1) {
            Some(first_open) => self.entries.split_off(&first_open),
            None => BTreeMap::new(),
        };
    }

    pub(super) fn revoke(&mut self, binding_untrusted: bool) {
        self.revoked |= binding_untrusted;
        self.owner = Weak::new();
        if self.revoked {
            self.entries.clear(); // This ledger remains revoked even if its tombstone ages out.
        } else {
            for entry in self.entries.values_mut() {
                entry.bytes = None; // Reconciliation retains attempts/release history.
            }
        }
    }
}

#[derive(Default)]
struct RegistryEntries {
    live: HashMap<KeyFingerprint, Arc<Mutex<Ledger>>>,
    // Recent deletion/trust-loss fingerprints have no Arc, binding or ID map.
    deleted: HashSet<KeyFingerprint>,
    deletion_order: VecDeque<KeyFingerprint>,
}

impl RegistryEntries {
    fn remember_deletion(&mut self, key: KeyFingerprint, limit: usize) {
        if limit == 0 || self.deleted.contains(&key) {
            return; // Repeated deletion does not refresh FIFO age.
        }
        if self.deletion_order.len() == limit {
            if let Some(oldest) = self.deletion_order.pop_front() {
                self.deleted.remove(&oldest);
            }
        }
        self.deleted.insert(key);
        self.deletion_order.push_back(key);
    }
}

struct Registry {
    entries: Mutex<RegistryEntries>,
    live_limit: usize,
    tombstone_limit: usize,
}

impl Registry {
    fn new(live_limit: usize, tombstone_limit: usize) -> Self {
        Self {
            entries: Mutex::new(RegistryEntries::default()),
            live_limit,
            tombstone_limit,
        }
    }

    fn acquire(
        &self,
        key: KeyFingerprint,
        binding: BindingFingerprint,
    ) -> Result<(Arc<Mutex<Ledger>>, Arc<()>), Error> {
        let ledger = {
            let mut entries = self.entries.lock().map_err(|_| Error::Unavailable)?;
            if let Some(registered) = entries.live.get(&key) {
                Arc::clone(registered)
            } else {
                if entries.deleted.contains(&key) {
                    return Err(Error::Invalidated);
                }
                if entries.live.len() >= self.live_limit {
                    return Err(Error::RegistryFull);
                }
                let ledger = Arc::new(Mutex::new(Ledger {
                    binding,
                    closed_through: None,
                    entries: BTreeMap::new(),
                    owner: Weak::new(),
                    revoked: false,
                }));
                entries.live.insert(key, Arc::clone(&ledger));
                ledger
            }
        }; // Never acquire a per-key lock, or seal, while holding the registry lock.
        let instance = Arc::new(());
        {
            let mut state = ledger.lock().map_err(|_| Error::Unavailable)?;
            if state.binding != binding {
                state.revoke(true);
                drop(state);
                self.finish_revocation(key, &ledger);
                return Err(Error::BindingMismatch);
            }
            if state.revoked {
                return Err(Error::Invalidated);
            }
            if state.owner.upgrade().is_some() {
                return Err(Error::CapabilityActive);
            }
            state.owner = Arc::downgrade(&instance);
        }
        Ok((ledger, instance))
    }

    fn revoke(&self, key: KeyFingerprint, permanent: bool) {
        let ledger = {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(ledger) = entries.live.get(&key) {
                Arc::clone(ledger)
            } else {
                if permanent {
                    entries.remember_deletion(key, self.tombstone_limit);
                }
                return;
            }
        };
        {
            // Keep this ledger registered until it is revoked. FIFO churn must
            // not admit a replacement while the old ledger can still release.
            ledger
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .revoke(permanent);
        }
        if permanent {
            self.finish_revocation(key, &ledger);
        }
    }

    // Called only after permanent per-key revocation and after releasing its lock.
    fn finish_revocation(&self, key: KeyFingerprint, ledger: &Arc<Mutex<Ledger>>) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries
            .live
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, ledger))
        {
            entries.live.remove(&key);
            entries.remember_deletion(key, self.tombstone_limit);
        }
        // Another revocation may already have removed this ledger and its
        // tombstone may have aged out. Never remove a newer live ledger here.
    }
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();
fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| {
        Registry::new(
            super::IKEV2_CANONICAL_MAX_TRACKED_KEYS,
            super::IKEV2_CANONICAL_MAX_TOMBSTONES,
        )
    })
}

pub(super) fn acquire<P: RecoveryProfile>(
    binding: &Ikev2CommittedWindowDomain<P>,
) -> Result<(Arc<Mutex<Ledger>>, Arc<()>), Error> {
    registry().acquire(
        KeyFingerprint(P::ledger_key(binding)),
        BindingFingerprint(P::binding_fingerprint(binding)?),
    )
}

pub(super) fn revoke(domain: &Ikev2AesGcmIvDomain, binding_untrusted: bool) {
    registry().revoke(KeyFingerprint::of(domain), binding_untrusted);
}

#[cfg(test)]
mod tests;

pub(super) fn gcm_ledger_key(domain: &Ikev2CommittedWindowDomain) -> [u8; 32] {
    KeyFingerprint::of(&domain.send).0
}
pub(super) fn gcm_binding_fingerprint(domain: &Ikev2CommittedWindowDomain) -> [u8; 32] {
    BindingFingerprint::of(domain).0
}
pub(super) fn revoke_profile<P: RecoveryProfile>(
    binding: &Ikev2CommittedWindowDomain<P>,
    permanent: bool,
) {
    registry().revoke(KeyFingerprint(P::ledger_key(binding)), permanent);
}
