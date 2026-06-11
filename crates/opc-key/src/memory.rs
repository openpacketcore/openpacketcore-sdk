use async_trait::async_trait;
use opc_types::TenantId;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

use crate::{
    errors::KeyError,
    provider::{KeyHandle, KeyProvider, AES_256_GCM_SIV_KEY_LEN},
    scope::{KeyId, KeyPurpose},
};

fn stable_rotation_base(key_id: &KeyId) -> &str {
    let mut candidate = key_id.as_str();
    while let Some((prefix, _suffix)) = split_rotation_suffix(candidate) {
        candidate = prefix;
    }
    candidate
}

fn split_rotation_suffix(candidate: &str) -> Option<(&str, u64)> {
    let (prefix, suffix) = candidate.rsplit_once("-r")?;
    if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }

    suffix.parse().ok().map(|value| (prefix, value))
}

fn terminal_rotation_suffix(key_id: &KeyId) -> Option<u64> {
    split_rotation_suffix(key_id.as_str()).map(|(_prefix, suffix)| suffix)
}

fn next_rotation_counter(
    state: &MemoryProviderState,
    purpose: KeyPurpose,
    tenant: &TenantId,
    active_key_id: &KeyId,
) -> u64 {
    let tracked = state
        .rotation_counters
        .get(&(purpose, tenant.clone()))
        .copied()
        .unwrap_or(0);
    let base = stable_rotation_base(active_key_id);
    let discovered = state
        .by_id
        .values()
        .filter(|handle| handle.purpose == purpose && handle.tenant == *tenant)
        .filter(|handle| stable_rotation_base(handle.key_id()) == base)
        .filter_map(|handle| terminal_rotation_suffix(handle.key_id()))
        .max()
        .unwrap_or(0);

    tracked.max(discovered) + 1
}

fn insert_rotation_counter(
    state: &mut MemoryProviderState,
    purpose: KeyPurpose,
    tenant: &TenantId,
    next_counter: u64,
) {
    state
        .rotation_counters
        .insert((purpose, tenant.clone()), next_counter);
}

#[derive(Default)]
struct MemoryProviderState {
    active: HashMap<(KeyPurpose, TenantId), KeyHandle>,
    by_id: HashMap<KeyId, KeyHandle>,
    rotation_counters: HashMap<(KeyPurpose, TenantId), u64>,
}

impl MemoryProviderState {
    fn store_handle(&mut self, handle: KeyHandle) -> Result<(), KeyError> {
        if self.by_id.contains_key(handle.key_id()) {
            return Err(KeyError::DuplicateKeyId {
                key_id: handle.key_id().clone(),
            });
        }

        self.by_id.insert(handle.key_id.clone(), handle.clone());
        self.active
            .insert((handle.purpose, handle.tenant.clone()), handle);
        Ok(())
    }
}

/// Deterministic in-memory provider used by tests and local development.
#[derive(Default)]
pub struct MemoryKeyProvider {
    inner: Mutex<MemoryProviderState>,
}

impl MemoryKeyProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an active key using zeroizing secret material.
    pub fn insert_active_key(
        &self,
        key_id: KeyId,
        purpose: KeyPurpose,
        tenant: TenantId,
        secret: Zeroizing<[u8; AES_256_GCM_SIV_KEY_LEN]>,
    ) -> Result<(), KeyError> {
        let handle = KeyHandle::new(key_id, purpose, tenant, secret);
        let mut inner = self
            .inner
            .lock()
            .expect("memory key provider mutex poisoned");
        inner.store_handle(handle)
    }

    pub fn insert_historical_key(&self, handle: KeyHandle) -> Result<(), KeyError> {
        let mut inner = self
            .inner
            .lock()
            .expect("memory key provider mutex poisoned");
        if inner.by_id.contains_key(handle.key_id()) {
            return Err(KeyError::DuplicateKeyId {
                key_id: handle.key_id().clone(),
            });
        }
        inner.by_id.insert(handle.key_id.clone(), handle);
        Ok(())
    }
}

#[async_trait]
impl KeyProvider for MemoryKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        let inner = self
            .inner
            .lock()
            .expect("memory key provider mutex poisoned");
        inner
            .active
            .get(&(purpose, tenant.clone()))
            .cloned()
            .ok_or(KeyError::NotFound)
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        let inner = self
            .inner
            .lock()
            .expect("memory key provider mutex poisoned");
        inner.by_id.get(key_id).cloned().ok_or(KeyError::NotFound)
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        let mut inner = self
            .inner
            .lock()
            .expect("memory key provider mutex poisoned");
        let old_handle = inner
            .active
            .get(&(purpose, tenant.clone()))
            .cloned()
            .ok_or(KeyError::NotFound)?;

        let next_counter = next_rotation_counter(&inner, purpose, tenant, &old_handle.key_id);
        insert_rotation_counter(&mut inner, purpose, tenant, next_counter);

        let mut hasher = Sha256::new();
        hasher.update(old_handle.material.bytes.as_slice());
        hasher.update(next_counter.to_be_bytes());
        let next_secret = Zeroizing::new(<[u8; AES_256_GCM_SIV_KEY_LEN]>::from(hasher.finalize()));
        let next_key_id = KeyId::new(format!(
            "{}-r{}",
            stable_rotation_base(&old_handle.key_id),
            next_counter
        ))?;
        let next_handle = KeyHandle::new(next_key_id.clone(), purpose, tenant.clone(), next_secret);
        inner.store_handle(next_handle)?;

        Ok(next_key_id)
    }
}
