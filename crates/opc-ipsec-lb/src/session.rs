//! Session-store backed ownership reads.

use std::fmt;
use std::io;

use async_trait::async_trait;
use bytes::Bytes;
use opc_session_store::{
    SessionBackend, SessionKey, SessionKeyType, StateClass, StoreError, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId};

use crate::error::IpsecLbError;
use crate::model::{ClusterNode, SaId, ShardId};
use crate::ports::OwnershipSource;

const OWNERSHIP_KEY_TYPE: &str = "ipsec-lb-ownership";
const SHARD_KEY_PREFIX: &[u8] = b"opc-ipsec-lb/shard/";
const IKE_SA_KEY_PREFIX: &[u8] = b"opc-ipsec-lb/sa/ike/";
const ESP_SA_KEY_PREFIX: &[u8] = b"opc-ipsec-lb/sa/esp/";

/// Resolves LB ownership lookups to session-store keys.
pub trait SessionOwnershipKeyResolver: Send + Sync + fmt::Debug {
    /// Return the session-store key for a shard owner.
    fn shard_key(&self, shard: ShardId) -> Result<SessionKey, IpsecLbError>;

    /// Return the session-store key for an SA owner.
    fn sa_key(&self, sa: SaId) -> Result<SessionKey, IpsecLbError>;
}

/// Deterministic default keyspace for IPsec LB ownership records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOwnershipKeyspace {
    tenant: TenantId,
    nf_kind: NetworkFunctionKind,
}

impl SessionOwnershipKeyspace {
    /// Build a keyspace scoped to one tenant and NF kind.
    #[must_use]
    pub const fn new(tenant: TenantId, nf_kind: NetworkFunctionKind) -> Self {
        Self { tenant, nf_kind }
    }

    fn key(&self, stable_id: Vec<u8>) -> SessionKey {
        SessionKey {
            tenant: self.tenant.clone(),
            nf_kind: self.nf_kind.clone(),
            key_type: SessionKeyType::Other(OWNERSHIP_KEY_TYPE.to_owned()),
            stable_id: Bytes::from(stable_id),
        }
    }
}

impl SessionOwnershipKeyResolver for SessionOwnershipKeyspace {
    fn shard_key(&self, shard: ShardId) -> Result<SessionKey, IpsecLbError> {
        let mut stable_id = Vec::with_capacity(SHARD_KEY_PREFIX.len() + 2);
        stable_id.extend_from_slice(SHARD_KEY_PREFIX);
        stable_id.extend_from_slice(&shard.get().to_be_bytes());
        Ok(self.key(stable_id))
    }

    fn sa_key(&self, sa: SaId) -> Result<SessionKey, IpsecLbError> {
        let mut stable_id = Vec::new();
        match sa {
            SaId::Ike { responder_spi } => {
                stable_id.reserve(IKE_SA_KEY_PREFIX.len() + 8);
                stable_id.extend_from_slice(IKE_SA_KEY_PREFIX);
                stable_id.extend_from_slice(&responder_spi.to_be_bytes());
            }
            SaId::Esp { spi } => {
                stable_id.reserve(ESP_SA_KEY_PREFIX.len() + 4);
                stable_id.extend_from_slice(ESP_SA_KEY_PREFIX);
                stable_id.extend_from_slice(&spi.to_be_bytes());
            }
        }
        Ok(self.key(stable_id))
    }
}

/// Ownership source backed by `opc-session-store` record metadata.
#[derive(Clone)]
pub struct SessionStoreOwnershipSource<B, R = SessionOwnershipKeyspace> {
    backend: B,
    resolver: R,
}

impl<B, R> fmt::Debug for SessionStoreOwnershipSource<B, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionStoreOwnershipSource")
            .finish_non_exhaustive()
    }
}

impl<B, R> SessionStoreOwnershipSource<B, R>
where
    B: SessionBackend,
    R: SessionOwnershipKeyResolver,
{
    /// Build a session-store ownership source from explicit backend and key resolver.
    #[must_use]
    pub const fn new(backend: B, resolver: R) -> Self {
        Self { backend, resolver }
    }

    async fn owner_for_key(&self, key: SessionKey) -> Result<Option<ClusterNode>, IpsecLbError> {
        let Some(record) = self.backend.get(&key).await.map_err(map_store_error)? else {
            return Ok(None);
        };
        validate_ownership_record(&record)?;
        Ok(Some(ClusterNode::new(record.owner.as_str())))
    }
}

#[async_trait]
impl<B, R> OwnershipSource for SessionStoreOwnershipSource<B, R>
where
    B: SessionBackend,
    R: SessionOwnershipKeyResolver,
{
    async fn shard_owner(&self, shard: ShardId) -> Result<Option<ClusterNode>, IpsecLbError> {
        let key = self.resolver.shard_key(shard)?;
        self.owner_for_key(key).await
    }

    async fn sa_owner(&self, sa: SaId) -> Result<Option<ClusterNode>, IpsecLbError> {
        let key = self.resolver.sa_key(sa)?;
        self.owner_for_key(key).await
    }
}

fn validate_ownership_record(record: &StoredSessionRecord) -> Result<(), IpsecLbError> {
    if record.state_class != StateClass::AuthoritativeSession {
        return Err(IpsecLbError::invalid_config(
            "session_store.state_class",
            "ownership records must be authoritative-session state",
        ));
    }
    if record.key.key_type != SessionKeyType::Other(OWNERSHIP_KEY_TYPE.to_owned()) {
        return Err(IpsecLbError::invalid_config(
            "session_store.key_type",
            "ownership record key type mismatch",
        ));
    }
    Ok(())
}

fn map_store_error(error: StoreError) -> IpsecLbError {
    match error {
        StoreError::NotFound => IpsecLbError::NotFound,
        StoreError::StaleFence | StoreError::LeaseHeld | StoreError::LeaseExpired => {
            IpsecLbError::ownership_conflict("session-store ownership fence is not held")
        }
        StoreError::CasConflict => {
            IpsecLbError::ownership_conflict("session-store ownership generation changed")
        }
        StoreError::InvalidKey(_) => {
            IpsecLbError::invalid_config("session_store.key", "session-store key rejected")
        }
        StoreError::CapabilityNotSupported(_) => IpsecLbError::Unsupported,
        StoreError::BackendUnavailable(_) => IpsecLbError::io(
            "session_store_get",
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "session store unavailable",
            ),
        ),
        StoreError::Crypto(_) | StoreError::Serialization(_) => IpsecLbError::invalid_config(
            "session_store.record",
            "session-store ownership record is unreadable",
        ),
        StoreError::PayloadTooLarge { .. }
        | StoreError::InvalidRestoreScanRequest(_)
        | StoreError::RestoreScanPageTooLarge { .. } => {
            IpsecLbError::invalid_config("session_store", "session-store read failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use opc_session_store::{
        CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, FakeSessionBackend,
        Generation, OwnerId, SessionBackend, SessionLeaseManager, SessionStore, StateType,
        StoredSessionRecord,
    };

    use super::*;

    fn keyspace() -> SessionOwnershipKeyspace {
        SessionOwnershipKeyspace::new(
            TenantId::new("tenant-a").unwrap(),
            NetworkFunctionKind::new("epdg").unwrap(),
        )
    }

    async fn write_owner(
        store: &SessionStore<FakeSessionBackend>,
        key: SessionKey,
        owner: &str,
        state_class: StateClass,
    ) {
        let owner = OwnerId::new(owner).unwrap();
        let lease = store
            .acquire(&key, owner.clone(), Duration::from_secs(60))
            .await
            .unwrap();
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: lease.fence(),
            state_class,
            state_type: StateType::from_static(OWNERSHIP_KEY_TYPE),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        let result = store
            .compare_and_set(CompareAndSet {
                key,
                lease,
                expected_generation: None,
                new_record: record,
            })
            .await
            .unwrap();
        assert_eq!(result, CompareAndSetResult::Success);
    }

    #[tokio::test]
    async fn reads_sa_and_shard_owners_from_session_store_metadata() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 0x1122_3344 };
        write_owner(
            &store,
            keyspace.sa_key(sa).unwrap(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        write_owner(
            &store,
            keyspace.shard_key(ShardId::new(7)).unwrap(),
            "worker-b",
            StateClass::AuthoritativeSession,
        )
        .await;

        let source = SessionStoreOwnershipSource::new(store, keyspace);
        assert_eq!(
            source.sa_owner(sa).await.unwrap().unwrap().as_str(),
            "worker-a"
        );
        assert_eq!(
            source
                .shard_owner(ShardId::new(7))
                .await
                .unwrap()
                .unwrap()
                .as_str(),
            "worker-b"
        );
    }

    #[tokio::test]
    async fn missing_owner_reads_as_none() {
        let source = SessionStoreOwnershipSource::new(
            SessionStore::new(FakeSessionBackend::new()),
            keyspace(),
        );
        assert!(source
            .sa_owner(SaId::Esp { spi: 1 })
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn non_authoritative_records_are_rejected() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Ike { responder_spi: 9 };
        write_owner(
            &store,
            keyspace.sa_key(sa).unwrap(),
            "worker-a",
            StateClass::DataplaneLookup,
        )
        .await;

        let source = SessionStoreOwnershipSource::new(store, keyspace);
        assert!(matches!(
            source.sa_owner(sa).await.unwrap_err(),
            IpsecLbError::InvalidConfig { .. }
        ));
    }
}
