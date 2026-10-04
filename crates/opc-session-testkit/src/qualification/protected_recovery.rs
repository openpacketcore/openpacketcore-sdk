//! Synthetic durable external owner for retained-root recovery qualification.
//! Every process reopens the same FULL-sync journal. The resource effect and
//! whole-scope fence use the same SQLite transaction/serialization boundary.
//! This models an actually enforceable provider contract, not a product adapter.

use opc_session_store::consensus::protected_recovery::{
    ProtectedAsyncRecovery, ProtectedAsyncRecoveryOwner, ProtectedRecoveryChallenge,
    ProtectedRecoveryError, ProtectedRecoveryInventory, ProtectedRecoveryOwner,
    ProtectedRecoveryReceipt,
};
use opc_session_store::{
    RosterAttestationTrustRootV1, SessionConsensusIdentity, SessionConsensusNodeId,
};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use rusqlite::{params, Connection, TransactionBehavior};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

const OWNER: [u8; 32] = [0x91; 32];
type Result<T> = std::result::Result<T, ProtectedRecoveryError>;
fn pending<T>(_: T) -> ProtectedRecoveryError {
    ProtectedRecoveryError::OwnerPending
}

/// One retained provider journal, shared by the independent voter processes.
pub struct Journal {
    path: PathBuf,
    identity: SessionConsensusIdentity,
}
impl Journal {
    /// Provision the external owner once, before any voter starts. Reopening
    /// never calls this function or silently replaces missing custody.
    pub fn provision(directory: &Path, identity: SessionConsensusIdentity) -> Result<()> {
        let journal = Arc::new(Self {
            path: directory.join("protected-provider.sqlite"),
            identity,
        });
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&journal.path)
            .map_err(pending)?;
        let connection = journal.connection()?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS scope (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                identity BLOB NOT NULL, floor INTEGER NOT NULL, completion BLOB);
             CREATE TABLE IF NOT EXISTS effects (
                binding BLOB PRIMARY KEY, fence INTEGER NOT NULL,
                state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 2));
             CREATE TABLE IF NOT EXISTS resource (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), writes INTEGER NOT NULL);
             INSERT OR IGNORE INTO resource VALUES(1,0);",
            )
            .map_err(pending)?;
        let encoded = serde_json::to_vec(&identity).map_err(pending)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO scope VALUES(1,?1,0,NULL)",
                [&encoded],
            )
            .map_err(pending)?;
        let actual: Vec<u8> = connection
            .query_row("SELECT identity FROM scope WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(pending)?;
        if actual != encoded {
            return Err(ProtectedRecoveryError::AuthorityRejected);
        }
        Ok(())
    }
    /// Reopen retained custody. Missing/corrupt provider storage fails closed.
    pub fn open(directory: &Path, identity: SessionConsensusIdentity) -> Result<Arc<Self>> {
        let journal = Arc::new(Self {
            path: directory.join("protected-provider.sqlite"),
            identity,
        });
        let actual: Vec<u8> = journal
            .connection()?
            .query_row("SELECT identity FROM scope WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(pending)?;
        if actual != serde_json::to_vec(&identity).map_err(pending)? {
            return Err(ProtectedRecoveryError::AuthorityRejected);
        }
        Ok(journal)
    }
    fn connection(&self) -> Result<Connection> {
        let connection =
            Connection::open_with_flags(&self.path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(pending)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(1))
            .map_err(pending)?;
        connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
            .map_err(pending)?;
        Ok(connection)
    }
    /// Prepare synthetic work, then optionally apply its one-slot effect.
    /// A global floor applies even when this binding has never existed.
    pub fn effect(&self, binding: u64, fence: u64, execute: bool) -> Result<()> {
        let mut exact = [0; 32];
        exact[..8].copy_from_slice(&binding.to_le_bytes());
        self.effect_binding(exact, fence, execute)
    }
    /// Execute against an exact SDK member binding in the same global scope.
    pub fn effect_binding(&self, binding: [u8; 32], fence: u64, execute: bool) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(pending)?;
        let floor: u64 = tx
            .query_row("SELECT floor FROM scope WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(pending)?;
        if fence <= floor {
            return Err(ProtectedRecoveryError::AuthorityRejected);
        }
        tx.execute(
            "INSERT OR IGNORE INTO effects VALUES(?1,?2,0)",
            params![binding.as_slice(), fence],
        )
        .map_err(pending)?;
        let (prior_fence, state): (u64, u8) = tx
            .query_row(
                "SELECT fence,state FROM effects WHERE binding=?1",
                [binding.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(pending)?;
        if fence < prior_fence || state == 2 {
            return Err(ProtectedRecoveryError::AuthorityRejected);
        }
        if execute && state == 0 {
            tx.execute("UPDATE resource SET writes=writes+1 WHERE singleton=1", [])
                .map_err(pending)?;
            tx.execute(
                "UPDATE effects SET fence=?2,state=1 WHERE binding=?1",
                params![binding.as_slice(), fence],
            )
            .map_err(pending)?;
        }
        tx.commit().map_err(pending)
    }
    /// Read an exact durable outcome at a current higher fence. Missing
    /// custody stays unknown; only retirement can establish a negative result.
    pub fn status_binding(&self, binding: [u8; 32], fence: u64) -> Result<Option<bool>> {
        use rusqlite::OptionalExtension;
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(pending)?;
        let floor: u64 = tx
            .query_row("SELECT floor FROM scope WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(pending)?;
        if fence <= floor {
            return Err(ProtectedRecoveryError::AuthorityRejected);
        }
        let prior: Option<(u64, u8)> = tx
            .query_row(
                "SELECT fence,state FROM effects WHERE binding=?1",
                [binding.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(pending)?;
        let Some((old, state)) = prior else {
            return Ok(None);
        };
        if fence < old {
            return Err(ProtectedRecoveryError::AuthorityRejected);
        }
        tx.execute(
            "UPDATE effects SET fence=?2 WHERE binding=?1",
            params![binding.as_slice(), fence],
        )
        .map_err(pending)?;
        tx.commit().map_err(pending)?;
        Ok(match state {
            1 => Some(true),
            2 => Some(false),
            _ => None,
        })
    }
    /// Read persisted floor, applied effects and retired prepared effects.
    pub fn progress(&self) -> Result<(u64, u64, u64)> {
        self.connection()?.query_row(
            "SELECT floor,(SELECT writes FROM resource),(SELECT count(*) FROM effects WHERE state=2) FROM scope",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).map_err(pending)
    }
}

fn key(byte: u8) -> Result<SigningKey> {
    SigningKey::from_bytes((&[byte; 32]).into()).map_err(pending)
}
fn sign(key: &SigningKey, digest: [u8; 32]) -> Result<[u8; 64]> {
    let signature: Signature = key.sign_prehash(&digest).map_err(pending)?;
    Ok(signature.normalize_s().to_bytes().into())
}

#[async_trait::async_trait]
impl ProtectedAsyncRecoveryOwner for Journal {
    fn identity(&self) -> [u8; 32] {
        OWNER
    }
    async fn retire(
        &self,
        challenge: &ProtectedRecoveryChallenge,
    ) -> Result<ProtectedRecoveryReceipt> {
        if challenge.identity() != self.identity {
            return Err(ProtectedRecoveryError::AuthorityRejected);
        }
        let owned = challenge.clone();
        let path = self.path.clone();
        let identity = self.identity;
        // The accepted blocking transaction remains joined by the SDK's
        // supervisor even if the voter RPC/caller deadline expires.
        tokio::task::spawn_blocking(move || {
            let journal = Journal { path, identity };
            let mut connection = journal.connection()?;
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(pending)?;
            let floor: u64 = tx
                .query_row("SELECT floor FROM scope WHERE singleton=1", [], |r| {
                    r.get(0)
                })
                .map_err(pending)?;
            if floor > owned.retire_through() {
                return Err(ProtectedRecoveryError::AuthorityRejected);
            }
            let digest = owned.signing_digest()?;
            // Transaction serialization joins every already executing effect.
            // Prepared-but-unexecuted rows acquire durable negative outcomes;
            // applied rows and their immutable outcomes remain available.
            tx.execute(
                "UPDATE effects SET state=2 WHERE state=0 AND fence<=?1",
                [owned.retire_through()],
            )
            .map_err(pending)?;
            tx.execute(
                "UPDATE scope SET floor=?1,completion=?2 WHERE singleton=1",
                params![owned.retire_through(), digest.as_slice()],
            )
            .map_err(pending)?;
            tx.commit().map_err(pending)?;
            owned.receipt(
                OWNER,
                sign(&key(0x41)?, owned.owner_signing_digest(OWNER)?)?,
            )
        })
        .await
        .map_err(pending)?
    }
}

/// Build the synthetic root-authorized complete inventory and real journal owner.
pub fn authority(
    directory: &Path,
    identity: SessionConsensusIdentity,
    voters: &BTreeSet<SessionConsensusNodeId>,
    root: RosterAttestationTrustRootV1,
) -> Result<Arc<ProtectedAsyncRecovery>> {
    let owner = ProtectedRecoveryOwner::new(
        OWNER,
        key(0x41)?
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .map_err(pending)?,
    )?;
    let inventory = vec![owner];
    let signature = sign(
        &key(0x31)?,
        ProtectedRecoveryInventory::signing_digest(identity, voters, &root, &inventory)?,
    )?;
    let inventory = ProtectedRecoveryInventory::from_signed_parts(
        identity, voters, root, inventory, signature,
    )?;
    Ok(Arc::new(ProtectedAsyncRecovery::new(
        inventory,
        vec![Journal::open(directory, identity)?],
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_session_store::{
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId,
    };

    fn identity(epoch: u64) -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            SessionConsensusClusterId::new("protected-provider-journal").unwrap(),
            SessionConsensusConfigurationId::from_bytes([0x51; 32]),
            SessionConsensusConfigurationEpoch::new(epoch).unwrap(),
        )
    }

    #[test]
    fn protected_provider_missing_corrupt_and_foreign_storage_cannot_recreate_custody() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("protected-provider.sqlite");
        assert!(Journal::open(directory.path(), identity(1)).is_err());
        assert!(!path.exists());
        std::fs::write(&path, b"synthetic corrupt provider root").unwrap();
        assert!(Journal::open(directory.path(), identity(1)).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"synthetic corrupt provider root"
        );
        let valid = tempfile::tempdir().unwrap();
        Journal::provision(valid.path(), identity(1)).unwrap();
        let journal = Journal::open(valid.path(), identity(1)).unwrap();
        journal.effect(1, 1, true).unwrap();
        assert!(Journal::provision(valid.path(), identity(1)).is_err());
        assert!(matches!(
            Journal::open(valid.path(), identity(2)),
            Err(ProtectedRecoveryError::AuthorityRejected)
        ));
        assert_eq!(
            Journal::open(valid.path(), identity(1))
                .unwrap()
                .progress()
                .unwrap(),
            (0, 1, 0)
        );
        assert_eq!(
            journal.status_binding([0x77; 32], 2).unwrap(),
            None,
            "missing effect custody never fabricates a negative outcome"
        );
    }
}
