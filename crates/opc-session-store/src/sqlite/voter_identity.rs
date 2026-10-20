//! The volume's private enrollment record, outside every replicated image.

use super::*;
use std::io::{Read, Write};

use opc_consensus::voter_slots::{SlotId, VoterIncarnation, VoterSlotIdentity, VoterSlotMember};
use opc_consensus::ConsensusClusterId;
use zeroize::Zeroizing;

use crate::{ConsensusSessionStoreOpenError, VoterIdentitySigner};

const TABLE: &str = "consensus_voter_anchor";
const SCHEMA: &str = "CREATE TABLE consensus_voter_anchor (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    format INTEGER NOT NULL CHECK (format = 1),
    installation BLOB NOT NULL CHECK (typeof(installation) = 'blob' AND length(installation) = 32),
    slot INTEGER NOT NULL CHECK (slot BETWEEN 1 AND 65535),
    incarnation INTEGER NOT NULL CHECK (incarnation BETWEEN 1 AND 140737488355328),
    key_digest BLOB NOT NULL CHECK (typeof(key_digest) = 'blob' AND length(key_digest) = 32),
    initialized INTEGER NOT NULL CHECK (initialized IN (0, 1))
)";

fn refused() -> ConsensusSessionStoreOpenError {
    ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired
}

fn key_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(".voter-identity");
    PathBuf::from(path)
}

pub(super) fn anchor_present(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = ?1)",
        [TABLE],
        |row| row.get(0),
    )
}

struct PublicAnchor {
    installation: ConsensusClusterId,
    identity: VoterSlotIdentity,
    key_digest: [u8; 32],
    initialized: bool,
}

fn read_public_anchor(conn: &Connection) -> Result<PublicAnchor, ConsensusSessionStoreOpenError> {
    if !anchor_present(conn).map_err(|_| refused())? {
        return Err(refused());
    }
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM consensus_voter_anchor", [], |row| {
            row.get(0)
        })
        .map_err(|_| refused())?;
    let (version, installation, slot, incarnation, digest, initialized):
        (u64, Vec<u8>, u16, u64, Vec<u8>, u64) = conn
        .query_row(
            "SELECT format, installation, slot, incarnation, key_digest, initialized FROM consensus_voter_anchor WHERE singleton = 1 AND length(installation) = 32 AND length(key_digest) = 32",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .map_err(|_| refused())?;
    if count != 1 || version != 1 || initialized > 1 {
        return Err(refused());
    }
    Ok(PublicAnchor {
        installation: ConsensusClusterId::from_bytes(
            installation.try_into().map_err(|_| refused())?,
        ),
        identity: VoterSlotIdentity::new(
            SlotId::new(slot).map_err(|_| refused())?,
            VoterIncarnation::new(incarnation).map_err(|_| refused())?,
        ),
        key_digest: digest.try_into().map_err(|_| refused())?,
        initialized: initialized == 1,
    })
}

/// The public local binding is checked again inside the identity transaction.
/// A retained key alone cannot re-seed a lost database or consumed enrollment.
pub(super) fn require_seed_enrollment(
    conn: &Connection,
    seed: &consensus::voter_slots::Seed,
    initialized: bool,
) -> Result<(), crate::consensus::storage::SessionConsensusStorageError> {
    use crate::consensus::storage::SessionConsensusStorageError::VoterIdentityReplacementRequired;
    let anchor = read_public_anchor(conn).map_err(|_| VoterIdentityReplacementRequired)?;
    if anchor.initialized != initialized
        || anchor.installation != seed.genesis.cluster_instance
        || !seed.initial.slots.iter().any(|slot| {
            slot.member.identity == anchor.identity
                && slot.member.key_digest == anchor.key_digest
                && slot.retired_through < anchor.identity.incarnation().get()
        })
    {
        return Err(VoterIdentityReplacementRequired);
    }
    Ok(())
}

/// Called in the same transaction that creates the first consensus identity.
pub(super) fn consume_enrollment(
    conn: &Connection,
) -> Result<(), crate::consensus::storage::SessionConsensusStorageError> {
    use crate::consensus::storage::SessionConsensusStorageError as Error;
    let changed = conn.execute(
        "UPDATE consensus_voter_anchor SET initialized = 1 WHERE singleton = 1 AND initialized = 0", [],
    ).map_err(|_| Error::BackendUnavailable)?;
    if changed != 1 {
        return Err(Error::VoterIdentityReplacementRequired);
    }
    Ok(())
}

fn create_public_anchor(
    conn: &Connection,
    installation: ConsensusClusterId,
    identity: VoterSlotIdentity,
    key_digest: [u8; 32],
) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA)?;
    conn.execute(
        "INSERT INTO consensus_voter_anchor VALUES (1, 1, ?1, ?2, ?3, ?4, 0)",
        params![
            installation.as_bytes(),
            identity.slot().get(),
            identity.incarnation().get(),
            key_digest.as_slice()
        ],
    )?;
    Ok(())
}

// Pure storage fixtures seed only the public projection. Public store tests
// exercise real file-backed enrollment and proof of the SDK-generated key.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn enroll_projection_for_test(
    conn: &Connection,
    table: &opc_consensus::voter_slots::VoterSlotTable,
) {
    let member = &table.slots[0].member;
    create_public_anchor(
        conn,
        table.cluster_instance,
        member.identity,
        member.key_digest,
    )
    .unwrap();
}

pub(super) fn read_anchor(
    conn: &Connection,
    database: &Path,
) -> Result<VoterIdentitySigner, ConsensusSessionStoreOpenError> {
    let anchor = read_public_anchor(conn)?;
    let signer = read_private_anchor(database)?;
    if signer.cluster_instance() != anchor.installation
        || signer.identity() != anchor.identity
        || signer.key_digest() != anchor.key_digest
    {
        return Err(refused());
    }
    Ok(signer)
}

fn read_private_anchor(
    database: &Path,
) -> Result<VoterIdentitySigner, ConsensusSessionStoreOpenError> {
    let mut file = open_regular_read_nofollow(&key_path(database)).map_err(|_| refused())?;
    if file.metadata().map_err(|_| refused())?.len() != crate::voter_identity::RECORD_BYTES as u64 {
        return Err(refused());
    }
    let mut bytes = Zeroizing::new([0; crate::voter_identity::RECORD_BYTES]);
    file.read_exact(bytes.as_mut()).map_err(|_| refused())?;
    VoterIdentitySigner::from_record(&bytes)
}

impl SqliteSessionBackend {
    /// Explicitly enroll a new volume, before publishing its immutable manifest.
    ///
    /// The SDK generates the private incarnation key. Its installation, slot,
    /// incarnation and key digest are persisted together in the private volume
    /// record, with a matching public binding in the database transaction. No
    /// private key enters the database, native basis, log, or snapshot. Success
    /// follows both durable writes; an interrupted enrollment fails closed.
    ///
    /// The consumer chooses enrollment from its durable allocation/publication
    /// record, never from an empty path. After publication it only reopens.
    /// Existing or interrupted enrollment is never overwritten. A replacement
    /// gets a new volume and a new incarnation selected through RFC 023.
    pub async fn enroll_voter_identity(
        &self,
        installation: ConsensusClusterId,
        identity: VoterSlotIdentity,
    ) -> Result<VoterIdentitySigner, ConsensusSessionStoreOpenError> {
        let path = self
            .database_path
            .clone()
            .ok_or(ConsensusSessionStoreOpenError::StorageUnavailable)?;
        #[cfg(target_os = "linux")]
        if self
            .native_owner
            .as_ref()
            .is_some_and(|owner| owner.selected())
        {
            return Err(ConsensusSessionStoreOpenError::VoterIdentityAlreadyEnrolled);
        }
        let conn = self.conn.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let unavailable = |_| ConsensusSessionStoreOpenError::StorageUnavailable;
            let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Immediate)
                .map_err(unavailable)?;
            if anchor_present(&tx).map_err(unavailable)?
                || consensus_identity_exists(&tx)
                    .map_err(|_| ConsensusSessionStoreOpenError::VoterIdentityAlreadyEnrolled)?
                || std::fs::symlink_metadata(key_path(&path)).is_ok()
            {
                return Err(ConsensusSessionStoreOpenError::VoterIdentityAlreadyEnrolled);
            }
            let signer = VoterIdentitySigner::generate(installation, identity)?;
            create_public_anchor(&tx, installation, identity, signer.key_digest())
                .map_err(unavailable)?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(key_path(&path)).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    ConsensusSessionStoreOpenError::VoterIdentityAlreadyEnrolled
                } else {
                    ConsensusSessionStoreOpenError::StorageUnavailable
                }
            })?;
            file.write_all(signer.record().as_ref())
                .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
            file.sync_all()
                .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
            File::open(
                path.parent()
                    .ok_or(ConsensusSessionStoreOpenError::StorageUnavailable)?,
            )
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
            tx.commit().map_err(unavailable)?;
            Ok(signer)
        })
        .await
        .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?
    }

    /// Reopen the exact retained key without generating or provisioning anything.
    ///
    /// `member` comes from the published genesis manifest or the selected
    /// committed replacement table. The consensus opener repeats this check
    /// and checks the recovered committed retirement floor before starting Raft.
    pub async fn voter_identity_signer(
        &self,
        installation: ConsensusClusterId,
        member: &VoterSlotMember,
    ) -> Result<VoterIdentitySigner, ConsensusSessionStoreOpenError> {
        let path = self.database_path.clone().ok_or_else(refused)?;
        let member = member.clone();
        #[cfg(target_os = "linux")]
        let selected = self
            .native_owner
            .as_ref()
            .is_some_and(|owner| owner.selected());
        #[cfg(not(target_os = "linux"))]
        let selected = false;
        let conn = self.conn.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            // A selected native root must pass its existing format preflight
            // before any SQLite query. The opener validates the matching SQL
            // anchor immediately after that preflight and before starting Raft.
            let signer = if selected {
                read_private_anchor(&path)?
            } else {
                read_anchor(&conn, &path)?
            };
            if signer.cluster_instance() != installation
                || signer.identity() != member.identity
                || signer.key_digest() != member.key_digest
            {
                return Err(refused());
            }
            Ok(signer)
        })
        .await
        .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?
    }

    pub(crate) async fn has_voter_identity_anchor(
        &self,
    ) -> Result<bool, ConsensusSessionStoreOpenError> {
        Ok(self
            .database_path
            .as_ref()
            .is_some_and(|path| std::fs::symlink_metadata(key_path(path)).is_ok()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_consensus::voter_slots::{
        SlotId, VoterChallengeIssuer, VoterEnrollmentBinding, VoterIncarnation,
    };

    fn installation() -> ConsensusClusterId {
        ConsensusClusterId::from_bytes([0x91; 32])
    }
    fn identity() -> VoterSlotIdentity {
        VoterSlotIdentity::new(SlotId::new(1).unwrap(), VoterIncarnation::new(1).unwrap())
    }
    fn member(signer: &VoterIdentitySigner) -> VoterSlotMember {
        VoterSlotMember {
            identity: signer.identity(),
            key_digest: signer.key_digest(),
            descriptor_digest: [0x92; 32],
            admission_generation: 1,
        }
    }

    #[tokio::test]
    async fn enrolled_key_reopens_and_proves_only_its_own_fresh_challenge() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("voter.sqlite");
        let backend = SqliteSessionBackend::open(&path).unwrap();
        let signer = backend
            .enroll_voter_identity(installation(), identity())
            .await
            .unwrap();
        let selected = member(&signer);
        let public = signer.public_key();
        drop(backend);
        drop(signer);
        let backend = SqliteSessionBackend::open(&path).unwrap();
        let signer = backend
            .voter_identity_signer(installation(), &selected)
            .await
            .unwrap();
        assert_eq!(signer.public_key(), public);
        let issuer = VoterChallengeIssuer::new();
        let binding = VoterEnrollmentBinding {
            cluster_instance: installation(),
            identity: identity(),
            key_digest: signer.key_digest(),
            spiffe_id: "spiffe://example.test/voter/1".into(),
        };
        let challenge = issuer
            .issue_enrollment(
                binding.clone(),
                [0x93; 32],
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        let signature = signer.sign_enrollment(&challenge).unwrap();
        let proof = issuer
            .verify_enrollment(
                &challenge,
                &binding.spiffe_id,
                [0x93; 32],
                public,
                signature,
            )
            .unwrap();
        assert_eq!(proof.binding().unwrap(), &binding);
        assert!(
            issuer
                .verify_enrollment(
                    &challenge,
                    &binding.spiffe_id,
                    [0x93; 32],
                    public,
                    signature
                )
                .is_err(),
            "a consumed challenge cannot publish a second enrollment"
        );
        let mut foreign = challenge.clone();
        foreign.binding.identity =
            VoterSlotIdentity::new(SlotId::new(2).unwrap(), VoterIncarnation::new(1).unwrap());
        assert!(signer.sign_enrollment(&foreign).is_err());
        foreign = challenge.clone();
        foreign.binding.cluster_instance = ConsensusClusterId::from_bytes([0x94; 32]);
        assert!(signer.sign_enrollment(&foreign).is_err());
        let fresh = issuer
            .issue_enrollment(
                binding.clone(),
                [0x95; 32],
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        assert!(
            issuer
                .verify_enrollment(&fresh, &binding.spiffe_id, [0x95; 32], public, signature)
                .is_err(),
            "a signature from another fresh channel is not enrollment proof"
        );
        assert_eq!(format!("{signer:?}"), "VoterIdentitySigner { .. }");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(key_path(&path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
    }

    #[tokio::test]
    async fn enrollment_never_replaces_a_retained_or_interrupted_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("voter.sqlite");
        let backend = SqliteSessionBackend::open(&path).unwrap();
        let signer = backend
            .enroll_voter_identity(installation(), identity())
            .await
            .unwrap();
        let original = Zeroizing::new(std::fs::read(key_path(&path)).unwrap());
        let replacement =
            VoterSlotIdentity::new(SlotId::new(1).unwrap(), VoterIncarnation::new(2).unwrap());
        assert!(matches!(
            backend
                .enroll_voter_identity(installation(), replacement)
                .await,
            Err(ConsensusSessionStoreOpenError::VoterIdentityAlreadyEnrolled)
        ));
        assert!(
            std::fs::read(key_path(&path)).unwrap() == *original,
            "a second enrollment cannot overwrite the retained private record"
        );
        assert_eq!(
            backend
                .voter_identity_signer(installation(), &member(&signer))
                .await
                .unwrap()
                .key_digest(),
            signer.key_digest()
        );

        let path = directory.path().join("interrupted.sqlite");
        let backend = SqliteSessionBackend::open(&path).unwrap();
        std::fs::write(key_path(&path), b"incomplete enrollment").unwrap();
        assert!(matches!(
            backend
                .enroll_voter_identity(installation(), identity())
                .await,
            Err(ConsensusSessionStoreOpenError::VoterIdentityAlreadyEnrolled)
        ));
        assert_eq!(
            std::fs::read(key_path(&path)).unwrap(),
            b"incomplete enrollment"
        );
        assert!(matches!(
            backend
                .voter_identity_signer(installation(), &member(&signer))
                .await,
            Err(ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired)
        ));
    }

    #[tokio::test]
    async fn missing_corrupt_or_mismatched_anchor_never_regenerates_a_key() {
        for fault in 0..5 {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("voter.sqlite");
            let backend = SqliteSessionBackend::open(&path).unwrap();
            let signer = backend
                .enroll_voter_identity(installation(), identity())
                .await
                .unwrap();
            let mut selected = member(&signer);
            match fault {
                0 => std::fs::remove_file(key_path(&path)).unwrap(),
                1 => backend
                    .conn
                    .lock()
                    .await
                    .execute_batch("DROP TABLE consensus_voter_anchor")
                    .unwrap(),
                2 => std::fs::write(key_path(&path), b"torn record").unwrap(),
                3 => selected.key_digest[0] ^= 1,
                4 => {
                    selected.identity = VoterSlotIdentity::new(
                        SlotId::new(1).unwrap(),
                        VoterIncarnation::new(2).unwrap(),
                    )
                }
                _ => unreachable!(),
            }
            let before = std::fs::read(key_path(&path)).ok().map(Zeroizing::new);
            assert!(
                matches!(
                    backend
                        .voter_identity_signer(installation(), &selected)
                        .await,
                    Err(ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired)
                ),
                "fault {fault}"
            );
            let after = std::fs::read(key_path(&path)).ok().map(Zeroizing::new);
            assert!(
                before == after,
                "a refused reopen cannot provision or modify the private record"
            );
        }
    }

    #[tokio::test]
    async fn database_loss_is_not_repaired_from_a_retained_private_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("voter.sqlite");
        let backend = SqliteSessionBackend::open(&path).unwrap();
        let signer = backend
            .enroll_voter_identity(installation(), identity())
            .await
            .unwrap();
        let selected = member(&signer);
        drop(backend);
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            let entry = entry.unwrap();
            if entry.path() != key_path(&path) {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }
        let backend = SqliteSessionBackend::open(&path).unwrap();
        assert!(matches!(
            backend
                .voter_identity_signer(installation(), &selected)
                .await,
            Err(ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired)
        ));
        assert!(matches!(
            backend
                .enroll_voter_identity(installation(), identity())
                .await,
            Err(ConsensusSessionStoreOpenError::VoterIdentityAlreadyEnrolled)
        ));
        assert!(key_path(&path).is_file());
    }
}
