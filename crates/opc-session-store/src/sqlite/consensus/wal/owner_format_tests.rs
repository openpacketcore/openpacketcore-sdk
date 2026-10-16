use super::*;
use crate::consensus::storage::SessionConsensusStorageError;
use std::os::unix::fs::DirBuilderExt;

struct RootFixture {
    _directory: tempfile::TempDir,
    owner: NativeOwner,
    root_path: PathBuf,
    binding: Binding,
}

impl RootFixture {
    fn new(mode: SessionPersistenceMode) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let database = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join("store.sqlite"))
            .unwrap();
        let native_path = directory.path().join("store.sqlite.native-wal");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&native_path)
            .unwrap();
        let binding = Binding {
            identity: consensus::SessionConsensusIdentity::new(
                crate::consensus::SessionConsensusClusterId::new("native-root-format").unwrap(),
                crate::consensus::SessionConsensusConfigurationId::from_bytes([0x91; 32]),
                crate::consensus::SessionConsensusConfigurationEpoch::new(1).unwrap(),
            ),
            generation: [0x92; 32],
            basis: [0x93; 32],
            native: true,
            persistence: mode,
            async_closed_format: mode == SessionPersistenceMode::Async,
            async_recovery_format: mode == SessionPersistenceMode::Async,
        };
        let owner = NativeOwner {
            parent: Arc::new(File::open(directory.path()).unwrap()),
            database_identity: identity(&database.metadata().unwrap()),
            database,
            database_name: "store.sqlite".into(),
            native_name: "store.sqlite.native-wal".into(),
            selected: AtomicBool::new(true),
            current: Mutex::new(Weak::new()),
            generation_hook: Mutex::new(None),
            root_hook: Mutex::new(None),
            io_hook: Mutex::new(None),
            preflight_hook: Mutex::new(None),
        };
        Self {
            _directory: directory,
            owner,
            root_path: native_path.join("ROOT"),
            binding,
        }
    }

    fn select_root(&self, magic: &[u8; 8], digest: [u8; 32]) {
        let native = File::open(self.root_path.parent().unwrap()).unwrap();
        let (dev, ino) = identity(&native.metadata().unwrap());
        let mut bytes = Vec::from(*magic);
        for n in [
            self.owner.database_identity.0,
            self.owner.database_identity.1,
            dev,
            ino,
        ] {
            bytes.extend_from_slice(&n.to_be_bytes());
        }
        bytes.extend_from_slice(&self.binding.generation);
        bytes.extend_from_slice(&self.binding.basis);
        bytes.extend_from_slice(&digest);
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        assert_eq!(bytes.len() as u64, ROOT_BYTES);
        let mut root = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.root_path)
            .unwrap();
        root.write_all(&bytes).unwrap();
        root.sync_all().unwrap();
        rustix::fs::fsetxattr(
            &self.owner.database,
            SELECTION_ATTRIBUTE,
            &bytes,
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        self.owner.database.sync_all().unwrap();
    }

    fn legacy_digest(&self, domain: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(consensus::encode_json(&self.binding.identity).unwrap());
        hash.update(self.binding.generation);
        hash.update(self.binding.basis);
        hash.finalize().into()
    }

    fn bytes(&self) -> (Vec<u8>, Option<[u8; ROOT_BYTES as usize]>, Vec<u8>) {
        (
            fs::read(&self.root_path).unwrap(),
            read_selection(&self.owner.database).unwrap(),
            fs::read(self._directory.path().join("store.sqlite")).unwrap(),
        )
    }
}

#[test]
fn native_root_old_formats_require_fresh_installation_without_mutating_selection() {
    for (magic, domain, mode) in [
        (
            b"OPCNR001",
            b"opc-session-native-wal-v1".as_slice(),
            SessionPersistenceMode::Durable,
        ),
        (
            b"OPCNA001",
            b"opc-session-native-async-v1".as_slice(),
            SessionPersistenceMode::Async,
        ),
        (
            b"OPCNA002",
            b"opc-session-native-async-v2".as_slice(),
            SessionPersistenceMode::Async,
        ),
        (
            b"OPCNA003",
            b"opc-session-native-async-v3".as_slice(),
            SessionPersistenceMode::Async,
        ),
    ] {
        let fixture = RootFixture::new(mode);
        fixture.select_root(magic, fixture.legacy_digest(domain));
        let before = fixture.bytes();
        let error = fixture
            .owner
            .persistence_mode(fixture.binding.identity)
            .unwrap_err();
        assert_eq!(error.to_string(), "native root persistence format differs");
        assert_eq!(
            error
                .get_ref()
                .and_then(|e| e.downcast_ref::<SessionConsensusStorageError>()),
            Some(&SessionConsensusStorageError::PersistenceFormatMismatch)
        );
        assert_eq!(fixture.bytes(), before);
        let error = SessionConsensusStorageError::from_validation_error(error);
        assert_eq!(
            error,
            SessionConsensusStorageError::PersistenceFormatMismatch
        );
        assert_eq!(
            crate::ConsensusSessionStoreOpenError::from(error),
            crate::ConsensusSessionStoreOpenError::FreshInstallationRequired
        );

        let current_magic = if mode == SessionPersistenceMode::Durable {
            ROOT_MAGIC
        } else {
            ASYNC_RECOVERY_ROOT_MAGIC
        };
        fixture.select_root(current_magic, fixture.binding.digest().unwrap());
        let current = fixture.bytes();
        assert_eq!(
            fixture
                .owner
                .persistence_mode(fixture.binding.identity)
                .unwrap(),
            Some(mode)
        );
        assert_eq!(fixture.bytes(), current);
    }
}
