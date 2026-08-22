//! File-backed snapshot transport owned by the session consensus adapter.
//!
//! Keeping the path beside the Tokio file handle lets the SQLite state
//! machine atomically promote a fully received snapshot without buffering it
//! in process memory. Diagnostics deliberately do not expose the path.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, RawFd};
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt as _;
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt as _, AsyncWrite, AsyncWriteExt, ReadBuf};

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum payload bytes admitted in one consensus snapshot envelope.
pub(crate) const SNAPSHOT_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Maximum bytes accepted from a snapshot sender, including its fixed footer.
pub(crate) const SNAPSHOT_MAX_ENVELOPE_BYTES: u64 = SNAPSHOT_MAX_BYTES + 48;

/// Test-only coordination around a snapshot artifact lifecycle boundary.
#[cfg(test)]
pub(crate) struct SnapshotArtifactGate {
    armed: AtomicBool,
    started: AtomicBool,
    started_notify: tokio::sync::Notify,
    released: AtomicBool,
    released_notify: tokio::sync::Notify,
}

#[cfg(test)]
impl SnapshotArtifactGate {
    pub(crate) fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            started: AtomicBool::new(false),
            started_notify: tokio::sync::Notify::new(),
            released: AtomicBool::new(false),
            released_notify: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn arm(&self) {
        self.started.store(false, Ordering::Release);
        self.released.store(false, Ordering::Release);
        self.armed.store(true, Ordering::Release);
    }

    pub(crate) async fn wait_started(&self) {
        while !self.started.load(Ordering::Acquire) {
            self.started_notify.notified().await;
        }
    }

    pub(crate) fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.released_notify.notify_waiters();
    }

    pub(crate) async fn block_if_armed(&self) {
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        self.started.store(true, Ordering::Release);
        self.started_notify.notify_waiters();
        while !self.released.load(Ordering::Acquire) {
            self.released_notify.notified().await;
        }
        self.armed.store(false, Ordering::Release);
    }
}

/// Immutable identity taken from an already-open SQLite file descriptor.
///
/// On Linux this is deliberately based on the descriptor rather than its
/// pathname, which makes it stable when a snapshot name is atomically
/// replaced. Other platforms retain this internal handle shape for cfg
/// completeness, but public dynamic and fixed consensus initialization both
/// fail closed before snapshot state is created.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity;

/// A regular SQLite file pinned to an existing OS handle.
///
/// `path` is diagnostic and cleanup information only. It must never be used
/// as authorization that an operation still targets this handle.
#[allow(dead_code)]
pub(crate) struct PinnedSqliteFile {
    file: std::fs::File,
    path: PathBuf,
    identity: FileIdentity,
    cleanup: Option<UnpublishedSnapshotArtifact>,
}

/// Exact ownership of an SDK-created snapshot artifact which is not yet
/// published. Cleanup authenticates the object by its open-descriptor identity
/// before unlinking the SDK-controlled name, so a same-name replacement is
/// never removed.
pub(crate) struct UnpublishedSnapshotArtifact {
    path: PathBuf,
    identity: FileIdentity,
    sqlite_sidecars: bool,
    sidecars: Vec<(PathBuf, FileIdentity)>,
    armed: bool,
}

impl UnpublishedSnapshotArtifact {
    pub(crate) fn from_file(
        file: &std::fs::File,
        path: PathBuf,
        sqlite_sidecars: bool,
    ) -> io::Result<Self> {
        Self::from_metadata(path, &file.metadata()?, sqlite_sidecars)
    }

    pub(crate) fn from_metadata(
        path: PathBuf,
        metadata: &std::fs::Metadata,
        sqlite_sidecars: bool,
    ) -> io::Result<Self> {
        Ok(Self {
            path,
            identity: file_identity(metadata)?,
            sqlite_sidecars,
            sidecars: Vec::new(),
            armed: true,
        })
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    pub(crate) fn rebind_path(&mut self, path: PathBuf) {
        self.path = path;
    }

    fn capture_sidecars(&mut self) {
        if !self.sqlite_sidecars {
            return;
        }
        self.sidecars.clear();
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = self.path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            let Ok(metadata) = std::fs::symlink_metadata(&sidecar) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            if let Ok(identity) = file_identity(&metadata) {
                self.sidecars.push((sidecar, identity));
            }
        }
    }

    fn remove_if_owned(&self, path: &Path, identity: FileIdentity) {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return;
        };
        if !metadata.is_file() {
            return;
        }
        let Ok(observed) = file_identity(&metadata) else {
            return;
        };
        if same_file_object(observed, identity) {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Drop for UnpublishedSnapshotArtifact {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.remove_if_owned(&self.path, self.identity);
        for (sidecar, identity) in &self.sidecars {
            self.remove_if_owned(sidecar, *identity);
        }
    }
}

#[allow(dead_code)]
impl PinnedSqliteFile {
    /// Pin an already-open regular SQLite file to its current handle identity.
    pub(crate) fn from_file(file: std::fs::File, path: PathBuf) -> io::Result<Self> {
        let metadata = file.metadata()?;
        ensure_regular_file(&metadata)?;
        let identity = file_identity(&metadata)?;
        Ok(Self {
            file,
            path,
            identity,
            cleanup: None,
        })
    }

    /// Pin a newly-created SDK snapshot database and arm exact cleanup until
    /// the caller has durably published its enclosing snapshot.
    pub(crate) fn from_new_file(file: std::fs::File, path: PathBuf) -> io::Result<Self> {
        let mut pinned = Self::from_file(file, path)?;
        pinned.cleanup = Some(UnpublishedSnapshotArtifact::from_file(
            &pinned.file,
            pinned.path.clone(),
            true,
        )?);
        Ok(pinned)
    }

    /// The SDK-controlled diagnostic path associated with this handle.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The identity captured from the open handle when it was pinned.
    pub(crate) fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Borrow the pinned handle without resolving its pathname again.
    pub(crate) fn file(&self) -> &std::fs::File {
        &self.file
    }

    /// Clone the pinned OS handle without reopening its pathname.
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        self.verify_identity()?;
        let file = self.file.try_clone()?;
        if file_identity(&file.metadata()?)? != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cloned SQLite file handle identity changed",
            ));
        }
        Ok(Self {
            file,
            path: self.path.clone(),
            identity: self.identity,
            cleanup: None,
        })
    }

    /// Consume the wrapper and return the already-open OS handle.
    pub(crate) fn into_file(mut self) -> std::fs::File {
        self.cleanup = None;
        self.file
    }

    /// Transfer cleanup ownership alongside the descriptor for an
    /// unpublished SDK-created artifact.
    pub(crate) fn into_file_with_cleanup(
        mut self,
    ) -> (std::fs::File, Option<UnpublishedSnapshotArtifact>) {
        let cleanup = self.cleanup.take();
        (self.file, cleanup)
    }

    /// Mark the SDK-created database as intentionally retained by its caller.
    pub(crate) fn disarm_cleanup(&mut self) {
        if let Some(cleanup) = self.cleanup.as_mut() {
            cleanup.disarm();
        }
    }

    /// Refresh the expected content identity after SQLite has written through
    /// this same descriptor. Cleanup ownership remains attached to the inode.
    pub(crate) fn refresh_identity(mut self) -> io::Result<Self> {
        self.identity = file_identity(&self.file.metadata()?)?;
        Ok(self)
    }

    /// Record the exact identities of any SQLite sidecars created for this
    /// unique raw artifact, so later cleanup cannot remove replacements.
    pub(crate) fn capture_created_sidecars(&mut self) {
        if let Some(cleanup) = self.cleanup.as_mut() {
            cleanup.capture_sidecars();
        }
    }

    /// Revalidate that the held handle itself has not changed identity.
    pub(crate) fn verify_identity(&self) -> io::Result<()> {
        let current = file_identity(&self.file.metadata()?)?;
        if current == self.identity {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pinned SQLite file handle identity changed",
            ))
        }
    }

    /// Compare a pathname with the pinned identity for diagnostics or cleanup.
    ///
    /// This follows the path at the time of comparison and is intentionally
    /// not an authorization primitive.
    pub(crate) fn path_matches_identity(&self, path: &Path) -> io::Result<bool> {
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_file() {
            return Ok(false);
        }
        Ok(file_identity(&metadata)? == self.identity)
    }

    /// Return the descriptor for descriptor-based SQLite binding on Linux.
    #[cfg(target_os = "linux")]
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl fmt::Debug for PinnedSqliteFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedSqliteFile(<redacted>)")
    }
}

/// A seekable, chunkable snapshot file and its SDK-controlled staging path.
pub(crate) struct SessionSnapshotFile {
    file: tokio::fs::File,
    path: PathBuf,
    _cleanup: Option<UnpublishedSnapshotArtifact>,
    position: u64,
    length: u64,
    receiving: bool,
}

#[allow(dead_code)]
impl SessionSnapshotFile {
    /// Create a new receiving file. Existing data is never reused.
    pub(crate) async fn create(path: PathBuf) -> io::Result<Self> {
        #[cfg(test)]
        {
            return Self::create_inner(path, None).await;
        }
        #[cfg(not(test))]
        {
            Self::create_inner(path).await
        }
    }

    async fn create_inner(
        path: PathBuf,
        #[cfg(test)] after_create: Option<&SnapshotArtifactGate>,
    ) -> io::Result<Self> {
        reject_symlink(&path).await?;
        let file = snapshot_open_options(true, true, true).open(&path).await?;
        #[cfg(test)]
        if let Some(after_create) = after_create {
            after_create.block_if_armed().await;
        }
        let cleanup = UnpublishedSnapshotArtifact::from_metadata(
            path.clone(),
            &file.metadata().await?,
            false,
        )?;
        Self::from_file_with_cleanup(file, path, Some(cleanup)).await
    }

    /// Open an immutable current snapshot for transfer.
    pub(crate) async fn open(path: PathBuf) -> io::Result<Self> {
        reject_symlink(&path).await?;
        let file = snapshot_open_options(false, true, false)
            .open(&path)
            .await?;
        Self::from_file_with_cleanup(file, path, None).await
    }

    /// Attach a diagnostic path to an already-open regular snapshot handle.
    pub(crate) async fn from_file(file: tokio::fs::File, path: PathBuf) -> io::Result<Self> {
        Self::from_file_with_cleanup(file, path, None).await
    }

    async fn from_file_with_cleanup(
        file: tokio::fs::File,
        path: PathBuf,
        cleanup: Option<UnpublishedSnapshotArtifact>,
    ) -> io::Result<Self> {
        let metadata = file.metadata().await?;
        ensure_regular_file(&metadata)?;
        let length = metadata.len();
        if length > SNAPSHOT_MAX_ENVELOPE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot file exceeds the maximum envelope size",
            ));
        }
        let receiving = cleanup.is_some();
        Ok(Self {
            file,
            path,
            _cleanup: cleanup,
            position: 0,
            length,
            receiving,
        })
    }

    /// Convert an already-open standard file without resolving its path again.
    pub(crate) async fn from_std(file: std::fs::File, path: PathBuf) -> io::Result<Self> {
        Self::from_file(tokio::fs::File::from_std(file), path).await
    }

    /// SDK-controlled path associated with this handle.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Borrow the held Tokio file without reopening its path.
    pub(crate) fn file(&self) -> &tokio::fs::File {
        &self.file
    }

    /// Mutably borrow the held Tokio file without reopening its path.
    pub(crate) fn file_mut(&mut self) -> &mut tokio::fs::File {
        &mut self.file
    }

    /// Clone the held file handle without resolving its path again.
    pub(crate) async fn try_clone(&self) -> io::Result<Self> {
        Self::from_file(self.file.try_clone().await?, self.path.clone()).await
    }

    /// Consume the wrapper and return the already-open Tokio file.
    pub(crate) fn into_file(self) -> tokio::fs::File {
        self.file
    }

    /// Consume the wrapper and return the already-open standard file.
    pub(crate) async fn into_std(self) -> std::fs::File {
        self.file.into_std().await
    }

    /// Read metadata from the held handle rather than resolving its path.
    pub(crate) async fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file.metadata().await
    }

    /// Seek the held file back to its first byte.
    pub(crate) async fn rewind(&mut self) -> io::Result<()> {
        self.file.rewind().await.map(|_| ())
    }

    /// Flush both file content and metadata before promotion.
    pub(crate) async fn sync_all(&mut self) -> io::Result<()> {
        self.file.flush().await?;
        self.file.sync_all().await
    }
}

fn ensure_regular_file(metadata: &std::fs::Metadata) -> io::Result<()> {
    if metadata.is_file() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot file must be a regular file",
        ))
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn file_identity(metadata: &std::fs::Metadata) -> io::Result<FileIdentity> {
    Ok(FileIdentity {
        device: metadata.st_dev(),
        inode: metadata.st_ino(),
        size: metadata.st_size(),
    })
}

#[cfg(target_os = "linux")]
fn same_file_object(left: FileIdentity, right: FileIdentity) -> bool {
    left.device == right.device && left.inode == right.inode
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn file_identity(_metadata: &std::fs::Metadata) -> io::Result<FileIdentity> {
    Ok(FileIdentity)
}

#[cfg(not(target_os = "linux"))]
fn same_file_object(_left: FileIdentity, _right: FileIdentity) -> bool {
    false
}

fn snapshot_open_options(create_new: bool, read: bool, write: bool) -> tokio::fs::OpenOptions {
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(create_new).read(read).write(write);
    #[cfg(unix)]
    {
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}

async fn reject_symlink(path: &Path) -> io::Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot path must not be a symbolic link",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

impl fmt::Debug for SessionSnapshotFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSnapshotFile(<redacted>)")
    }
}

impl AsyncRead for SessionSnapshotFile {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.file).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = match u64::try_from(buf.filled().len() - before) {
                    Ok(read) => read,
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snapshot read length overflow",
                        )));
                    }
                };
                self.position = match self.position.checked_add(read) {
                    Some(position) => position,
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snapshot position overflow",
                        )));
                    }
                };
                Poll::Ready(Ok(()))
            }
            pending => pending,
        }
    }
}

impl AsyncWrite for SessionSnapshotFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.receiving && self.position != self.length {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot receive writes must be contiguous",
            )));
        }
        let requested = match u64::try_from(buf.len()) {
            Ok(length) => length,
            Err(_) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snapshot write length is invalid",
                )));
            }
        };
        if self
            .position
            .checked_add(requested)
            .is_none_or(|end| end > SNAPSHOT_MAX_ENVELOPE_BYTES)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot write exceeds the maximum envelope size",
            )));
        }
        match Pin::new(&mut self.file).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                let written_u64 = match u64::try_from(written) {
                    Ok(written) => written,
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snapshot write length overflow",
                        )));
                    }
                };
                self.position = match self.position.checked_add(written_u64) {
                    Some(position) => position,
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snapshot position overflow",
                        )));
                    }
                };
                self.length = self.length.max(self.position);
                Poll::Ready(Ok(written))
            }
            pending => pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.file).poll_shutdown(cx)
    }
}

impl AsyncSeek for SessionSnapshotFile {
    fn start_seek(mut self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        let target = match position {
            io::SeekFrom::Start(offset) => i128::from(offset),
            io::SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
            io::SeekFrom::End(offset) => i128::from(self.length) + i128::from(offset),
        };
        if target < 0 || target > i128::from(SNAPSHOT_MAX_ENVELOPE_BYTES) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot seek exceeds the maximum envelope size",
            ));
        }
        let target = u64::try_from(target).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot seek target is invalid",
            )
        })?;
        Pin::new(&mut self.file).start_seek(io::SeekFrom::Start(target))?;
        Ok(())
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        match Pin::new(&mut self.file).poll_complete(cx) {
            Poll::Ready(Ok(position)) if position <= SNAPSHOT_MAX_ENVELOPE_BYTES => {
                self.position = position;
                Poll::Ready(Ok(position))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot seek exceeds the maximum envelope size",
            ))),
            pending => pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    #[cfg(target_os = "linux")]
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;

    #[cfg(target_os = "linux")]
    use super::{PinnedSqliteFile, UnpublishedSnapshotArtifact};
    use super::{SessionSnapshotFile, SnapshotArtifactGate};
    use tempfile::tempdir;

    #[cfg(target_os = "linux")]
    #[test]
    fn unpublished_sqlite_cleanup_removes_only_its_created_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("build.sqlite");
        let created = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let owned = PinnedSqliteFile::from_new_file(created, path.clone())?;
        drop(owned);
        assert!(!path.exists());

        let created = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let owned = PinnedSqliteFile::from_new_file(created, path.clone())?;
        let replacement = directory.path().join("replacement.sqlite");
        std::fs::write(&replacement, b"replacement")?;
        std::fs::rename(&replacement, &path)?;
        drop(owned);
        assert_eq!(std::fs::read(&path)?, b"replacement");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unpublished_sqlite_cleanup_fences_each_created_sidecar_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("build.sqlite");
        let created = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let mut owned = PinnedSqliteFile::from_new_file(created, path.clone())?;
        let wal = directory.path().join("build.sqlite-wal");
        let shm = directory.path().join("build.sqlite-shm");
        std::fs::write(&wal, b"owned wal")?;
        std::fs::write(&shm, b"owned shm")?;
        owned.capture_created_sidecars();

        let replacement = directory.path().join("replacement-wal");
        std::fs::write(&replacement, b"foreign replacement")?;
        std::fs::rename(&replacement, &wal)?;
        drop(owned);

        assert!(!path.exists());
        assert!(!shm.exists());
        assert_eq!(std::fs::read(wal)?, b"foreign replacement");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unpublished_snapshot_cleanup_tracks_atomic_promotion_and_publication(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let temporary = directory.path().join("seal.part");
        let published = directory.path().join("snapshot.opc");
        let created = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&temporary)?;
        let mut cleanup =
            UnpublishedSnapshotArtifact::from_file(&created, temporary.clone(), false)?;
        std::fs::rename(&temporary, &published)?;
        cleanup.rebind_path(published.clone());
        drop(cleanup);
        assert!(!published.exists());

        let created = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&temporary)?;
        let mut cleanup =
            UnpublishedSnapshotArtifact::from_file(&created, temporary.clone(), false)?;
        std::fs::rename(&temporary, &published)?;
        cleanup.rebind_path(published.clone());
        cleanup.disarm();
        drop(cleanup);
        assert!(published.exists());
        Ok(())
    }

    #[tokio::test]
    async fn create_new_rejects_an_existing_file() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("snapshot");
        let _snapshot = SessionSnapshotFile::create(path.clone()).await?;

        let error = SessionSnapshotFile::create(path)
            .await
            .err()
            .ok_or("create succeeded")?;
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_immediately_after_receive_create_cleans_the_exact_artifact(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming-cancelled.part");
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let task_path = path.clone();
        let task_gate = Arc::clone(&gate);
        let task = tokio::spawn(async move {
            let _snapshot =
                SessionSnapshotFile::create_inner(task_path, Some(task_gate.as_ref())).await?;
            Ok::<(), io::Error>(())
        });

        gate.wait_started().await;
        assert!(path.is_file(), "the created receive artifact is observable");
        task.abort();
        assert!(task
            .await
            .expect_err("receive task is cancelled")
            .is_cancelled());
        assert!(
            !path.exists(),
            "cancellation after create must clean the exact receive artifact"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn abandoned_receive_cleanup_never_unlinks_a_same_name_replacement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let receiving = SessionSnapshotFile::create(path.clone()).await?;
        let replacement = directory.path().join("replacement.part");
        std::fs::write(&replacement, b"replacement")?;
        std::fs::rename(&replacement, &path)?;
        drop(receiving);
        assert_eq!(std::fs::read(path)?, b"replacement");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_non_regular_files() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("directory");
        std::fs::create_dir(&path)?;

        let error = SessionSnapshotFile::open(path)
            .await
            .err()
            .ok_or("directory was accepted as a snapshot")?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symbolic_link_paths() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempdir()?;
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        std::fs::write(&target, b"snapshot")?;
        symlink(&target, &link)?;

        let error = SessionSnapshotFile::open(link)
            .await
            .err()
            .ok_or("symbolic link was accepted as a snapshot")?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn open_handle_survives_atomic_path_replacement() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let path = directory.path().join("snapshot");
        std::fs::write(&path, b"original")?;
        let snapshot = SessionSnapshotFile::open(path.clone()).await?;
        let pinned = PinnedSqliteFile::from_file(snapshot.into_std().await, path.clone())?;
        let identity = pinned.identity();

        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"replacement")?;
        std::fs::rename(&replacement, &path)?;

        pinned.verify_identity()?;
        assert_eq!(pinned.identity(), identity);
        assert!(!pinned.path_matches_identity(&path)?);
        let mut bytes = Vec::new();
        pinned.file().try_clone()?.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"original");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn revalidation_detects_mutation_of_held_file() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("snapshot");
        std::fs::write(&path, b"original")?;
        let pinned = PinnedSqliteFile::from_file(std::fs::File::open(&path)?, path.clone())?;

        let mut writer = std::fs::OpenOptions::new().append(true).open(path)?;
        writer.write_all(b" changed")?;
        writer.sync_all()?;

        let error = pinned
            .verify_identity()
            .err()
            .ok_or("mutated handle identity was accepted")?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        Ok(())
    }

    #[tokio::test]
    async fn debug_redacts_paths() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("secret-snapshot-name");
        let snapshot = SessionSnapshotFile::create(path.clone()).await?;
        assert!(!format!("{snapshot:?}").contains("secret-snapshot-name"));

        #[cfg(target_os = "linux")]
        {
            let pinned = PinnedSqliteFile::from_file(snapshot.into_std().await, path)?;
            assert!(!format!("{pinned:?}").contains("secret-snapshot-name"));
        }
        Ok(())
    }
}
