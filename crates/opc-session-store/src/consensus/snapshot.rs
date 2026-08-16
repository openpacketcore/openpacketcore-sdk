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

/// Immutable identity taken from an already-open SQLite file descriptor.
///
/// On Linux this is deliberately based on the descriptor rather than its
/// pathname, which makes it stable when a snapshot name is atomically
/// replaced. Other platforms retain the handle wrapper for portable Dynamic
/// snapshot transport; only Linux can use it as a SQLite descriptor binding.
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
    // Only extracted input uses this. Its private 0600 name remains available
    // long enough for SQLite to open the descriptor URI, then is unlinked as
    // soon as the attachment has retained its own descriptor.
    private_staging_path: bool,
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
            private_staging_path: false,
        })
    }

    /// Replace the SDK's writable extraction descriptor with a read-only
    /// descriptor for the same inode.
    ///
    /// The later SQLite attachment uses `/proc/self/fd`, so it does not need
    /// a pathname. Once this returns there is no SDK-held writable descriptor.
    /// The private staging name is removed after SQLite retains its attachment,
    /// before source validation and copying begin.
    #[cfg(target_os = "linux")]
    pub(crate) fn seal_extracted_source(
        writable: std::fs::File,
        path: PathBuf,
    ) -> io::Result<Self> {
        let writable_metadata = writable.metadata()?;
        ensure_regular_file(&writable_metadata)?;
        let identity = file_identity(&writable_metadata)?;

        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let read_only = options.open(&path)?;
        let read_only_metadata = read_only.metadata()?;
        ensure_regular_file(&read_only_metadata)?;
        if file_identity(&read_only_metadata)? != identity
            || file_identity(&writable.metadata()?)? != identity
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "extracted SQLite snapshot identity changed before sealing",
            ));
        }
        // The only writer was created by extraction. Close it before handing
        // this source to SQLite, leaving no SDK-held writer for these bytes.
        drop(writable);
        if file_identity(&read_only.metadata()?)? != identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "extracted SQLite snapshot identity changed while sealing",
            ));
        }
        let path_metadata = std::fs::symlink_metadata(&path)?;
        ensure_regular_file(&path_metadata)?;
        if file_identity(&path_metadata)? != identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "extracted SQLite snapshot path changed while sealing",
            ));
        }
        Ok(Self {
            file: read_only,
            path,
            identity,
            private_staging_path: true,
        })
    }

    /// Descriptor-bound SQLite installation is only supported on Linux.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn seal_extracted_source(
        _writable: std::fs::File,
        _path: PathBuf,
    ) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sealed SQLite snapshot binding requires Linux",
        ))
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
            private_staging_path: false,
        })
    }

    /// Consume the wrapper and return the already-open OS handle.
    pub(crate) fn into_file(self) -> std::fs::File {
        self.file
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

    /// Remove the private extraction name after SQLite has opened an
    /// attachment from this pinned descriptor. Caller-owned snapshot paths are
    /// never removed by this method.
    pub(crate) fn remove_private_staging_path_after_attach(&mut self) -> io::Result<()> {
        if !self.private_staging_path {
            return Ok(());
        }
        let metadata = std::fs::symlink_metadata(&self.path)?;
        ensure_regular_file(&metadata)?;
        if file_identity(&metadata)? != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sealed SQLite snapshot path identity changed before removal",
            ));
        }
        std::fs::remove_file(&self.path)?;
        self.private_staging_path = false;
        Ok(())
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
    /// Receiving files have no durable owner until installation commits.
    /// Dropping one must therefore reclaim its SDK-created staging path.
    cleanup: SnapshotCleanup,
}

/// The cleanup guard is deliberately declared after the file handle above so
/// Rust closes the handle before attempting path removal on every platform.
struct SnapshotCleanup {
    path: Option<PathBuf>,
}

#[cfg(test)]
#[derive(Clone)]
struct SnapshotCreateDeliveryProbe {
    created: std::sync::Arc<std::sync::Barrier>,
    release: std::sync::Arc<std::sync::Barrier>,
    completed: std::sync::Arc<tokio::sync::Notify>,
}

impl SnapshotCleanup {
    fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for SnapshotCleanup {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
}

#[allow(dead_code)]
impl SessionSnapshotFile {
    /// Create a new receiving file. Existing data is never reused.
    pub(crate) async fn create(path: PathBuf) -> io::Result<Self> {
        Self::create_in_detached_owner(
            path,
            #[cfg(test)]
            None,
        )
        .await
    }

    /// Keep creation and the cleanup owner in a detached blocking task. The
    /// OS create and guard construction have no cancellation point between
    /// them; a cancelled receiver makes failed delivery drop that owner.
    async fn create_in_detached_owner(
        path: PathBuf,
        #[cfg(test)] delivery_probe: Option<SnapshotCreateDeliveryProbe>,
    ) -> io::Result<Self> {
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let result = Self::create_new_with_cleanup_sync(path);
            #[cfg(test)]
            if let Some(probe) = &delivery_probe {
                // The test pauses only after `result` owns both the opened
                // descriptor and its unlink guard.
                probe.created.wait();
                probe.release.wait();
            }
            // If the creating future was cancelled, `send` returns the
            // completed owner and dropping it reclaims the receiving path.
            let _ = completion_tx.send(result);
            #[cfg(test)]
            if let Some(probe) = delivery_probe {
                probe.completed.notify_one();
            }
        });
        completion_rx.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::Interrupted,
                "snapshot creation task terminated before completion",
            )
        })?
    }

    fn create_new_with_cleanup_sync(path: PathBuf) -> io::Result<Self> {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snapshot path must not be a symbolic link",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let file = snapshot_create_options(true, true).open(&path)?;
        // Arm only after create_new succeeded, so an existing leaf can never
        // be removed when its open reports AlreadyExists.
        let cleanup = SnapshotCleanup::new(Some(path.clone()));
        ensure_regular_file(&file.metadata()?)?;
        Ok(Self {
            file: tokio::fs::File::from_std(file),
            path,
            cleanup,
        })
    }

    #[cfg(test)]
    async fn create_paused_before_delivery_for_test(
        path: PathBuf,
        delivery_probe: SnapshotCreateDeliveryProbe,
    ) -> io::Result<Self> {
        Self::create_in_detached_owner(path, Some(delivery_probe)).await
    }

    /// Open an immutable current snapshot for transfer.
    pub(crate) async fn open(path: PathBuf) -> io::Result<Self> {
        reject_symlink(&path).await?;
        let file = snapshot_open_options(false, true, false)
            .open(&path)
            .await?;
        Self::from_file(file, path).await
    }

    /// Attach a diagnostic path to an already-open regular snapshot handle.
    pub(crate) async fn from_file(file: tokio::fs::File, path: PathBuf) -> io::Result<Self> {
        Self::from_file_with_cleanup(file, path, false).await
    }

    async fn from_file_with_cleanup(
        file: tokio::fs::File,
        path: PathBuf,
        remove_on_drop: bool,
    ) -> io::Result<Self> {
        // A successful create has already materialized its receiving path.
        // Construct its owner before this metadata await so an I/O failure or
        // caller cancellation cannot orphan the staging file.
        let snapshot = Self {
            file,
            cleanup: SnapshotCleanup::new(remove_on_drop.then(|| path.clone())),
            path,
        };
        ensure_regular_file(&snapshot.file.metadata().await?)?;
        Ok(snapshot)
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
        // The original remains the sole owner of a receiving staging path;
        // a transient clone must not remove it while that owner is live.
        Self::from_file(self.file.try_clone().await?, self.path.clone()).await
    }

    /// Consume the wrapper and return the already-open standard file.
    pub(crate) async fn into_std(mut self) -> io::Result<std::fs::File> {
        // A type with a drop cleanup hook cannot move its field out directly.
        // Clone the descriptor, leave the original to close, and deliberately
        // transfer path ownership away from the wrapper.
        let cloned = self.file.try_clone().await?;
        self.cleanup.disarm();
        Ok(cloned.into_std().await)
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

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn file_identity(_metadata: &std::fs::Metadata) -> io::Result<FileIdentity> {
    Ok(FileIdentity)
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

fn snapshot_create_options(read: bool, write: bool) -> std::fs::OpenOptions {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).read(read).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

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
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

impl AsyncWrite for SessionSnapshotFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.file).poll_write(cx, buf)
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
        Pin::new(&mut self.file).start_seek(position)
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.file).poll_complete(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;

    #[cfg(target_os = "linux")]
    use super::PinnedSqliteFile;
    use super::SessionSnapshotFile;
    use tempfile::tempdir;

    use super::SnapshotCreateDeliveryProbe;

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
    async fn receiving_snapshot_is_removed_when_dropped_before_install(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let snapshot = SessionSnapshotFile::create(path.clone()).await?;
        assert!(path.exists());
        drop(snapshot);
        assert!(!path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_create_reclaims_path_created_before_delivery(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let probe = SnapshotCreateDeliveryProbe {
            created: Arc::new(std::sync::Barrier::new(2)),
            release: Arc::new(std::sync::Barrier::new(2)),
            completed: Arc::new(tokio::sync::Notify::new()),
        };
        let creator = tokio::spawn(SessionSnapshotFile::create_paused_before_delivery_for_test(
            path.clone(),
            probe.clone(),
        ));
        let created = Arc::clone(&probe.created);
        tokio::task::spawn_blocking(move || created.wait())
            .await
            .expect("creation reaches post-owner hold");
        assert!(path.exists(), "the receiving file was created");

        creator.abort();
        let _ = creator.await;
        let release = Arc::clone(&probe.release);
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .expect("release post-owner hold");
        probe.completed.notified().await;
        assert!(
            !path.exists(),
            "failed delivery drops the armed owner and reclaims the path"
        );
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
        let pinned = PinnedSqliteFile::from_file(snapshot.into_std().await?, path.clone())?;
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
    fn sealing_extracted_source_removes_writer_then_staging_name_after_attachment(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.sqlite");
        let mut writable = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        writable.write_all(b"exact incoming bytes")?;
        writable.sync_all()?;

        let mut sealed = PinnedSqliteFile::seal_extracted_source(writable, path.clone())?;
        assert!(path.exists());
        sealed.verify_identity()?;
        let mut cloned = sealed.file().try_clone()?;
        assert!(cloned.write_all(b"mutation").is_err());
        sealed.verify_identity()?;
        sealed.remove_private_staging_path_after_attach()?;
        assert!(!path.exists());
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
            let pinned = PinnedSqliteFile::from_file(snapshot.into_std().await?, path)?;
            assert!(!format!("{pinned:?}").contains("secret-snapshot-name"));
        }
        Ok(())
    }
}
