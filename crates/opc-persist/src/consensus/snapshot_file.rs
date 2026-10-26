//! File-backed snapshot transport for config consensus.

use std::fmt;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

#[cfg(test)]
pub(crate) mod test_io;

/// Integrity of the bytes admitted through this descriptor, invalidated by writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedSnapshotEnvelope {
    pub(crate) payload_length: u64,
    pub(crate) checksum: [u8; 32],
    pub(crate) total_length: u64,
}

/// Seekable snapshot staging file. Its path is never exposed in diagnostics.
pub(crate) struct ConfigSnapshotFile {
    file: super::snapshot_io::SnapshotIo,
    path: PathBuf,
    cleanup_on_drop: bool,
    verified: Option<VerifiedSnapshotEnvelope>,
    #[cfg(test)]
    read_gate: Option<tokio::sync::oneshot::Receiver<()>>,
    #[cfg(test)]
    read_released: bool,
}

impl ConfigSnapshotFile {
    #[cfg(test)]
    pub(crate) async fn create(path: PathBuf) -> io::Result<Self> {
        Self::create_with_owner(path, None).await
    }

    pub(crate) async fn create_owned(
        path: PathBuf,
        owner: std::sync::Arc<super::storage::SnapshotDirectoryOwner>,
    ) -> io::Result<Self> {
        Self::create_with_owner(path, Some(owner)).await
    }

    async fn create_with_owner(
        path: PathBuf,
        owner: Option<std::sync::Arc<super::storage::SnapshotDirectoryOwner>>,
    ) -> io::Result<Self> {
        // Construct the cleanup guard in the blocking task. Cancellation of
        // its receiver cannot strand a file created after the caller was gone.
        tokio::task::spawn_blocking(move || {
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).read(true).write(true);
            #[cfg(unix)]
            options.mode(0o600);
            let file = options.open(&path)?;
            let staged = Self {
                file: super::snapshot_io::SnapshotIo::new(file, owner),
                path,
                cleanup_on_drop: true,
                verified: None,
                #[cfg(test)]
                read_gate: None,
                #[cfg(test)]
                read_released: false,
            };
            #[cfg(unix)]
            std::fs::set_permissions(&staged.path, std::fs::Permissions::from_mode(0o600))?;
            Ok(staged)
        })
        .await
        .map_err(|_| io::Error::other("config snapshot receiver creation failed"))?
    }

    pub(crate) async fn open(path: PathBuf) -> io::Result<Self> {
        Self::open_with_owner(path, None)
    }

    pub(crate) async fn open_owned(
        path: PathBuf,
        owner: std::sync::Arc<super::storage::SnapshotDirectoryOwner>,
    ) -> io::Result<Self> {
        Self::open_with_owner(path, Some(owner))
    }

    fn open_with_owner(
        path: PathBuf,
        owner: Option<std::sync::Arc<super::storage::SnapshotDirectoryOwner>>,
    ) -> io::Result<Self> {
        #[cfg(unix)]
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        #[cfg(not(unix))]
        let file = std::fs::OpenOptions::new().read(true).open(&path)?;
        Ok(Self {
            file: super::snapshot_io::SnapshotIo::new(file, owner),
            path,
            cleanup_on_drop: false,
            verified: None,
            #[cfg(test)]
            read_gate: None,
            #[cfg(test)]
            read_released: false,
        })
    }

    pub(crate) fn verification_reader(
        &mut self,
        owner: std::sync::Arc<super::storage::SnapshotDirectoryOwner>,
    ) -> VerificationReader<'_> {
        let previous = self.file.replace_verification_owner(Some(owner));
        VerificationReader {
            file: self,
            previous,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn verified_envelope(&self) -> Option<VerifiedSnapshotEnvelope> {
        self.verified
    }

    pub(crate) fn set_verified_envelope(&mut self, verified: VerifiedSnapshotEnvelope) {
        self.verified = Some(verified);
    }

    pub(crate) fn invalidate_verified_envelope(&mut self) {
        self.verified = None;
    }

    /// Transfer cleanup responsibility to the snapshot installer.
    pub(crate) fn disarm_cleanup(&mut self) {
        self.cleanup_on_drop = false;
    }

    pub(crate) async fn metadata(&mut self) -> io::Result<std::fs::Metadata> {
        self.file.metadata().await
    }

    pub(crate) async fn sync_all(&mut self) -> io::Result<()> {
        #[cfg(test)]
        test_io::step(&self.path, test_io::Phase::Sync).await;
        self.file.sync_all().await
    }
}

/// Keep admission only for active verification, including cancellation. Each
/// physical worker keeps its own clone after this scope releases the reader.
pub(crate) struct VerificationReader<'a> {
    file: &'a mut ConfigSnapshotFile,
    previous: Option<std::sync::Arc<super::storage::SnapshotDirectoryOwner>>,
}

impl std::ops::Deref for VerificationReader<'_> {
    type Target = ConfigSnapshotFile;

    fn deref(&self) -> &Self::Target {
        self.file
    }
}

impl std::ops::DerefMut for VerificationReader<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.file
    }
}

impl Drop for VerificationReader<'_> {
    fn drop(&mut self) {
        self.file
            .file
            .replace_verification_owner(self.previous.take());
    }
}

impl Drop for ConfigSnapshotFile {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl fmt::Debug for ConfigSnapshotFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfigSnapshotFile(<redacted>)")
    }
}

impl AsyncRead for ConfigSnapshotFile {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        #[cfg(test)]
        if buffer.remaining() >= 4096 {
            use std::future::Future;
            if self.read_gate.is_none() && !self.read_released {
                self.read_gate = test_io::gate(&self.path, test_io::Phase::Read);
            }
            if let Some(gate) = self.read_gate.as_mut() {
                let _ = std::task::ready!(Pin::new(gate).poll(context));
                self.read_gate = None;
                self.read_released = true;
            }
        }
        let result = Pin::new(&mut self.file).poll_read(context, buffer);
        #[cfg(test)]
        if result.is_ready() {
            self.read_released = false;
        }
        result
    }
}

impl AsyncWrite for ConfigSnapshotFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.verified = None;
        Pin::new(&mut self.file).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_shutdown(context)
    }
}

impl AsyncSeek for ConfigSnapshotFile {
    fn start_seek(mut self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        Pin::new(&mut self.file).start_seek(position)
    }

    fn poll_complete(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.file).poll_complete(context)
    }
}
