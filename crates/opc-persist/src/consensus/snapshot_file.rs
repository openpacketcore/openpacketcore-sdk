//! File-backed snapshot transport for config consensus.

use std::fmt;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Seekable snapshot staging file. Its path is never exposed in diagnostics.
pub(crate) struct ConfigSnapshotFile {
    file: tokio::fs::File,
    path: PathBuf,
    cleanup_on_drop: bool,
}

impl ConfigSnapshotFile {
    pub(crate) async fn create(path: PathBuf) -> io::Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .await?;
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            file,
            path,
            cleanup_on_drop: true,
        })
    }

    pub(crate) async fn open(path: PathBuf) -> io::Result<Self> {
        #[cfg(unix)]
        let file = tokio::fs::File::from_std(
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?,
        );
        #[cfg(not(unix))]
        let file = tokio::fs::OpenOptions::new().read(true).open(&path).await?;
        Ok(Self {
            file,
            path,
            cleanup_on_drop: false,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Transfer cleanup responsibility to the snapshot installer.
    pub(crate) fn disarm_cleanup(&mut self) {
        self.cleanup_on_drop = false;
    }

    pub(crate) async fn sync_all(&mut self) -> io::Result<()> {
        self.file.flush().await?;
        self.file.sync_all().await
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
        Pin::new(&mut self.file).poll_read(context, buffer)
    }
}

impl AsyncWrite for ConfigSnapshotFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
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
