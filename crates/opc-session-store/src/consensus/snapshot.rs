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

use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, AsyncWriteExt, ReadBuf};

/// A seekable, chunkable snapshot file and its SDK-controlled staging path.
pub(crate) struct SessionSnapshotFile {
    file: tokio::fs::File,
    path: PathBuf,
}

impl SessionSnapshotFile {
    /// Create a new receiving file. Existing data is never reused.
    pub(crate) async fn create(path: PathBuf) -> io::Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .await?;
        Ok(Self { file, path })
    }

    /// Open an immutable current snapshot for transfer.
    pub(crate) async fn open(path: PathBuf) -> io::Result<Self> {
        let file = tokio::fs::OpenOptions::new().read(true).open(&path).await?;
        Ok(Self { file, path })
    }

    /// SDK-controlled path associated with this handle.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Flush both file content and metadata before promotion.
    pub(crate) async fn sync_all(&mut self) -> io::Result<()> {
        self.file.flush().await?;
        self.file.sync_all().await
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
