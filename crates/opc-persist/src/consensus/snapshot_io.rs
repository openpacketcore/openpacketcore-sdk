//! Snapshot file operations whose blocking work retains directory admission.

use std::fs::{File, Metadata, Permissions};
use std::future::Future as _;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::task::JoinHandle;

use super::storage::SnapshotDirectoryOwner;

// Each blocking closure owns this handle, including while queued. Dropping its
// async caller or runtime cannot release admission before the physical I/O.
struct OwnedHandle {
    file: Mutex<SnapshotFile>,
    _owner: Option<Arc<SnapshotDirectoryOwner>>,
}

struct SnapshotFile {
    file: File,
    #[cfg(test)]
    positioning_calls: usize,
}

impl SnapshotFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)
    }

    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        #[cfg(test)]
        {
            self.positioning_calls += 1;
        }
        self.file.seek(position)
    }

    fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    fn metadata(&self) -> io::Result<Metadata> {
        self.file.metadata()
    }

    fn set_permissions(&self, permissions: Permissions) -> io::Result<()> {
        self.file.set_permissions(permissions)
    }
}

enum CompletedIo {
    Read(Vec<u8>),
    Written,
    Sought(u64),
}

pub(super) struct SnapshotIo {
    handle: Arc<OwnedHandle>,
    verification_owner: Option<Arc<SnapshotDirectoryOwner>>,
    pending: Option<JoinHandle<io::Result<CompletedIo>>>,
    position: u64,
    seek: Option<SeekFrom>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    read_ready: bool,
}

impl SnapshotIo {
    // Match the existing snapshot copy buffer; a poll never queues unbounded
    // memory, and each file has at most one pending data operation.
    const BUFFER_BYTES: usize = 1024 * 1024;

    pub(super) fn new(file: File, owner: Option<Arc<SnapshotDirectoryOwner>>) -> Self {
        Self {
            handle: Arc::new(OwnedHandle {
                file: Mutex::new(SnapshotFile {
                    file,
                    #[cfg(test)]
                    positioning_calls: 0,
                }),
                _owner: owner,
            }),
            verification_owner: None,
            pending: None,
            position: 0,
            seek: None,
            read_buffer: Vec::new(),
            read_offset: 0,
            read_ready: false,
        }
    }

    pub(super) fn replace_verification_owner(
        &mut self,
        owner: Option<Arc<SnapshotDirectoryOwner>>,
    ) -> Option<Arc<SnapshotDirectoryOwner>> {
        std::mem::replace(&mut self.verification_owner, owner)
    }

    fn spawn<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut SnapshotFile) -> io::Result<T> + Send + 'static,
    ) -> JoinHandle<io::Result<T>> {
        let handle = self.handle.clone();
        let owner = self.verification_owner.clone();
        tokio::task::spawn_blocking(move || {
            // Verification can borrow an exported descriptor-only reader. Its
            // scope may end before this physical operation, so retain its own
            // admission independently of that scope and the reader's lifetime.
            let _owner = owner;
            let mut file = handle
                .file
                .lock()
                .map_err(|_| io::Error::other("config snapshot file lock poisoned"))?;
            operation(&mut file)
        })
    }

    async fn run<T: Send + 'static>(
        &mut self,
        operation: impl FnOnce(&mut SnapshotFile) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        self.flush().await?;
        self.spawn(operation)
            .await
            .map_err(|_| io::Error::other("config snapshot file worker failed"))?
    }

    pub(super) async fn sync_all(&mut self) -> io::Result<()> {
        self.run(|file| file.sync_all()).await
    }

    pub(super) async fn metadata(&mut self) -> io::Result<Metadata> {
        self.run(|file| file.metadata()).await
    }

    pub(super) async fn set_permissions(&mut self, permissions: Permissions) -> io::Result<()> {
        self.run(move |file| file.set_permissions(permissions))
            .await
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let result = ready!(Pin::new(pending).poll(cx));
        self.pending = None;
        match result.map_err(|_| io::Error::other("config snapshot file worker failed"))?? {
            CompletedIo::Read(bytes) => {
                self.read_buffer = bytes;
                self.read_offset = 0;
                self.read_ready = true;
            }
            CompletedIo::Written => {}
            CompletedIo::Sought(position) => self.position = position,
        }
        Poll::Ready(Ok(()))
    }

    fn discard_read(&mut self) {
        self.read_buffer.clear();
        self.read_offset = 0;
        self.read_ready = false;
    }
}

impl AsyncRead for SnapshotIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_complete(cx))?;
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.read_ready {
            let position = self.position;
            let length = output.remaining().min(Self::BUFFER_BYTES);
            self.pending = Some(self.spawn(move |file| {
                file.seek(SeekFrom::Start(position))?;
                let mut bytes = vec![0; length];
                let read = file.read(&mut bytes)?;
                bytes.truncate(read);
                Ok(CompletedIo::Read(bytes))
            }));
            ready!(self.poll_pending(cx))?;
        }
        let length = output
            .remaining()
            .min(self.read_buffer.len() - self.read_offset);
        output.put_slice(&self.read_buffer[self.read_offset..self.read_offset + length]);
        self.read_offset += length;
        self.position += length as u64;
        if self.read_offset == self.read_buffer.len() {
            self.discard_read();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SnapshotIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.as_mut().poll_complete(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = input.len().min(Self::BUFFER_BYTES);
        let position = self.position;
        let next = position.checked_add(length as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "snapshot offset overflow")
        })?;
        let bytes = input[..length].to_vec();
        self.discard_read();
        self.pending = Some(self.spawn(move |file| {
            file.seek(SeekFrom::Start(position))?;
            file.write_all(&bytes)?;
            Ok(CompletedIo::Written)
        }));
        self.position = next;
        // As with Tokio File, accepted bytes may still be queued. The closure
        // owns admission; flush/seek/the next write observes its result.
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_complete(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl AsyncSeek for SnapshotIo {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        if self.seek.is_some() {
            return Err(io::Error::other("config snapshot seek already in progress"));
        }
        self.seek = Some(position);
        Ok(())
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        ready!(self.poll_pending(cx))?;
        if let Some(seek) = self.seek.take() {
            let position = self.position;
            self.discard_read();
            self.pending = Some(self.spawn(move |file| {
                // Reads advance the logical position only when delivered, so a
                // cancelled read or a smaller replacement buffer cannot skip data.
                file.seek(SeekFrom::Start(position))?;
                file.seek(seek).map(CompletedIo::Sought)
            }));
            ready!(self.poll_pending(cx))?;
        }
        Poll::Ready(Ok(self.position))
    }
}

#[cfg(test)]
mod operation_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

    #[tokio::test]
    async fn cancelled_read_preserves_position_for_smaller_reads_writes_and_seeks() {
        let raw = tempfile::tempfile().unwrap();
        let mut file = SnapshotIo::new(raw, None);
        file.write_all(b"abcdefghij").await.unwrap();
        file.seek(SeekFrom::Start(0)).await.unwrap();
        // Hold the actual file lock so the read is known to be pending when
        // its borrowing future is cancelled. No timer or scheduler race.
        let handle = file.handle.clone();
        let mut larger = [0; 8];
        let mut read = Box::pin(file.read(&mut larger));
        std::future::poll_fn(|cx| {
            let _held = handle.file.lock().unwrap();
            assert!(read.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(read);
        let mut smaller = [0; 2];
        file.read_exact(&mut smaller).await.unwrap();
        assert_eq!(&smaller, b"ab");
        assert_eq!(file.stream_position().await.unwrap(), 2);
        file.write_all(b"XY").await.unwrap();
        assert_eq!(file.seek(SeekFrom::Current(-1)).await.unwrap(), 3);
        file.read_exact(&mut smaller).await.unwrap();
        assert_eq!(&smaller, b"Ye");
        assert_eq!(file.seek(SeekFrom::End(-2)).await.unwrap(), 8);
        file.read_exact(&mut smaller).await.unwrap();
        assert_eq!(&smaller, b"ij");
        assert_eq!(file.read(&mut smaller).await.unwrap(), 0, "EOF completes");
        file.seek(SeekFrom::Start(0)).await.unwrap();
        let mut all = Vec::new();
        file.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"abXYefghij");
    }
}
