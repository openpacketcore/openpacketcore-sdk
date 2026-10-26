//! Keep descriptor borrows inside one poll so terminal close can deregister it.

use std::future::poll_fn;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::{Mutex, MutexGuard};
use std::task::Poll;

use opc_tokio_fd_sys::AsyncOwnedFd;
use tokio::io::Interest;

#[derive(Debug)]
pub(super) struct SocketDescriptor {
    registration: Mutex<Option<AsyncOwnedFd>>,
    closed: tokio::sync::watch::Sender<bool>,
    read_gate: tokio::sync::Mutex<()>,
    write_gate: tokio::sync::Mutex<()>,
}

impl SocketDescriptor {
    pub(super) fn new(registration: AsyncOwnedFd) -> Self {
        Self {
            registration: Mutex::new(Some(registration)),
            closed: tokio::sync::watch::Sender::new(false),
            read_gate: tokio::sync::Mutex::new(()),
            write_gate: tokio::sync::Mutex::new(()),
        }
    }

    fn registration(&self) -> MutexGuard<'_, Option<AsyncOwnedFd>> {
        self.registration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn with_fd<T>(
        &self,
        operation: impl FnOnce(BorrowedFd<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        let registration = self.registration();
        let fd = registration.as_ref().ok_or_else(closed_error)?;
        operation(fd.get_ref().as_fd())
    }

    // Keep readiness errors outside syscall errors for the callers' close policy.
    pub(super) async fn io<T>(
        &self,
        interest: Interest,
        mut operation: impl FnMut(BorrowedFd<'_>) -> io::Result<T>,
    ) -> io::Result<io::Result<T>> {
        let mut closed = self.closed.subscribe();
        let ready = async {
            // poll_*_ready retains one waker per direction, including accept.
            let _gate = if interest.is_readable() {
                self.read_gate.lock().await
            } else {
                self.write_gate.lock().await
            };
            poll_fn(|cx| loop {
                let registration = self.registration();
                let Some(fd) = registration.as_ref() else {
                    return Poll::Ready(Err(closed_error()));
                };
                let ready = if interest.is_readable() {
                    fd.poll_read_ready(cx)
                } else {
                    fd.poll_write_ready(cx)
                };
                let mut ready = match ready {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(ready)) => ready,
                };
                match ready.try_io(|fd| operation(fd.get_ref().as_fd())) {
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(result) => return Poll::Ready(Ok(result)),
                    Err(_would_block) => continue,
                }
            })
            .await
        };
        tokio::select! {
            biased;
            _ = closed.wait_for(|closed| *closed) => Err(closed_error()),
            result = ready => result,
        }
    }

    pub(super) fn abort_on_wire(&self) -> io::Result<()> {
        let result = {
            let mut registration = self.registration();
            let Some(fd) = registration.take() else {
                return Ok(());
            };
            let result = opc_libsctp_sys::set_abort_on_close(fd.get_ref().as_fd());
            // AsyncOwnedFd deregisters before dropping its owned descriptor.
            drop(fd);
            result
        };
        self.closed.send_replace(true);
        result
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "SCTP descriptor is closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn pair() -> (SocketDescriptor, UnixStream) {
        let (local, peer) = UnixStream::pair().expect("socket pair");
        local.set_nonblocking(true).expect("nonblocking local");
        peer.set_nonblocking(true).expect("nonblocking peer");
        (
            SocketDescriptor::new(AsyncOwnedFd::new(local.into()).expect("registration")),
            peer,
        )
    }

    fn read_byte(fd: BorrowedFd<'_>) -> io::Result<u8> {
        let mut byte = [0];
        if opc_libsctp_sys::recv_msg(fd, &mut byte)?.bytes != 1 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok(byte[0])
    }

    #[tokio::test]
    async fn abort_drops_registration_before_pending_futures_or_handles() {
        let (descriptor, mut peer) = pair();
        let mut reading = Box::pin(descriptor.io(Interest::READABLE, read_byte));
        let mut queued = Box::pin(descriptor.io(Interest::READABLE, read_byte));
        let mut writing = Box::pin(descriptor.io(Interest::WRITABLE, |_| {
            Err::<(), _>(io::Error::from(io::ErrorKind::WouldBlock))
        }));
        poll_fn(|cx| {
            assert!(reading.as_mut().poll(cx).is_pending());
            assert!(queued.as_mut().poll(cx).is_pending());
            assert!(writing.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        descriptor.abort_on_wire().expect("abortive close");
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).expect("peer EOF before repoll"), 0);
        // The second read must wake even while the first still owns read_gate.
        for result in [
            tokio::time::timeout(Duration::from_secs(1), queued)
                .await
                .expect("queued read woke"),
            tokio::time::timeout(Duration::from_secs(1), reading)
                .await
                .expect("read woke"),
        ] {
            assert_eq!(
                result.expect_err("closed readiness").kind(),
                io::ErrorKind::NotConnected
            );
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), writing)
                .await
                .expect("write woke")
                .expect_err("closed write readiness")
                .kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            descriptor
                .with_fd(|_| Ok(()))
                .expect_err("no later descriptor access")
                .kind(),
            io::ErrorKind::NotConnected
        );
        descriptor.abort_on_wire().expect("idempotent close");
    }

    #[tokio::test]
    async fn concurrent_readers_serialize_without_lost_wakeups() {
        let (descriptor, mut peer) = pair();
        let mut first = Box::pin(descriptor.io(Interest::READABLE, read_byte));
        let mut second = Box::pin(descriptor.io(Interest::READABLE, read_byte));
        poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            assert!(second.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        peer.write_all(b"xy").expect("two queued bytes");
        let (first, second) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(first, second)
        })
        .await
        .expect("both readers complete");
        assert_eq!(first.expect("first ready").expect("first read"), b'x');
        assert_eq!(second.expect("second ready").expect("second read"), b'y');
    }

    #[tokio::test]
    async fn cancelled_reader_releases_gate_and_syscall_errors_remain_distinct() {
        let (descriptor, mut peer) = pair();
        let mut cancelled = Box::pin(descriptor.io(Interest::READABLE, read_byte));
        poll_fn(|cx| {
            assert!(cancelled.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(cancelled);
        peer.write_all(b"xy").expect("readable bytes");
        let mut interrupted = false;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            descriptor.io(Interest::READABLE, |fd| {
                if !interrupted {
                    interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                read_byte(fd)
            }),
        )
        .await
        .expect("replacement read completed")
        .expect("ready")
        .expect("read");
        assert_eq!(result, b'x');
        let error = descriptor
            .io(Interest::READABLE, |_| {
                Err::<(), _>(io::Error::from(io::ErrorKind::PermissionDenied))
            })
            .await
            .expect("ready")
            .expect_err("syscall error");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            descriptor
                .io(Interest::READABLE, read_byte)
                .await
                .expect("ready")
                .expect("read"),
            b'y'
        );
    }
}
