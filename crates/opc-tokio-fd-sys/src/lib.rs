//! Owned Unix descriptor registration for Tokio's reactor.
//!
//! The registration consumes an `OwnedFd` and exposes only shared access until
//! Tokio deregisters and closes it. This preserves the lifetime required by
//! Tokio's registration API (RUSTSEC-2026-0386).

#![cfg(unix)]
#![deny(missing_docs)]

use std::io;
use std::ops::Deref;
use std::os::fd::OwnedFd;
use tokio::io::{unix::AsyncFd, Interest};

/// A descriptor whose ownership cannot change while registered with Tokio.
///
/// The descriptor must support the reactor and use nonblocking I/O. Shared
/// readiness operations are available through [`Deref`]; mutable access and
/// extraction of the inner registration are deliberately unavailable.
///
/// Raw descriptor integers cannot establish ownership:
/// ```compile_fail,E0308
/// use opc_tokio_fd_sys::AsyncOwnedFd;
/// let _ = AsyncOwnedFd::new(123);
/// ```
///
/// Safe callers cannot replace the registered descriptor:
/// ```compile_fail,E0596
/// use opc_tokio_fd_sys::AsyncOwnedFd;
/// use std::os::fd::OwnedFd;
/// fn replace(mut registered: AsyncOwnedFd, replacement: OwnedFd) {
///     *registered.get_mut() = replacement;
/// }
/// ```
///
/// Safe callers cannot take ownership of the inner registration:
/// ```compile_fail,E0507
/// use opc_tokio_fd_sys::AsyncOwnedFd;
/// fn extract(registered: AsyncOwnedFd) {
///     let _ = registered.into_inner();
/// }
/// ```
#[derive(Debug)]
pub struct AsyncOwnedFd(AsyncFd<OwnedFd>);

impl AsyncOwnedFd {
    /// Register an owned nonblocking descriptor for readable/writable readiness.
    ///
    /// Returns the reactor's registration error. Like Tokio's registration API,
    /// this requires a current Tokio runtime with I/O enabled.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        Self::with_interest(fd, Interest::READABLE | Interest::WRITABLE)
    }

    /// Register an owned nonblocking descriptor for the selected readiness.
    ///
    /// Returns the reactor's registration error and closes the descriptor on
    /// failure. This requires a current Tokio runtime with I/O enabled.
    pub fn with_interest(fd: OwnedFd, interest: Interest) -> io::Result<Self> {
        // SAFETY: OwnedFd keeps this descriptor valid; no mutable/owning access
        // to the inner registration is exposed before Tokio deregisters it.
        unsafe { AsyncFd::register_with_interest(fd, interest) }
            .map(Self)
            .map_err(Into::into)
    }
}

impl Deref for AsyncOwnedFd {
    type Target = AsyncFd<OwnedFd>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[tokio::test]
    async fn readiness_retains_descriptor_until_registration_is_dropped() {
        let (reader, mut peer) = UnixStream::pair().expect("socket pair");
        reader.set_nonblocking(true).expect("nonblocking reader");
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("bounded peer read");
        let registered = AsyncOwnedFd::with_interest(reader.into(), Interest::READABLE)
            .expect("register reader");
        peer.write_all(b"x").expect("peer write");
        let mut byte = [0];
        let count = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let mut ready = registered.readable().await.expect("read readiness");
                match ready
                    .try_io(|fd| rustix::io::read(fd.get_ref(), &mut byte).map_err(io::Error::from))
                {
                    Ok(result) => break result.expect("read byte"),
                    Err(_) => continue,
                }
            }
        })
        .await
        .expect("bounded readiness");
        assert_eq!(count, 1);
        assert_eq!(byte, *b"x");
        drop(registered);
        assert_eq!(peer.read(&mut byte).expect("peer EOF"), 0);
    }
}
