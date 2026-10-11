//! One-second exchanges for the explicitly scoped producer only.

use super::*;
use std::time::Instant;

#[derive(Debug)]
pub(super) struct ScopedNetlinkTransport;
fn bounded_receive(
    deadline: Instant,
    buffer: &mut [u8],
    receive: impl FnOnce(&mut [u8]) -> io::Result<ReceiveMessageOutcome>,
) -> io::Result<ReceiveMessageOutcome> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "scoped XFRM exchange deadline",
        ));
    }
    receive(buffer)
}
struct Session {
    inner: NetlinkXfrmSession,
    deadline: Instant,
}
impl LinuxXfrmSession for Session {
    fn send(&mut self, request: &[u8]) -> Result<(), XfrmError> {
        self.deadline = Instant::now() + Duration::from_secs(1);
        self.inner.send(request)
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveMessageOutcome> {
        bounded_receive(self.deadline, buffer, |buffer| self.inner.receive(buffer))
    }
}
impl LinuxXfrmTransport for ScopedNetlinkTransport {
    fn transact(
        &self,
        operation: &'static str,
        class: NetlinkOperationClass,
        request: &[u8],
        sequence: u32,
        config: LinuxXfrmBackendConfig,
    ) -> Result<Option<SensitiveBuffer>, XfrmError> {
        let deadline = Instant::now() + Duration::from_secs(1);
        let socket = open_netlink_socket().map_err(|error| map_open_error(operation, error))?;
        let sent =
            send_message(&socket, request).map_err(|error| XfrmError::io("netlink_send", error))?;
        if sent != request.len() {
            return Err(XfrmError::StateIndeterminate { operation });
        }
        receive_netlink_response(operation, class, sequence, config, |buffer| {
            bounded_receive(deadline, buffer, |buffer| {
                receive_message_outcome(&socket, buffer)
            })
        })
    }
    fn open_session(
        &self,
        operation: &'static str,
    ) -> Result<Box<dyn LinuxXfrmSession>, XfrmError> {
        let socket = open_netlink_socket().map_err(|error| map_open_error(operation, error))?;
        Ok(Box::new(Session {
            inner: NetlinkXfrmSession { socket },
            deadline: Instant::now() + Duration::from_secs(1),
        }))
    }
    fn verify_empty(
        &self,
        message: u16,
        sequence: u32,
        config: LinuxXfrmBackendConfig,
    ) -> Result<(), XfrmError> {
        namespace_reset::verify_empty_local(message, sequence, config, false)
    }
    fn verify_empty_scoped(
        &self,
        message: u16,
        sequence: u32,
        config: LinuxXfrmBackendConfig,
    ) -> Result<(), XfrmError> {
        namespace_reset::verify_empty_local(message, sequence, config, true)
    }
    fn probe(&self, config: LinuxXfrmBackendConfig) -> XfrmProbe {
        NetlinkXfrmTransport.probe(config)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_expired_exchange_does_not_consume_another_datagram() {
        let mut called = false;
        let result = bounded_receive(Instant::now() - Duration::from_secs(1), &mut [0; 8], |_| {
            called = true;
            Ok(ReceiveMessageOutcome::Complete { bytes_received: 0 })
        });
        assert!(!called);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
