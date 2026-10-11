//! Flush and independently verify the namespace tables. This is deliberately
//! separate from the established single-object response parser: an ACK, one
//! multipart row, or an interrupted dump cannot prove an empty table.

use super::*;
use opc_linux_xfrm_sys::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, XFRM_MSG_FLUSHPOLICY, XFRM_MSG_FLUSHSA, XFRM_POLICY_TYPE_SUB,
};

const OPERATION: &str = "exclusive_namespace_reset_readback";

impl LinuxXfrmBackend {
    pub(crate) fn flush_namespace_policies(&self) -> Result<(), XfrmError> {
        self.flush_namespace_policies_contained(None)
    }

    pub(crate) fn flush_namespace_policies_contained(
        &self,
        contained: Option<&opc_linux_gtpu_sys::tc::ContainedScope>,
    ) -> Result<(), XfrmError> {
        for (policy_type, operation) in [
            (XFRM_POLICY_TYPE_MAIN, "reset_namespace_main_policies"),
            (XFRM_POLICY_TYPE_SUB, "reset_namespace_sub_policies"),
        ] {
            if let Some(contained) = contained {
                contained
                    .recheck()
                    .map_err(crate::local_scope::scope_error)?;
            }
            let mut body = sensitive_buffer_with_capacity(12);
            // struct xfrm_userpolicy_type has two holes: u8 type, padding,
            // u16 reserved1, u8 reserved2, tail padding (six bytes total).
            append_attr(&mut body, XFRMA_POLICY_TYPE, &[policy_type, 0, 0, 0, 0, 0])?;
            match self.transact(
                operation,
                XFRM_MSG_FLUSHPOLICY,
                NLM_F_REQUEST | NLM_F_ACK,
                body,
            ) {
                Ok(None) | Err(XfrmError::NotFound) => {}
                // CONFIG_XFRM_SUB_POLICY=n rejects SUB. MAIN must still work,
                // and the subsequent all-type dump must independently be empty.
                Err(error)
                    if policy_type == XFRM_POLICY_TYPE_SUB
                        && error.raw_os_error() == Some(LINUX_EINVAL) => {}
                Err(error) => return Err(error),
                Ok(Some(_)) => return Err(XfrmError::StateIndeterminate { operation }),
            }
        }
        Ok(())
    }

    pub(crate) fn flush_namespace_sas(&self) -> Result<(), XfrmError> {
        // A zero xfrm_usersa_flush.proto matches ALL protocols. The IPsec
        // wildcard 255 would match only ESP, AH, and IPComp.
        match self.transact(
            "reset_namespace_sas",
            XFRM_MSG_FLUSHSA,
            NLM_F_REQUEST | NLM_F_ACK,
            Zeroizing::new(vec![0]),
        ) {
            Ok(None) | Err(XfrmError::NotFound) => Ok(()),
            Err(error) => Err(error),
            Ok(Some(_)) => Err(XfrmError::StateIndeterminate {
                operation: "reset_namespace_sas",
            }),
        }
    }

    pub(crate) fn verify_namespace_empty(&self) -> Result<(), XfrmError> {
        for message_type in [XFRM_MSG_GETPOLICY, XFRM_MSG_GETSA] {
            self.ensure_namespace_binding()?;
            self.inner.transport.verify_empty(
                message_type,
                self.next_sequence(),
                self.inner.config,
            )?;
        }
        Ok(())
    }
}

pub(super) fn verify_empty(
    message_type: u16,
    sequence: u32,
    config: LinuxXfrmBackendConfig,
) -> Result<(), XfrmError> {
    verify_empty_profile(message_type, sequence, config, false, false)
}

pub(super) fn verify_empty_scoped(
    message_type: u16,
    sequence: u32,
    config: LinuxXfrmBackendConfig,
) -> Result<(), XfrmError> {
    verify_empty_profile(message_type, sequence, config, true, true)
}

pub(super) fn verify_empty_local(
    message_type: u16,
    sequence: u32,
    config: LinuxXfrmBackendConfig,
    include_socket_policies: bool,
) -> Result<(), XfrmError> {
    verify_empty_profile(
        message_type,
        sequence,
        config,
        include_socket_policies,
        true,
    )
}

fn verify_empty_profile(
    message_type: u16,
    sequence: u32,
    config: LinuxXfrmBackendConfig,
    include_socket_policies: bool,
    bounded: bool,
) -> Result<(), XfrmError> {
    let deadline = bounded.then(|| std::time::Instant::now() + std::time::Duration::from_secs(1));
    let socket = open_netlink_socket().map_err(|error| map_open_error(OPERATION, error))?;
    // The dump dispatch parses attributes at offset zero for SA and ignores
    // policy filters. No identity payload or family/protocol filter is sent.
    let request = encode_netlink_message(message_type, NLM_F_REQUEST | NLM_F_DUMP, sequence, &[])?;
    let sent = send_message(&socket, &request).map_err(|error| XfrmError::io(OPERATION, error))?;
    if sent != request.len() {
        return Err(XfrmError::Unavailable);
    }
    let mut buffer = Zeroizing::new(vec![0; config.receive_buffer_len]);
    for _ in 0..config.receive_attempts {
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(XfrmError::Unavailable);
        }
        match receive_message_outcome(&socket, &mut buffer) {
            Ok(ReceiveMessageOutcome::Complete { bytes_received: 0 }) => {}
            Ok(ReceiveMessageOutcome::Complete { bytes_received }) => {
                let datagram = buffer.get(..bytes_received).ok_or(XfrmError::Unavailable)?;
                if (if include_socket_policies {
                    empty_dump_datagram_scoped(datagram, message_type, sequence)
                } else {
                    empty_dump_datagram(datagram, message_type, sequence)
                })? {
                    return Ok(());
                }
                continue;
            }
            Ok(ReceiveMessageOutcome::RejectedNonKernel) => {}
            Ok(ReceiveMessageOutcome::ConsumedOversize { .. }) => {
                return Err(XfrmError::Unavailable)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(XfrmError::io(OPERATION, error)),
            Ok(_) => return Err(XfrmError::Unavailable),
        }
        if !config.retry_delay.is_zero() {
            std::thread::sleep(config.retry_delay);
        }
    }
    Err(XfrmError::Unavailable)
}

fn empty_dump_datagram(
    datagram: &[u8],
    request_type: u16,
    sequence: u32,
) -> Result<bool, XfrmError> {
    empty_dump_datagram_profile(datagram, request_type, sequence, false)
}

fn empty_dump_datagram_profile(
    datagram: &[u8],
    request_type: u16,
    sequence: u32,
    include_socket_policies: bool,
) -> Result<bool, XfrmError> {
    let mut offset = 0;
    let mut done = false;
    while offset < datagram.len() {
        let frame = &datagram[offset..];
        if done || frame.len() < NETLINK_HEADER_LEN {
            return Err(XfrmError::Unavailable);
        }
        let length = read_u32_ne(frame, 0)? as usize;
        if length < NETLINK_HEADER_LEN
            || length > frame.len()
            || read_u32_ne(frame, 8)? != sequence
            || read_u16_ne(frame, 6)? & NLM_F_DUMP_INTR != 0
        {
            return Err(XfrmError::Unavailable);
        }
        let payload = &frame[NETLINK_HEADER_LEN..length];
        match read_u16_ne(frame, 4)? {
            NLMSG_DONE => {
                if payload.len() < 4 || read_u32_ne(payload, 0)? != 0 {
                    return Err(XfrmError::Unavailable);
                }
                done = true;
            }
            NLMSG_ERROR => {
                parse_netlink_error(payload)?;
            }
            XFRM_MSG_NEWSA if request_type == XFRM_MSG_GETSA => {
                return Err(XfrmError::StateMismatch {
                    operation: OPERATION,
                });
            }
            XFRM_MSG_NEWPOLICY if request_type == XFRM_MSG_GETPOLICY => {
                if payload.len() < XFRM_USER_POLICY_INFO_LEN {
                    return Err(XfrmError::Unavailable);
                }
                // The kernel's policy walk also includes per-socket policies
                // at directions 3..=5, which flush deliberately leaves alone.
                match payload[160] {
                    0..=2 => {
                        return Err(XfrmError::StateMismatch {
                            operation: OPERATION,
                        })
                    }
                    3..=5 if !include_socket_policies => {}
                    _ => return Err(XfrmError::Unavailable),
                }
            }
            _ => return Err(XfrmError::Unavailable),
        }
        offset = offset
            .checked_add(align_to_netlink(length).ok_or(XfrmError::Unavailable)?)
            .ok_or(XfrmError::Unavailable)?;
        if offset > datagram.len() {
            return Err(XfrmError::Unavailable);
        }
    }
    Ok(done)
}

fn empty_dump_datagram_scoped(
    datagram: &[u8],
    request_type: u16,
    sequence: u32,
) -> Result<bool, XfrmError> {
    empty_dump_datagram_profile(datagram, request_type, sequence, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct FlushWire(Arc<Mutex<Vec<Vec<u8>>>>);

    impl LinuxXfrmTransport for FlushWire {
        fn transact(
            &self,
            _operation: &'static str,
            _class: NetlinkOperationClass,
            request: &[u8],
            _sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.0.lock().unwrap().push(request.to_vec());
            if request.len() == 28 && request[20] == 1 {
                return Err(XfrmError::io(
                    "netlink_ack",
                    io::Error::from_raw_os_error(LINUX_EINVAL),
                ));
            }
            Ok(None)
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::mock()
        }
    }

    #[test]
    fn flush_wire_uses_six_byte_policy_types_and_zero_protocol() {
        let wire = FlushWire::default();
        let requests = Arc::clone(&wire.0);
        let backend = LinuxXfrmBackend::with_transport(wire);
        backend.flush_namespace_policies().unwrap();
        backend.flush_namespace_sas().unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        for (index, kind) in [29_u16, 29, 28].into_iter().enumerate() {
            assert_eq!(&requests[index][4..6], &kind.to_ne_bytes());
            assert_eq!(&requests[index][6..8], &5_u16.to_ne_bytes());
        }
        // UAPI xfrm_userpolicy_type has size six, and the NLA including its
        // header is ten bytes plus alignment. Literal fixtures are deliberate.
        for (index, policy_type) in [0_u8, 1].into_iter().enumerate() {
            let mut expected = Vec::new();
            expected.extend_from_slice(&10_u16.to_ne_bytes());
            expected.extend_from_slice(&16_u16.to_ne_bytes());
            expected.extend_from_slice(&[policy_type, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(&requests[index][16..], expected);
        }
        assert_eq!(&requests[2][16..], &[0]);
    }

    fn frame(kind: u16, flags: u16, body: &[u8]) -> SensitiveBuffer {
        encode_netlink_message(kind, flags, 1, body).unwrap()
    }

    #[test]
    fn readback_requires_complete_successful_dump_and_rejects_rows() {
        let done = frame(NLMSG_DONE, 2, &[0; 4]);
        for request in [XFRM_MSG_GETSA, XFRM_MSG_GETPOLICY] {
            assert!(empty_dump_datagram(&done, request, 1).unwrap());
            assert!(empty_dump_datagram(&done, request, 2).is_err());
            assert!(
                empty_dump_datagram(&frame(NLMSG_DONE, NLM_F_DUMP_INTR, &[0; 4]), request, 1)
                    .is_err()
            );
            assert!(empty_dump_datagram(
                &frame(NLMSG_DONE, 2, &(-5_i32).to_ne_bytes()),
                request,
                1
            )
            .is_err());
            assert!(empty_dump_datagram(&frame(NLMSG_DONE, 2, &[]), request, 1).is_err());
            assert!(!empty_dump_datagram(&frame(NLMSG_ERROR, 0, &[0; 4]), request, 1).unwrap());
            let mut trailing = done.to_vec();
            trailing.extend_from_slice(&done);
            assert!(empty_dump_datagram(&trailing, request, 1).is_err());
        }
        assert!(empty_dump_datagram(
            &frame(XFRM_MSG_NEWSA, 2, &[0; XFRM_USER_SA_INFO_LEN]),
            XFRM_MSG_GETSA,
            1
        )
        .is_err());
        let mut policy = vec![0; XFRM_USER_POLICY_INFO_LEN];
        policy[161] = XFRM_POLICY_BLOCK;
        assert!(empty_dump_datagram(
            &frame(XFRM_MSG_NEWPOLICY, 2, &policy),
            XFRM_MSG_GETPOLICY,
            1
        )
        .is_err());
        policy[160] = 3;
        let mut socket_policy_and_done = frame(XFRM_MSG_NEWPOLICY, 2, &policy).to_vec();
        assert!(!empty_dump_datagram(&socket_policy_and_done, XFRM_MSG_GETPOLICY, 1).unwrap());
        socket_policy_and_done.extend_from_slice(&done);
        assert!(empty_dump_datagram(&socket_policy_and_done, XFRM_MSG_GETPOLICY, 1).unwrap());
    }

    #[test]
    fn scoped_profile_refuses_every_per_socket_policy_direction() {
        for direction in 3..=5 {
            let mut policy = vec![0; XFRM_USER_POLICY_INFO_LEN];
            policy[160] = direction;
            policy[161] = XFRM_POLICY_BLOCK;
            let mut reply = frame(XFRM_MSG_NEWPOLICY, 2, &policy).to_vec();
            reply.extend_from_slice(&frame(NLMSG_DONE, 2, &[0; 4]));
            assert!(
                empty_dump_datagram_scoped(&reply, XFRM_MSG_GETPOLICY, 1).is_err(),
                "a scoped producer cannot admit per-socket policy direction {direction}"
            );
            assert!(
                empty_dump_datagram(&reply, XFRM_MSG_GETPOLICY, 1).unwrap(),
                "the existing namespace-reset companion contract remains distinct"
            );
        }
    }
}
