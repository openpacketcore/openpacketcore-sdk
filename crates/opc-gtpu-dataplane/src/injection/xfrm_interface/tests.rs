use super::*;

fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&u16::try_from(value.len() + 4).unwrap().to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

fn link(kind: &[u8], id: u32, metadata: bool) -> Vec<u8> {
    let mut data = attr(1, &3_u32.to_ne_bytes());
    data.extend(attr(2, &id.to_ne_bytes()));
    if metadata {
        data.extend(attr(3, &[]));
    }
    let mut info = attr(1, kind);
    info.extend(attr(2 | 0x8000, &data));
    let mut body = vec![0; 16];
    body[2..4].copy_from_slice(&0xfffe_u16.to_ne_bytes());
    body[4..8].copy_from_slice(&7_u32.to_ne_bytes());
    body.extend(attr(18 | 0x8000, &info));
    body
}

fn message(kind: u16, sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    bytes[..4].copy_from_slice(&u32::try_from(body.len() + 16).unwrap().to_ne_bytes());
    bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
    bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
    bytes.extend_from_slice(body);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

#[test]
fn identity_requires_xfrm_kind_nonzero_expected_id_and_local_fixed_metadata() {
    assert!(
        parse_identity(&link(b"xfrm\0", 19, false), 7, 19)
            == Ok(LinkIdentity {
                underlying_link: 3,
                if_id: 19
            })
    );
    for body in [link(b"dummy\0", 19, false), link(b"xfrm\0", 19, true)] {
        assert!(matches!(
            parse_identity(&body, 7, 19),
            Err(Error::UnsupportedInterface)
        ));
    }
    let mut cross_namespace = link(b"xfrm\0", 19, false);
    cross_namespace.extend(attr(37, &2_u32.to_ne_bytes()));
    assert!(matches!(
        parse_identity(&cross_namespace, 7, 19),
        Err(Error::UnsupportedInterface)
    ));
    for (index, id) in [(8, 19), (7, 0), (7, 20)] {
        assert!(matches!(
            parse_identity(&link(b"xfrm\0", id, false), index, 19),
            Err(Error::InterfaceIdentityMismatch)
        ));
    }
}

#[test]
fn notifications_refuse_identical_replacement_and_ignore_other_links() {
    let body = link(b"xfrm\0", 19, false);
    for kind in [RTM_DELLINK, RTM_NEWLINK] {
        assert!(matches!(
            parse_messages(&message(kind, 0, &body), true, 2, 7, 19),
            Err(Error::InterfaceIdentityMismatch)
        ));
        assert!(parse_messages(&message(kind, 0, &body), true, 2, 8, 19) == Ok(None));
    }
    assert!(
        parse_messages(&message(RTM_NEWLINK, 2, &body), false, 2, 7, 19)
            == Ok(Some(LinkIdentity {
                underlying_link: 3,
                if_id: 19
            }))
    );
}

#[test]
fn malformed_or_ambiguous_identity_never_authorizes_a_binding() {
    let body = link(b"xfrm\0", 19, false);
    let mut duplicate = body.clone();
    duplicate.extend_from_slice(&body[16..]);
    assert!(parse_identity(&duplicate, 7, 19).is_err());
    let reply = message(RTM_NEWLINK, 2, &body);
    for length in 0..reply.len() {
        // An empty datagram is not a successful receipt either.
        assert!(!matches!(
            parse_messages(&reply[..length], false, 2, 7, 19),
            Ok(Some(_))
        ));
    }
    assert!(parse_messages(&reply, false, 3, 7, 19).is_err());
    assert!(parse_messages(&message(NLMSG_OVERRUN, 2, &[]), false, 2, 7, 19).is_err());
    let mut duplicate_reply = reply.clone();
    duplicate_reply.extend_from_slice(&reply);
    assert!(parse_messages(&duplicate_reply, false, 2, 7, 19).is_err());
    let mut interrupted = reply;
    interrupted[6..8].copy_from_slice(&0x10_u16.to_ne_bytes());
    assert!(parse_messages(&interrupted, false, 2, 7, 19).is_err());
}

#[test]
fn kernel_errors_and_transport_diagnostics_remain_value_free() {
    for errno in [nix::libc::ENODEV, nix::libc::ENXIO] {
        let missing = message(NLMSG_ERROR, 2, &(-errno).to_ne_bytes());
        assert!(matches!(
            parse_messages(&missing, false, 2, 7, 19),
            Err(Error::InterfaceUnavailable)
        ));
    }
    assert_eq!(
        socket_error(io::Error::from(io::ErrorKind::NotFound)),
        Error::InterfaceUnavailable
    );
    assert_eq!(
        Error::InterfaceUnavailable.to_string(),
        "downlink injection interface unavailable"
    );
    assert_eq!(
        format!("{:?}", Error::InterfaceUnavailable),
        "InterfaceUnavailable"
    );
    assert!(std::error::Error::source(&Error::InterfaceUnavailable).is_none());
    let denied = message(NLMSG_ERROR, 2, &(-nix::libc::EPERM).to_ne_bytes());
    assert!(matches!(
        parse_messages(&denied, false, 2, 7, 19),
        Err(Error::Socket {
            kind: io::ErrorKind::PermissionDenied
        })
    ));
    let error = socket_error(io::Error::new(
        io::ErrorKind::InvalidData,
        "sensitive identity",
    ));
    assert_eq!(format!("{error:?}"), "Socket { kind: InvalidData }");
    assert!(!error.to_string().contains("sensitive"));
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(
        socket_error(io::Error::from(io::ErrorKind::Unsupported)),
        Error::UnsupportedPlatform
    );
}
