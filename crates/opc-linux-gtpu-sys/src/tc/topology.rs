#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Topology {
    pub(super) ifindex: u32,
    pub(super) clsact: bool,
    pub(super) shared: bool,
    pub(super) hardware: bool,
    pub(super) tcx_count: u32,
    pub(super) xdp_absent: bool,
}

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InterfaceIdentity {
    pub(super) ifindex: u32,
    pub(super) kind: u16,
    pub(super) configuration: Vec<(u16, Vec<u8>)>,
}

use wire::{attr, attributes, c_string, invalid, u16_at, u32_at, word};

pub(super) fn parse_link(bytes: &[u8], ifindex: u32) -> io::Result<(InterfaceIdentity, bool)> {
    if bytes.len() < 32
        || u16_at(bytes, 4)? != crate::RTM_NEWLINK
        || bytes[16] != 0
        || bytes[17] != 0
        || u32_at(bytes, 20)? != ifindex
    {
        return Err(invalid());
    }
    let attrs = attributes(&bytes[32..])?;
    c_string(attr(&attrs, 3).ok_or_else(invalid)?, 15)?;
    let kind = u16_at(bytes, 18)?;
    let configuration = attrs
        .iter()
        .filter(|(key, _)| matches!(key, 1 | 3 | 5 | 20 | 37 | 54))
        .map(|(key, value)| (*key, value.to_vec()))
        .collect();
    let mut xdp_absent = false;
    if let Some(xdp) = attr(&attrs, 43) {
        let xdp = attributes(xdp)?;
        xdp_absent = attr(&xdp, 2) == Some(&[0]) && xdp.iter().all(|(key, _)| matches!(key, 2..=7));
        for (key, data) in &xdp {
            if matches!(key, 3..=7) && word(data)? != 0 {
                xdp_absent = false;
            }
        }
    }
    Ok((
        InterfaceIdentity {
            ifindex,
            kind,
            configuration,
        },
        xdp_absent,
    ))
}

pub(super) fn parse_qdisc(bytes: &[u8], ifindex: u32) -> io::Result<(bool, bool, bool)> {
    if bytes.len() < 36
        || u16_at(bytes, 4)? != 36
        || bytes[16..20] != [0; 4]
        || u32_at(bytes, 20)? != ifindex
    {
        return Err(invalid());
    }
    let attrs = attributes(&bytes[36..])?;
    let kind = c_string(attr(&attrs, 1).ok_or_else(invalid)?, 16)?;
    let clsact = kind == b"clsact";
    let handle = u32_at(bytes, 24)?;
    let parent = u32_at(bytes, 28)?;
    // tcm_info is the qdisc's runtime reference count, not classifier info.
    if clsact && (handle != 0xffff0000 || parent != 0xfffffff1) {
        return Err(invalid());
    }
    // A legacy ingress qdisc occupies the same kernel parent and cannot be
    // assumed compatible with clsact. Never replace it as a side effect.
    if !clsact && (handle == 0xffff0000 || parent == 0xfffffff1) {
        return Err(invalid());
    }
    let shared = attr(&attrs, 13).map(word).transpose()?.unwrap_or(0) != 0
        || attr(&attrs, 14).map(word).transpose()?.unwrap_or(0) != 0;
    let hardware = match attr(&attrs, 12) {
        None | Some([0]) => false,
        Some([1]) => true,
        Some(_) => return Err(invalid()),
    };
    if clsact
        && attrs
            .iter()
            .any(|(key, _)| !matches!(key, 1..=4 | 7 | 9 | 12..=14))
    {
        return Err(invalid());
    }
    if clsact && attr(&attrs, 2).is_some_and(|options| !options.is_empty()) {
        return Err(invalid());
    }
    Ok((clsact, shared, hardware))
}

fn request(
    client: &mut TcClient,
    message_type: u16,
    flags: u16,
    body: &[u8],
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::from(((body.len() + 16) as u32).to_ne_bytes());
    bytes.extend(message_type.to_ne_bytes());
    bytes.extend((crate::NLM_F_REQUEST | flags).to_ne_bytes());
    bytes.extend(client.next_sequence()?.to_ne_bytes());
    bytes.extend(client.transport()?.port_id().to_ne_bytes());
    bytes.extend(body);
    Ok(bytes)
}

pub(super) fn inspect_link(
    client: &mut TcClient,
    ifindex: u32,
) -> io::Result<(InterfaceIdentity, bool)> {
    client.exchange(|client| inspect_link_inner(client, ifindex))
}

fn inspect_link_inner(
    client: &mut TcClient,
    ifindex: u32,
) -> io::Result<(InterfaceIdentity, bool)> {
    let mut body = vec![0; 16];
    body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    let request = request(client, crate::RTM_GETLINK, crate::NLM_F_ACK, &body)?;
    let deadline = client.exchange_deadline()?;
    client.transport()?.send(&request)?;
    let mut identity = None;
    let mut acknowledged = false;
    let mut buffer = vec![0; 65_536];
    while !acknowledged {
        let length = client.transport()?.receive(&mut buffer, deadline)?;
        for frame in wire::frames(
            &buffer[..length],
            u32_at(&request, 8)?,
            u32_at(&request, 12)?,
        )? {
            if acknowledged {
                return Err(invalid());
            }
            match u16_at(frame, 4)? {
                crate::RTM_NEWLINK if identity.is_none() && u16_at(frame, 6)? == 0 => {
                    identity = Some(parse_link(frame, ifindex)?)
                }
                crate::NLMSG_ERROR => {
                    wire::ack(frame, &request)?;
                    acknowledged = true;
                }
                _ => return Err(invalid()),
            }
        }
    }
    identity.ok_or_else(invalid)
}

pub(super) fn inspect_qdisc(client: &mut TcClient, ifindex: u32) -> io::Result<(bool, bool, bool)> {
    client.exchange(|client| inspect_qdisc_inner(client, ifindex))
}

fn inspect_qdisc_inner(client: &mut TcClient, ifindex: u32) -> io::Result<(bool, bool, bool)> {
    let mut body = vec![0; 20];
    body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    let request = request(client, 38, crate::NLM_F_DUMP, &body)?;
    let deadline = client.exchange_deadline()?;
    client.transport()?.send(&request)?;
    let mut done = false;
    let mut result = (false, false, false);
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0_usize;
    let mut buffer = vec![0; 65_536];
    while !done {
        let length = client.transport()?.receive(&mut buffer, deadline)?;
        total += length;
        if total > 4 * 1024 * 1024 {
            return Err(invalid());
        }
        for frame in wire::frames(
            &buffer[..length],
            u32_at(&request, 8)?,
            u32_at(&request, 12)?,
        )? {
            if done || u16_at(frame, 6)? != crate::NLM_F_MULTI {
                return Err(invalid());
            }
            match u16_at(frame, 4)? {
                36 => {
                    // RTM_GETQDISC dumps are namespace-wide on Linux even
                    // when tcm_ifindex names one device. Ownership and qdisc
                    // compatibility checks apply only to the covered device.
                    let observed_ifindex = u32_at(frame, 20)?;
                    if observed_ifindex != ifindex {
                        continue;
                    }
                    let (clsact, shared, hardware) = parse_qdisc(frame, ifindex)?;
                    if seen.len() >= 4096 || !seen.insert((u32_at(frame, 24)?, u32_at(frame, 28)?))
                    {
                        return Err(invalid());
                    }
                    if result.0 && clsact {
                        return Err(invalid());
                    }
                    result.0 |= clsact;
                    result.1 |= shared;
                    result.2 |= hardware;
                }
                crate::NLMSG_DONE if frame.len() == 20 && u32_at(frame, 16)? == 0 => done = true,
                _ => return Err(invalid()),
            }
        }
    }
    Ok(result)
}

pub(super) fn ensure_clsact(client: &mut TcClient, ifindex: u32) -> io::Result<()> {
    client.exchange(|client| ensure_clsact_inner(client, ifindex))
}

fn ensure_clsact_inner(client: &mut TcClient, ifindex: u32) -> io::Result<()> {
    let state = inspect_qdisc(client, ifindex)?;
    if state.1 || state.2 {
        return Err(invalid());
    }
    if state.0 {
        return Ok(());
    }
    let mut body = vec![0; 20];
    body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    body[8..12].copy_from_slice(&0xffff0000_u32.to_ne_bytes());
    body[12..16].copy_from_slice(&0xfffffff1_u32.to_ne_bytes());
    body.extend(wire::encode_attributes(&[(1, b"clsact\0".to_vec())])?);
    let request = request(
        client,
        36,
        crate::NLM_F_ACK | crate::NLM_F_CREATE | crate::NLM_F_EXCL,
        &body,
    )?;
    let deadline = client.exchange_deadline()?;
    client.transport()?.send(&request)?;
    let mut buffer = vec![0; 65_536];
    let length = client.transport()?.receive(&mut buffer, deadline)?;
    wire::ack(&buffer[..length], &request)?;
    if inspect_qdisc(client, ifindex)? != (true, false, false) {
        return Err(invalid());
    }
    Ok(())
}
