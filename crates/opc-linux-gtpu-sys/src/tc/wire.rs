use super::*;
use std::collections::BTreeSet;

const CHAIN: u16 = 11;
const MAX_ENTRIES: usize = 4096;
const MAX_DUMP_BYTES: usize = 4 * 1024 * 1024;

pub(super) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "tc_inventory")
}
pub(super) fn conflict() -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, "tc_occupant_changed")
}

pub(super) fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
pub(super) fn u16_at(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}

type Attributes<'a> = Vec<(u16, &'a [u8])>;

pub(super) fn attributes(mut bytes: &[u8]) -> io::Result<Attributes<'_>> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    while !bytes.is_empty() {
        let length = usize::from(u16_at(bytes, 0)?);
        let kind = u16_at(bytes, 2)?;
        // Nested is descriptive, but network-order attributes have different
        // semantics and cannot silently alias native-order ownership fields.
        if kind & 0x4000 != 0 || length < 4 || length > bytes.len() || !seen.insert(kind & 0x3fff) {
            return Err(invalid());
        }
        let aligned = crate::align_to_netlink(length).ok_or_else(invalid)?;
        if bytes
            .get(length..aligned)
            .ok_or_else(invalid)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(invalid());
        }
        result.push((kind & 0x3fff, &bytes[4..length]));
        if result.len() > 256 {
            return Err(invalid());
        }
        bytes = bytes.get(aligned..).ok_or_else(invalid)?;
    }
    result.sort_unstable_by_key(|(kind, _)| *kind);
    Ok(result)
}

pub(super) fn attr<'a>(attrs: &Attributes<'a>, key: u16) -> Option<&'a [u8]> {
    attrs
        .iter()
        .find_map(|(kind, bytes)| (*kind == key).then_some(*bytes))
}

pub(super) fn word(bytes: &[u8]) -> io::Result<u32> {
    if bytes.len() != 4 {
        return Err(invalid());
    }
    u32_at(bytes, 0)
}

pub(super) fn c_string(bytes: &[u8], limit: usize) -> io::Result<&[u8]> {
    let value = bytes.strip_suffix(&[0]).ok_or_else(invalid)?;
    if value.is_empty() || value.len() > limit || value.contains(&0) {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn owned(attrs: &Attributes<'_>) -> Vec<(u16, Vec<u8>)> {
    attrs
        .iter()
        .map(|(kind, value)| (*kind, value.to_vec()))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) slot: TcSlot,
    pub(super) kind: Vec<u8>,
    // Counters are excluded, but every unrecognized configuration attribute
    // stays in the comparison; unknown configuration cannot prove SDK shape.
    configuration: Vec<(u16, Vec<u8>)>,
    pub(super) bpf: Option<TcBpfIdentity>,
    pub(super) gact: Option<TcGactIdentity>,
}

impl Entry {
    pub(super) fn known_summary(&self) -> bool {
        self.slot.handle == 0
            && matches!(self.kind.as_slice(), b"bpf" | b"matchall")
            && self
                .configuration
                .iter()
                .all(|(key, _)| matches!(key, 1 | 11))
    }
}

fn bpf_identity(attrs: &Attributes<'_>) -> io::Result<Option<TcBpfIdentity>> {
    if attrs.iter().any(|(key, _)| !matches!(key, 7..=11)) {
        return Ok(None);
    }
    let Some(id) = attr(attrs, 11) else {
        return Ok(None);
    };
    let Some(name) = attr(attrs, 7) else {
        return Ok(None);
    };
    let Some(tag) = attr(attrs, 10) else {
        return Ok(None);
    };
    let Some(flags) = attr(attrs, 8) else {
        return Ok(None);
    };
    let program_id = word(id)?;
    let name = c_string(name, 128)?.to_vec();
    let tag = tag.try_into().map_err(|_| invalid())?;
    let classifier_flags = attr(attrs, 9).map(word).transpose()?.unwrap_or(0);
    if program_id == 0 || word(flags)? != 1 {
        return Ok(None);
    }
    Ok(Some(TcBpfIdentity {
        program_id,
        name,
        tag,
        classifier_flags,
    }))
}

fn gact_identity(options: &Attributes<'_>) -> io::Result<Option<TcGactIdentity>> {
    if options.iter().any(|(key, _)| !matches!(key, 2..=5)) {
        return Ok(None);
    }
    let Some(flags) = attr(options, 3) else {
        return Ok(None);
    };
    if !matches!(word(flags)?, 1 | 9) {
        return Ok(None);
    }
    if let Some(counter) = attr(options, 4) {
        if counter.len() != 8 {
            return Err(invalid());
        }
    }
    if attr(options, 5).is_some_and(|pad| !pad.is_empty()) {
        return Err(invalid());
    }
    let Some(actions) = attr(options, 2) else {
        return Ok(None);
    };
    let actions = attributes(actions)?;
    if actions.len() != 1 || actions[0].0 != 1 {
        return Ok(None);
    }
    let action = attributes(actions[0].1)?;
    if action
        .iter()
        .any(|(key, _)| !matches!(key, 1 | 2 | 4 | 5 | 6 | 7 | 10))
    {
        return Ok(None);
    }
    if attr(&action, 1) != Some(b"gact\0".as_slice()) {
        return Ok(None);
    }
    if let Some(stats) = attr(&action, 4) {
        attributes(stats)?;
    }
    if attr(&action, 5).is_some_and(|pad| !pad.is_empty()) {
        return Err(invalid());
    }
    // A bitfield32 contains value and selector, not a plain u32.
    let flags = [2_u32.to_ne_bytes(), 2_u32.to_ne_bytes()].concat();
    if attr(&action, 7) != Some(flags.as_slice())
        || attr(&action, 10).map(word).transpose()? != Some(0)
    {
        return Ok(None);
    }
    let Some(cookie) = attr(&action, 6) else {
        return Ok(None);
    };
    let Ok(cookie) = cookie.try_into() else {
        return Ok(None);
    };
    let Some(parameters) = attr(&action, 2) else {
        return Ok(None);
    };
    let parameters = attributes(parameters)?;
    if parameters.iter().any(|(key, _)| !matches!(key, 1 | 2 | 4)) {
        return Ok(None);
    }
    if let Some(time) = attr(&parameters, 1) {
        if time.len() != 32 {
            return Err(invalid());
        }
    }
    if attr(&parameters, 4).is_some_and(|pad| !pad.is_empty()) {
        return Err(invalid());
    }
    let Some(parameters) = attr(&parameters, 2) else {
        return Ok(None);
    };
    if parameters.len() != 20 {
        return Err(invalid());
    }
    let action_index = u32_at(parameters, 0)?;
    if action_index == 0
        || u32_at(parameters, 4)? != 0
        || u32_at(parameters, 12)? == 0
        || u32_at(parameters, 16)? != 1
    {
        return Ok(None);
    }
    let verdict = match u32_at(parameters, 8)? {
        0 => TcVerdict::Pass,
        2 => TcVerdict::Drop,
        _ => return Ok(None),
    };
    Ok(Some(TcGactIdentity {
        cookie,
        verdict,
        action_index,
    }))
}

fn gact_options(
    index: u32,
    references: u32,
    bindings: u32,
    cookie: [u8; 16],
    verdict: TcVerdict,
    flags: u32,
) -> io::Result<Vec<u8>> {
    let action = match verdict {
        TcVerdict::Pass => 0_u32,
        TcVerdict::Drop => 2_u32,
    };
    let parameters = [index, 0, action, references, bindings]
        .into_iter()
        .flat_map(u32::to_ne_bytes)
        .collect();
    let action = encode_attributes(&[
        (1, b"gact\0".to_vec()),
        (2, encode_attributes(&[(2, parameters)])?),
        (6, cookie.to_vec()),
        (7, [2_u32.to_ne_bytes(), 2_u32.to_ne_bytes()].concat()),
    ])?;
    encode_attributes(&[
        (2, encode_attributes(&[(1, action)])?),
        (3, flags.to_ne_bytes().to_vec()),
    ])
}

fn entry(bytes: &[u8], ifindex: u32, hook: TcHook) -> io::Result<Entry> {
    if bytes.len() < 36
        || bytes[16..20] != [0; 4]
        || u32_at(bytes, 20)? != ifindex
        || u32_at(bytes, 28)? != hook.parent()
    {
        return Err(invalid());
    }
    let info = u32_at(bytes, 32)?;
    let handle = u32_at(bytes, 24)?;
    let mut attrs = attributes(&bytes[36..])?;
    let kind = c_string(attr(&attrs, 1).ok_or_else(invalid)?, 16)?.to_vec();
    let chain = attr(&attrs, CHAIN).map(word).transpose()?.unwrap_or(0);
    let mut slot = TcSlot::new(
        ifindex,
        hook,
        chain,
        u16::from_be(info as u16),
        (info >> 16) as u16,
        handle.max(1),
    )
    .map_err(|_| invalid())?;
    slot.handle = handle;
    if handle == 0 && attr(&attrs, 2).is_some() {
        return Err(invalid());
    }
    // Traffic counters do not distinguish installed objects. Unknown fields
    // do; preserve them and do not promote them to a recognized BPF identity.
    if let Some(stats) = attr(&attrs, 7) {
        attributes(stats)?;
    }
    attrs.retain(|(key, _)| !matches!(key, 3 | 4 | 7 | 9));
    let mut configuration = owned(&attrs);
    let mut bpf = None;
    let mut gact = None;
    if handle != 0 && kind == b"bpf" {
        let options = attributes(attr(&attrs, 2).ok_or_else(invalid)?)?;
        if attrs.iter().all(|(key, _)| matches!(key, 1 | 2 | 11)) {
            bpf = bpf_identity(&options)?;
        }
        // Canonical attribute order is independent of kernel dump order.
        let canonical = encode_attributes(&owned(&options))?;
        configuration
            .iter_mut()
            .find(|(key, _)| *key == 2)
            .ok_or_else(invalid)?
            .1 = canonical;
    }
    if handle != 0 && kind == b"matchall" {
        let options = attributes(attr(&attrs, 2).ok_or_else(invalid)?)?;
        if attrs.iter().all(|(key, _)| matches!(key, 1 | 2 | 11)) {
            gact = gact_identity(&options)?;
        }
        if let Some(identity) = &gact {
            // Only fully understood configuration is normalized. Ignore
            // runtime counters and reference counts, retain the sole binding.
            let flags = word(attr(&options, 3).ok_or_else(invalid)?)?;
            let canonical = gact_options(
                identity.action_index,
                0,
                1,
                identity.cookie,
                identity.verdict,
                flags,
            )?;
            configuration
                .iter_mut()
                .find(|(key, _)| *key == 2)
                .ok_or_else(invalid)?
                .1 = canonical;
        }
    }
    Ok(Entry {
        slot,
        kind,
        configuration,
        bpf,
        gact,
    })
}

pub(super) struct Dump {
    ifindex: u32,
    hook: TcHook,
    sequence: u32,
    port: u32,
    entries: Vec<Entry>,
    seen: BTreeSet<TcSlot>,
    done: bool,
    failed: bool,
    bytes: usize,
}

impl Dump {
    pub(super) fn new(ifindex: u32, hook: TcHook, sequence: u32, port: u32) -> Self {
        Self {
            ifindex,
            hook,
            sequence,
            port,
            entries: Vec::new(),
            seen: BTreeSet::new(),
            done: false,
            failed: false,
            bytes: 0,
        }
    }
    pub(super) fn is_done(&self) -> bool {
        self.done
    }
    pub(super) fn consume(&mut self, bytes: &[u8]) -> io::Result<()> {
        let result = self.consume_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn consume_inner(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        self.bytes = self.bytes.checked_add(bytes.len()).ok_or_else(invalid)?;
        if bytes.is_empty() || self.failed || self.bytes > MAX_DUMP_BYTES {
            return Err(invalid());
        }
        while !bytes.is_empty() {
            if self.done {
                return Err(invalid());
            }
            let length = u32_at(bytes, 0)? as usize;
            if length < 16 {
                return Err(invalid());
            }
            let message = bytes.get(..length).ok_or_else(invalid)?;
            let flags = u16_at(message, 6)?;
            if u32_at(message, 8)? != self.sequence
                || u32_at(message, 12)? != self.port
                || flags != crate::NLM_F_MULTI
            {
                return Err(invalid());
            }
            match u16_at(message, 4)? {
                crate::RTM_NEWTFILTER => {
                    let item = entry(message, self.ifindex, self.hook)?;
                    if self.entries.len() >= MAX_ENTRIES || !self.seen.insert(item.slot) {
                        return Err(invalid());
                    }
                    self.entries.push(item);
                }
                crate::NLMSG_DONE if length == 20 && u32_at(message, 16)? == 0 => self.done = true,
                _ => return Err(invalid()),
            }
            let aligned = crate::align_to_netlink(length).ok_or_else(invalid)?;
            if bytes
                .get(length..aligned)
                .ok_or_else(invalid)?
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(invalid());
            }
            bytes = bytes.get(aligned..).ok_or_else(invalid)?;
        }
        Ok(())
    }
    pub(super) fn finish(self) -> io::Result<Vec<Entry>> {
        if !self.done || self.failed {
            return Err(invalid());
        }
        Ok(self.entries)
    }
}

pub(super) fn encode_attributes(attrs: &[(u16, Vec<u8>)]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for (kind, data) in attrs {
        let length = data.len().checked_add(4).ok_or_else(invalid)?;
        out.extend(u16::try_from(length).map_err(|_| invalid())?.to_ne_bytes());
        out.extend(kind.to_ne_bytes());
        out.extend(data);
        out.resize(crate::align_to_netlink(out.len()).ok_or_else(invalid)?, 0);
    }
    Ok(out)
}

fn request(
    ifindex: u32,
    hook: TcHook,
    message_type: u16,
    flags: u16,
    sequence: u32,
    port: u32,
) -> io::Result<Vec<u8>> {
    if ifindex == 0 || ifindex > i32::MAX as u32 || sequence == 0 || port == 0 {
        return Err(invalid());
    }
    let mut out = Vec::from(36_u32.to_ne_bytes());
    out.extend(message_type.to_ne_bytes());
    out.extend((crate::NLM_F_REQUEST | flags).to_ne_bytes());
    out.extend(sequence.to_ne_bytes());
    out.extend(port.to_ne_bytes());
    out.extend([0; 4]);
    out.extend(ifindex.to_ne_bytes());
    out.extend(0_u32.to_ne_bytes());
    out.extend(hook.parent().to_ne_bytes());
    out.extend(0_u32.to_ne_bytes());
    Ok(out)
}

pub(super) fn dump_request(
    ifindex: u32,
    hook: TcHook,
    sequence: u32,
    port: u32,
) -> io::Result<Vec<u8>> {
    // Omit TCA_CHAIN and zero tcm_info: enumerate all chains/protocols/priorities.
    request(
        ifindex,
        hook,
        crate::RTM_GETTFILTER,
        crate::NLM_F_DUMP,
        sequence,
        port,
    )
}

pub(super) fn delete_request(
    slot: TcSlot,
    kind: &[u8],
    sequence: u32,
    port: u32,
) -> io::Result<Vec<u8>> {
    TcSlot::new(
        slot.ifindex,
        slot.hook,
        slot.chain,
        slot.protocol,
        slot.priority,
        slot.handle,
    )?;
    if kind.is_empty() || kind.len() > 16 || kind.contains(&0) {
        return Err(invalid());
    }
    let mut out = request(
        slot.ifindex,
        slot.hook,
        crate::RTM_DELTFILTER,
        crate::NLM_F_ACK,
        sequence,
        port,
    )?;
    out[24..28].copy_from_slice(&slot.handle.to_ne_bytes());
    out[32..36].copy_from_slice(
        &((u32::from(slot.priority) << 16) | u32::from(slot.protocol.to_be())).to_ne_bytes(),
    );
    let mut kind = kind.to_vec();
    kind.push(0);
    out.extend(encode_attributes(&[
        (1, kind),
        (CHAIN, slot.chain.to_ne_bytes().to_vec()),
    ])?);
    let length = out.len() as u32;
    out[..4].copy_from_slice(&length.to_ne_bytes());
    Ok(out)
}

pub(super) fn ack(bytes: &[u8], request: &[u8]) -> io::Result<()> {
    if u32_at(bytes, 0)? as usize != bytes.len()
        || u16_at(bytes, 4)? != crate::NLMSG_ERROR
        || u16_at(bytes, 6)? & !0x100 != 0
        || bytes.get(8..16) != request.get(8..16)
        || bytes.get(20..36) != request.get(..16)
    {
        return Err(invalid());
    }
    let status = u32_at(bytes, 16)? as i32;
    if status > 0 {
        return Err(invalid());
    }
    if status < 0 {
        return Err(io::Error::from_raw_os_error(
            status.checked_neg().ok_or_else(invalid)?,
        ));
    }
    if bytes.len() != 36 {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn gact_request(
    slot: TcSlot,
    cookie: [u8; 16],
    verdict: TcVerdict,
    sequence: u32,
    port: u32,
) -> io::Result<Vec<u8>> {
    let mut out = delete_request(slot, b"matchall", sequence, port)?;
    out[4..6].copy_from_slice(&crate::RTM_NEWTFILTER.to_ne_bytes());
    out[6..8].copy_from_slice(
        &(crate::NLM_F_REQUEST | crate::NLM_F_ACK | crate::NLM_F_CREATE | crate::NLM_F_EXCL)
            .to_ne_bytes(),
    );
    // Index zero allocates a fresh unshared action; no existing action is bound.
    out.extend(encode_attributes(&[(
        2,
        gact_options(0, 0, 0, cookie, verdict, 1)?,
    )])?);
    let length = out.len() as u32;
    out[..4].copy_from_slice(&length.to_ne_bytes());
    Ok(out)
}

pub(super) fn classifier_request(
    slot: TcSlot,
    fd: i32,
    name: &str,
    sequence: u32,
    port: u32,
) -> io::Result<Vec<u8>> {
    if fd < 0 || name.is_empty() || name.len() > 127 || name.as_bytes().contains(&0) {
        return Err(invalid());
    }
    let mut out = delete_request(slot, b"bpf", sequence, port)?;
    out[4..6].copy_from_slice(&crate::RTM_NEWTFILTER.to_ne_bytes());
    out[6..8].copy_from_slice(
        &(crate::NLM_F_REQUEST | crate::NLM_F_ACK | crate::NLM_F_CREATE | crate::NLM_F_EXCL)
            .to_ne_bytes(),
    );
    let mut name = name.as_bytes().to_vec();
    name.push(0);
    let options = encode_attributes(&[
        (6, fd.to_ne_bytes().to_vec()),
        (7, name),
        (8, 1_u32.to_ne_bytes().to_vec()), // TCA_BPF_FLAG_ACT_DIRECT
        (9, 1_u32.to_ne_bytes().to_vec()), // TCA_CLS_FLAGS_SKIP_HW
    ])?;
    out.extend(encode_attributes(&[(2, options)])?);
    let length = out.len() as u32;
    out[..4].copy_from_slice(&length.to_ne_bytes());
    Ok(out)
}

pub(super) fn frames(mut bytes: &[u8], sequence: u32, port: u32) -> io::Result<Vec<&[u8]>> {
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(invalid());
    }
    let mut frames = Vec::new();
    while !bytes.is_empty() {
        let length = u32_at(bytes, 0)? as usize;
        if length < 16 {
            return Err(invalid());
        }
        let frame = bytes.get(..length).ok_or_else(invalid)?;
        if u32_at(frame, 8)? != sequence || u32_at(frame, 12)? != port {
            return Err(invalid());
        }
        let aligned = crate::align_to_netlink(length).ok_or_else(invalid)?;
        if bytes
            .get(length..aligned)
            .ok_or_else(invalid)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(invalid());
        }
        frames.push(frame);
        bytes = bytes.get(aligned..).ok_or_else(invalid)?;
    }
    Ok(frames)
}
