//! Exact version-one framing and bounded untrusted wire claims.

use opc_types::{NetworkFunctionKind, TenantId};
use sha2::{Digest, Sha256};
use std::fmt;

pub(super) const HEADER_BYTES: usize = 128;
pub(super) const MAX_PROOF_FRAME_BYTES: usize = 8 * 1024;
pub(super) const MAX_SCOPE_COMMAND_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_SCOPE_FRAME_BYTES: usize = MAX_SCOPE_COMMAND_BYTES + 512;
pub(super) const MAX_NOTICE_FRAME_BYTES: usize = 64 * 1024;
pub(super) const MAX_AUTHORITY_BYTES: usize = 4096;

/// A malformed, noncanonical or out-of-bounds scope wire claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid scope wire claim")]
pub struct WireError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum FrameKind {
    Call = 1,
    Challenge = 2,
    Proof = 3,
    Result = 4,
    TicketNotice = 5,
}
impl TryFrom<u8> for FrameKind {
    type Error = WireError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Call),
            2 => Ok(Self::Challenge),
            3 => Ok(Self::Proof),
            4 => Ok(Self::Result),
            5 => Ok(Self::TicketNotice),
            _ => Err(WireError),
        }
    }
}

/// Independent transport connection/listener class, including both emergency pools.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// Typed authority and bounded control work.
    SafetyControl,
    /// Work for a positively established emergency session.
    Emergency,
    /// Unverified emergency classification, separately bounded.
    EmergencyClassification,
    /// Ordinary foreground work.
    Normal,
    /// Bounded recovery and maintenance work.
    Maintenance,
}
impl Class {
    fn decode(class: u8, bucket: u8) -> Result<Self, WireError> {
        match (class, bucket) {
            (0, 0) => Ok(Self::SafetyControl),
            (1, 1) => Ok(Self::Emergency),
            (1, 2) => Ok(Self::EmergencyClassification),
            (2, 0) => Ok(Self::Normal),
            (3, 0) => Ok(Self::Maintenance),
            _ => Err(WireError),
        }
    }
    const fn encode(self) -> [u8; 2] {
        match self {
            Self::SafetyControl => [0, 0],
            Self::Emergency => [1, 1],
            Self::EmergencyClassification => [1, 2],
            Self::Normal => [2, 0],
            Self::Maintenance => [3, 0],
        }
    }
    pub(super) const fn index(self) -> usize {
        match self {
            Self::SafetyControl => 0,
            Self::Emergency => 1,
            Self::EmergencyClassification => 2,
            Self::Normal => 3,
            Self::Maintenance => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Method {
    AdmitInitial = 1,
    SucceedClosed = 2,
    Close = 3,
    ApplyBatch = 4,
    Current = 5,
    Outcome = 6,
    Liveness = 7,
    Candidate = 8,
    BatchReopen = 9,
    BatchCancel = 10,
    BatchLookup = 11,
}
impl TryFrom<u8> for Method {
    type Error = WireError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AdmitInitial),
            2 => Ok(Self::SucceedClosed),
            3 => Ok(Self::Close),
            4 => Ok(Self::ApplyBatch),
            5 => Ok(Self::Current),
            6 => Ok(Self::Outcome),
            7 => Ok(Self::Liveness),
            8 => Ok(Self::Candidate),
            9 => Ok(Self::BatchReopen),
            10 => Ok(Self::BatchCancel),
            11 => Ok(Self::BatchLookup),
            _ => Err(WireError),
        }
    }
}
impl Method {
    pub(super) const fn is_startup(self) -> bool {
        matches!(self, Self::Liveness | Self::Candidate)
    }
    pub(super) const fn command_limit(self) -> usize {
        match self {
            Self::ApplyBatch => MAX_SCOPE_COMMAND_BYTES,
            Self::Liveness | Self::Candidate => 340,
            _ => MAX_AUTHORITY_BYTES,
        }
    }
}

/// Locally configured scope, encoded independently of the store's Postcard codec.
/// This routing identity is never proof of current execution or admission.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeBinding {
    installation: [u8; 32],
    tenant: TenantId,
    nf_kind: NetworkFunctionKind,
    slot: [u8; 32],
}
impl fmt::Debug for ScopeBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBinding([redacted])")
    }
}
impl ScopeBinding {
    /// Derive routing bytes from the native scope's configured store identity.
    /// The current native profile uses the name-derived consensus cluster ID.
    pub fn from_scope(
        scope: &opc_session_store::scope_authority::ScopeId,
    ) -> Result<Self, WireError> {
        Self::new(
            *scope.store().as_bytes(),
            scope.tenant().clone(),
            scope.nf_kind().clone(),
            *scope.slot(),
        )
    }
    /// Bind one configured store domain, tenant, network-function namespace and slot.
    pub fn new(
        installation: [u8; 32],
        tenant: TenantId,
        nf_kind: NetworkFunctionKind,
        slot: [u8; 32],
    ) -> Result<Self, WireError> {
        if slot == [0; 32] || tenant.as_str().len() > 128 || nf_kind.as_str().len() > 64 {
            return Err(WireError);
        }
        Ok(Self {
            installation,
            tenant,
            nf_kind,
            slot,
        })
    }
    pub(super) fn read(reader: &mut Reader<'_>) -> Result<Self, WireError> {
        let installation = reader.array()?;
        let tenant = TenantId::new(reader.text(128, false)?).map_err(|_| WireError)?;
        let nf_kind = NetworkFunctionKind::new(reader.text(64, false)?).map_err(|_| WireError)?;
        Self::new(installation, tenant, nf_kind, reader.array()?)
    }
    #[cfg(test)]
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        let value = Self::read(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }
    /// Exact RFC026 routing bytes, with bounded text lengths.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.installation.to_vec();
        // Constructors and identifier types enforce these bounds.
        bytes.extend_from_slice(&(self.tenant.as_str().len() as u16).to_be_bytes());
        bytes.extend_from_slice(self.tenant.as_str().as_bytes());
        bytes.extend_from_slice(&(self.nf_kind.as_str().len() as u16).to_be_bytes());
        bytes.extend_from_slice(self.nf_kind.as_str().as_bytes());
        bytes.extend_from_slice(&self.slot);
        bytes
    }
    /// SHA-256 routing commitment; not a boot-key or authority commitment.
    pub fn commitment(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"openpacketcore/scope/id/v1\0");
        digest.update(self.encode());
        digest.finalize().into()
    }
    /// Configured installation identity.
    pub const fn installation(&self) -> &[u8; 32] {
        &self.installation
    }
    /// Fixed scope for the owned TLS connection.
    pub fn tls_domain(&self) -> Result<opc_tls::ChannelBindingDomain, WireError> {
        opc_tls::ChannelBindingDomain::new(self.installation, self.encode()).map_err(|_| WireError)
    }
}

pub(super) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AuthorityReference {
    pub(super) record_uid: Vec<u8>,
    pub(super) revision: Vec<u8>,
}

impl AuthorityReference {
    pub(super) fn new(record_uid: Vec<u8>, revision: Vec<u8>) -> Result<Self, WireError> {
        if record_uid.is_empty()
            || record_uid.len() > 256
            || revision.is_empty()
            || revision.len() > 256
        {
            return Err(WireError);
        }
        Ok(Self {
            record_uid,
            revision,
        })
    }

    pub(super) fn write(&self, output: &mut Vec<u8>) -> Result<(), WireError> {
        output.push(1);
        put_lp16(output, &self.record_uid)?;
        put_lp16(output, &self.revision)
    }

    pub(super) fn read(reader: &mut Reader<'_>) -> Result<Option<Self>, WireError> {
        match reader.u8()? {
            0 => Ok(None),
            1 => Self::new(reader.lp16(256)?.to_vec(), reader.lp16(256)?.to_vec()).map(Some),
            _ => Err(WireError),
        }
    }
}

impl fmt::Debug for AuthorityReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorityReference([redacted])")
    }
}

pub(super) fn transport_request_digest(
    method: Method,
    request_id: &[u8; 16],
    canonical: &[u8],
) -> Result<[u8; 32], WireError> {
    if request_id == &[0; 16] || canonical.is_empty() || canonical.len() > method.command_limit() {
        return Err(WireError);
    }
    let domain: &[u8] = match method {
        Method::Current | Method::Outcome | Method::BatchReopen | Method::BatchLookup => {
            b"openpacketcore/scope/read/v1\0"
        }
        Method::Liveness | Method::Candidate => b"openpacketcore/scope/startup-request/v1\0",
        _ => return Err(WireError), // Native authority and batch helpers own their digests.
    };
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([method as u8]);
    digest.update(request_id);
    digest.update(canonical);
    Ok(digest.finalize().into())
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Header {
    pub(super) kind: FrameKind,
    pub(super) class: Class,
    pub(super) method: Method,
    pub(super) installation: [u8; 32],
    pub(super) scope: [u8; 32],
    pub(super) request_id: [u8; 16],
    pub(super) digest: [u8; 32],
    pub(super) payload_len: usize,
}
impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Header([redacted])")
    }
}
impl Header {
    pub(super) fn validate(&self) -> Result<(), WireError> {
        if self.request_id == [0; 16] || self.scope == [0; 32] || self.digest == [0; 32] {
            return Err(WireError);
        }
        let limit = match self.kind {
            FrameKind::Proof => MAX_PROOF_FRAME_BYTES - HEADER_BYTES,
            FrameKind::Challenge => {
                if self.payload_len != 32 || self.method.is_startup() {
                    return Err(WireError);
                }
                32
            }
            FrameKind::TicketNotice => {
                if self.method != Method::Candidate {
                    return Err(WireError);
                }
                MAX_NOTICE_FRAME_BYTES - HEADER_BYTES
            }
            FrameKind::Call => self.method.command_limit() + 36,
            FrameKind::Result => {
                if self.method == Method::ApplyBatch {
                    MAX_SCOPE_FRAME_BYTES - HEADER_BYTES
                } else {
                    MAX_AUTHORITY_BYTES + 69
                }
            }
        };
        if self.payload_len > limit {
            return Err(WireError);
        }
        Ok(())
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != HEADER_BYTES {
            return Err(WireError);
        }
        let mut reader = Reader::new(bytes);
        let remaining = reader.u32()? as usize;
        if reader.u16()? != 1 {
            return Err(WireError);
        }
        let kind = FrameKind::try_from(reader.u8()?)?;
        let class = Class::decode(reader.u8()?, reader.u8()?)?;
        let method = Method::try_from(reader.u8()?)?;
        if reader.u16()? != 0 {
            return Err(WireError);
        }
        let value = Self {
            kind,
            class,
            method,
            installation: reader.array()?,
            scope: reader.array()?,
            request_id: reader.array()?,
            digest: reader.array()?,
            payload_len: reader.u32()? as usize,
        };
        reader.finish()?;
        value.validate()?;
        if remaining != 124 + value.payload_len {
            return Err(WireError);
        }
        Ok(value)
    }
    pub(super) fn encode(&self) -> Result<[u8; 128], WireError> {
        self.validate()?;
        let mut bytes = [0; 128];
        bytes[0..4].copy_from_slice(&((124 + self.payload_len) as u32).to_be_bytes());
        bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
        bytes[6] = self.kind as u8;
        bytes[7..9].copy_from_slice(&self.class.encode());
        bytes[9] = self.method as u8;
        bytes[12..44].copy_from_slice(&self.installation);
        bytes[44..76].copy_from_slice(&self.scope);
        bytes[76..92].copy_from_slice(&self.request_id);
        bytes[92..124].copy_from_slice(&self.digest);
        bytes[124..128].copy_from_slice(&(self.payload_len as u32).to_be_bytes());
        Ok(bytes)
    }
    pub(super) fn matches_attempt(&self, other: &Self) -> bool {
        self.class == other.class
            && self.method == other.method
            && self.installation == other.installation
            && self.scope == other.scope
            && self.request_id == other.request_id
            && self.digest == other.digest
    }
    pub(super) fn response(&self, kind: FrameKind, payload_len: usize) -> Result<Self, WireError> {
        let mut value = self.clone();
        value.kind = kind;
        value.payload_len = payload_len;
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
pub(super) struct Frame {
    pub(super) header: Header,
    pub(super) payload: Vec<u8>,
}
#[cfg(test)]
impl Frame {
    pub(super) fn new(header: Header, payload: Vec<u8>) -> Result<Self, WireError> {
        header.validate()?;
        if header.payload_len != payload.len() {
            return Err(WireError);
        }
        Ok(Self { header, payload })
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let header = Header::decode(bytes.get(..HEADER_BYTES).ok_or(WireError)?)?;
        let payload = bytes.get(HEADER_BYTES..).ok_or(WireError)?;
        if payload.len() != header.payload_len {
            return Err(WireError);
        }
        Self::new(header, payload.to_vec())
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.payload.len() != self.header.payload_len {
            return Err(WireError);
        }
        let mut bytes = self.header.encode()?.to_vec();
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum ResultStatus {
    ProvenNoEffect = 0,
    Committed = 1,
    OutcomeUnknown = 2,
    Obsolete = 3,
    CurrentView = 4,
    BatchError = 5,
}
impl TryFrom<u8> for ResultStatus {
    type Error = WireError;
    fn try_from(value: u8) -> Result<Self, WireError> {
        match value {
            0 => Ok(Self::ProvenNoEffect),
            1 => Ok(Self::Committed),
            2 => Ok(Self::OutcomeUnknown),
            3 => Ok(Self::Obsolete),
            4 => Ok(Self::CurrentView),
            5 => Ok(Self::BatchError),
            _ => Err(WireError),
        }
    }
}

pub(super) struct ResultPayload {
    pub(super) nonce: [u8; 32],
    pub(super) status: ResultStatus,
    pub(super) own_execution: [u8; 32],
    pub(super) body: Vec<u8>,
}
impl ResultPayload {
    pub(super) fn new(
        nonce: [u8; 32],
        status: ResultStatus,
        own_execution: [u8; 32],
        body: Vec<u8>,
    ) -> Result<Self, WireError> {
        if nonce == [0; 32]
            || body.len() > MAX_SCOPE_FRAME_BYTES - HEADER_BYTES - 69
            || (status != ResultStatus::Committed && own_execution != [0; 32])
        {
            return Err(WireError);
        }
        let valid = match status {
            ResultStatus::ProvenNoEffect => matches!(body.as_slice(), [0, 1..=5]),
            ResultStatus::OutcomeUnknown => body.is_empty(),
            ResultStatus::Obsolete => matches!(body.as_slice(), [1..=4]),
            ResultStatus::Committed | ResultStatus::CurrentView | ResultStatus::BatchError => {
                !body.is_empty()
            }
        };
        if !valid {
            return Err(WireError);
        }
        Ok(Self {
            nonce,
            status,
            own_execution,
            body,
        })
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        let nonce = reader.array()?;
        let status = ResultStatus::try_from(reader.u8()?)?;
        let execution = reader.array()?;
        let body = reader
            .lp32(MAX_SCOPE_FRAME_BYTES - HEADER_BYTES - 69)?
            .to_vec();
        reader.finish()?;
        Self::new(nonce, status, execution, body)
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut result = self.nonce.to_vec();
        result.push(self.status as u8);
        result.extend_from_slice(&self.own_execution);
        put_lp32(&mut result, &self.body)?;
        Ok(result)
    }
}

pub(super) struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let value = self.remaining.get(..length).ok_or(WireError)?;
        self.remaining = &self.remaining[length..];
        Ok(value)
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.take(N)?.try_into().map_err(|_| WireError)
    }
    pub(super) fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.array::<1>()?[0])
    }
    pub(super) fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(super) fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(super) fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(super) fn lp16(&mut self, limit: usize) -> Result<&'a [u8], WireError> {
        let length = self.u16()? as usize;
        if length > limit {
            return Err(WireError);
        }
        self.take(length)
    }
    pub(super) fn lp32(&mut self, limit: usize) -> Result<&'a [u8], WireError> {
        let length = self.u32()? as usize;
        if length > limit {
            return Err(WireError);
        }
        self.take(length)
    }
    pub(super) fn text(&mut self, limit: usize, empty: bool) -> Result<&'a str, WireError> {
        let value = std::str::from_utf8(self.lp16(limit)?).map_err(|_| WireError)?;
        if (!empty && value.is_empty()) || value.chars().any(char::is_control) {
            return Err(WireError);
        }
        Ok(value)
    }
    pub(super) fn finish(self) -> Result<(), WireError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(WireError)
        }
    }
}
pub(super) fn put_lp16(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WireError> {
    let length = u16::try_from(value.len()).map_err(|_| WireError)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}
pub(super) fn put_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WireError> {
    let length = u32::try_from(value.len()).map_err(|_| WireError)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

pub(super) struct CallPayload {
    pub(super) nonce: [u8; 32],
    pub(super) canonical: Vec<u8>,
}
impl CallPayload {
    pub(super) fn decode(method: Method, bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        let nonce = reader.array()?;
        if nonce == [0; 32] {
            return Err(WireError);
        }
        let canonical = reader.lp32(method.command_limit())?;
        if canonical.is_empty() {
            return Err(WireError);
        }
        reader.finish()?;
        Ok(Self {
            nonce,
            canonical: canonical.to_vec(),
        })
    }
    pub(super) fn encode(&self, method: Method) -> Result<Vec<u8>, WireError> {
        if self.nonce == [0; 32]
            || self.canonical.is_empty()
            || self.canonical.len() > method.command_limit()
        {
            return Err(WireError);
        }
        let mut output = self.nonce.to_vec();
        put_lp32(&mut output, &self.canonical)?;
        Ok(output)
    }
}
