//! Canonical proof claims and trusted-observation digest inputs.
//!
//! Encoding a claim never verifies its source. Live connection, independent
//! issuer and committed-state checks belong to the admission boundary.

use super::wire::*;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use zeroize::Zeroizing;

const LIVENESS_DOMAIN: &[u8] = b"openpacketcore/scope/boot-liveness/v1\0";
const CANDIDATE_DOMAIN: &[u8] = b"openpacketcore/scope/boot-candidate/v1\0";

#[derive(Clone)]
pub(super) struct BootObservation {
    pub(super) namespace: String,
    pub(super) pod_name: String,
    pub(super) pod_uid: [u8; 16],
    pub(super) service_account: String,
    pub(super) service_account_uid: [u8; 16],
    pub(super) container_name: String,
    pub(super) container_id: String,
    pub(super) started_at: String,
}
impl BootObservation {
    pub(super) fn input(&self) -> Result<Vec<u8>, WireError> {
        if self.pod_uid == [0; 16] || self.service_account_uid == [0; 16] {
            return Err(WireError);
        }
        let mut output = b"openpacketcore/scope/platform-boot/v1\0".to_vec();
        text(&mut output, &self.namespace, 253, false, false)?;
        text(&mut output, &self.pod_name, 253, false, false)?;
        output.extend_from_slice(&self.pod_uid);
        text(&mut output, &self.service_account, 253, false, false)?;
        output.extend_from_slice(&self.service_account_uid);
        text(&mut output, &self.container_name, 253, false, false)?;
        text(&mut output, &self.container_id, 512, false, false)?;
        text(&mut output, &self.started_at, 64, false, false)?;
        Ok(output)
    }
    pub(super) fn digest(&self) -> Result<[u8; 32], WireError> {
        Ok(hash(&self.input()?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartupMode {
    Liveness,
    Candidate,
}
impl StartupMode {
    pub(super) const fn method(self) -> Method {
        match self {
            Self::Liveness => Method::Liveness,
            Self::Candidate => Method::Candidate,
        }
    }
    pub(super) const fn purpose(self) -> opc_tls::ChannelBindingPurpose {
        match self {
            Self::Liveness => opc_tls::ChannelBindingPurpose::BootLiveness,
            Self::Candidate => opc_tls::ChannelBindingPurpose::BootCandidate,
        }
    }
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Liveness => LIVENESS_DOMAIN,
            Self::Candidate => CANDIDATE_DOMAIN,
        }
    }
    const fn local_context(self) -> [u8; 3] {
        match self {
            Self::Liveness => [0, 0, 0],
            Self::Candidate => [1, 1, 1],
        }
    }
}

#[derive(Clone)]
pub(super) struct StartupClaims {
    pub(super) mode: StartupMode,
    pub(super) scope: ScopeBinding,
    pub(super) workload: [u8; 16],
    pub(super) process: [u8; 16],
    pub(super) public_key: [u8; 33],
    pub(super) credential_digest: [u8; 32],
    pub(super) observation: [u8; 32],
    pub(super) challenge: [u8; 32],
    pub(super) binding: [u8; 32],
}
impl StartupClaims {
    pub(super) fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.workload == [0; 16]
            || self.process == [0; 16]
            || self.credential_digest == [0; 32]
            || self.observation == [0; 32]
            || self.challenge == [0; 32]
            || self.binding == [0; 32]
        {
            return Err(WireError);
        }
        public_key(&self.public_key)?;
        let mut output = self.mode.domain().to_vec();
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.extend_from_slice(&[self.mode.method() as u8, 1]);
        output.extend_from_slice(&self.scope.encode());
        output.extend_from_slice(&self.workload);
        output.extend_from_slice(&self.process);
        output.extend_from_slice(&self.public_key);
        output.extend_from_slice(&self.credential_digest);
        output.extend_from_slice(&self.observation);
        output.extend_from_slice(&self.mode.local_context());
        output.extend_from_slice(&self.challenge);
        output.extend_from_slice(&self.binding);
        Ok(output)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_PROOF_FRAME_BYTES - HEADER_BYTES {
            return Err(WireError);
        }
        let mode = if bytes.starts_with(LIVENESS_DOMAIN) {
            StartupMode::Liveness
        } else if bytes.starts_with(CANDIDATE_DOMAIN) {
            StartupMode::Candidate
        } else {
            return Err(WireError);
        };
        let mut reader = Reader::new(bytes);
        reader.take(mode.domain().len())?;
        if reader.u16()? != 1 || reader.u8()? != mode.method() as u8 || reader.u8()? != 1 {
            return Err(WireError);
        }
        let mut claims = Self {
            mode,
            scope: ScopeBinding::read(&mut reader)?,
            workload: reader.array()?,
            process: reader.array()?,
            public_key: reader.array()?,
            credential_digest: reader.array()?,
            observation: reader.array()?,
            challenge: [0; 32],
            binding: [0; 32],
        };
        if reader.array::<3>()? != mode.local_context() {
            return Err(WireError);
        }
        claims.challenge = reader.array()?;
        claims.binding = reader.array()?;
        reader.finish()?;
        if claims.encode()?.as_slice() != bytes {
            return Err(WireError);
        }
        Ok(claims)
    }
}

pub(super) fn public_key(bytes: &[u8; 33]) -> Result<VerifyingKey, WireError> {
    if !matches!(bytes[0], 2 | 3) {
        return Err(WireError);
    }
    VerifyingKey::from_sec1_bytes(bytes).map_err(|_| WireError)
}
pub(super) fn verify_signature(
    key: &[u8; 33],
    input: &[u8],
    signature: &[u8; 64],
) -> Result<(), WireError> {
    let signature = Signature::from_slice(signature).map_err(|_| WireError)?;
    if signature.normalize_s() != signature {
        return Err(WireError);
    }
    public_key(key)?
        .verify(input, &signature)
        .map_err(|_| WireError)
}

pub(super) struct StartupProof {
    pub(super) credential: Zeroizing<Vec<u8>>,
    pub(super) claims: StartupClaims,
    pub(super) signature: [u8; 64],
}
impl StartupProof {
    pub(super) fn new(
        credential: Vec<u8>,
        claims: StartupClaims,
        signature: [u8; 64],
    ) -> Result<Self, WireError> {
        let credential = Zeroizing::new(credential);
        if credential.is_empty()
            || credential.len() > 4096
            || !credential.is_ascii()
            || credential.iter().any(u8::is_ascii_control)
            || hash(&credential) != claims.credential_digest
        {
            return Err(WireError);
        }
        // This checks claim structure, never the independent platform observation.
        let claims_len = claims.encode()?.len();
        let proof = Self {
            credential,
            claims,
            signature,
        };
        // Do not create an unprotected temporary copy of the credential merely
        // to check the encoded size. Both variable fields are already bounded.
        if 2 + proof.credential.len() + 4 + claims_len + 64 > MAX_PROOF_FRAME_BYTES - HEADER_BYTES {
            return Err(WireError);
        }
        Ok(proof)
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut output = Vec::new();
        put_lp16(&mut output, &self.credential)?;
        put_lp32(&mut output, &self.claims.encode()?)?;
        output.extend_from_slice(&self.signature);
        Ok(output)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_PROOF_FRAME_BYTES - HEADER_BYTES {
            return Err(WireError);
        }
        let mut reader = Reader::new(bytes);
        let mut credential = Zeroizing::new(reader.lp16(4096)?.to_vec());
        let claims = StartupClaims::decode(reader.lp32(MAX_PROOF_FRAME_BYTES - HEADER_BYTES)?)?;
        let signature = reader.array()?;
        reader.finish()?;
        Self::new(std::mem::take(&mut *credential), claims, signature)
    }
}

#[derive(Clone)]
pub(super) struct TerminationObservation {
    pub(super) namespace: String,
    pub(super) pod_name: String,
    pub(super) pod_uid: [u8; 16],
    pub(super) container_name: String,
    pub(super) container_id: String,
    pub(super) exit_code: i32,
    pub(super) signal: i32,
    pub(super) reason: String,
    pub(super) message: String,
    pub(super) started_at: String,
    pub(super) finished_at: String,
    pub(super) record: AuthorityReference,
}
impl TerminationObservation {
    pub(super) fn input(&self, predecessor: &[u8]) -> Result<Vec<u8>, WireError> {
        check_stamp_bytes(predecessor)?;
        if self.pod_uid == [0; 16] {
            return Err(WireError);
        }
        let mut output = b"openpacketcore/scope/closure/kubernetes-final/v1\0".to_vec();
        output.extend_from_slice(&1_u16.to_be_bytes());
        put_lp32(&mut output, predecessor)?;
        output.extend_from_slice(&self.pod_uid);
        text(&mut output, &self.namespace, 253, false, false)?;
        text(&mut output, &self.pod_name, 253, false, false)?;
        text(&mut output, &self.container_name, 253, false, false)?;
        text(&mut output, &self.container_id, 512, false, false)?;
        text(&mut output, &self.exit_code.to_string(), 11, false, false)?;
        text(&mut output, &self.signal.to_string(), 11, false, false)?;
        text(&mut output, &self.reason, 256, true, true)?;
        // Commit the exact API capture without copying it into the bounded
        // evidence input. Runtime prefixes and UTF-8 replacement can expand it
        // beyond the kubelet's termination-file byte limit.
        output.extend_from_slice(&hash(self.message.as_bytes()));
        text(&mut output, &self.started_at, 64, false, true)?;
        text(&mut output, &self.finished_at, 64, false, true)?;
        self.record.write(&mut output)?;
        Ok(output)
    }
}

pub(super) fn local_quiescence_input(stamp: &[u8], nonce: &[u8; 32]) -> Result<Vec<u8>, WireError> {
    check_stamp_bytes(stamp)?;
    if nonce == &[0; 32] {
        return Err(WireError);
    }
    let mut output = b"openpacketcore/scope/closure/local-quiescence/v1\0".to_vec();
    output.extend_from_slice(&1_u16.to_be_bytes());
    put_lp32(&mut output, stamp)?;
    output.extend_from_slice(nonce);
    output.extend_from_slice(&[1, 1]);
    Ok(output)
}
fn check_stamp_bytes(stamp: &[u8]) -> Result<(), WireError> {
    // The trusted caller supplies the canonical native stamp; no second native codec.
    if stamp.is_empty() || stamp.len() > MAX_AUTHORITY_BYTES {
        Err(WireError)
    } else {
        Ok(())
    }
}
fn text(
    output: &mut Vec<u8>,
    value: &str,
    limit: usize,
    empty: bool,
    opaque: bool,
) -> Result<(), WireError> {
    if value.len() > limit
        || (!empty && value.is_empty())
        || (!opaque && value.chars().any(char::is_control))
    {
        return Err(WireError);
    }
    put_lp16(output, value.as_bytes())
}

#[derive(Clone)]
pub(super) struct PossessionClaims {
    pub(super) call: Header,
    pub(super) caller_nonce: [u8; 32],
    pub(super) execution: [u8; 32],
    pub(super) public_key: [u8; 33],
    pub(super) authority: Option<AuthorityReference>,
    pub(super) challenge: [u8; 32],
    pub(super) binding: [u8; 32],
}
impl PossessionClaims {
    pub(super) fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.call.kind != FrameKind::Call
            || self.call.method.is_startup()
            || self.caller_nonce == [0; 32]
            || self.execution == [0; 32]
            || self.challenge == [0; 32]
            || self.binding == [0; 32]
            || (self.authority.is_some()
                && !matches!(
                    self.call.method,
                    Method::AdmitInitial | Method::SucceedClosed
                ))
        {
            return Err(WireError);
        }
        public_key(&self.public_key)?;
        let mut output = b"openpacketcore/scope/process-possession/v1\0".to_vec();
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.push(0);
        output.extend_from_slice(&self.call.encode()?);
        output.extend_from_slice(&self.caller_nonce);
        output.extend_from_slice(&self.execution);
        output.extend_from_slice(&self.public_key);
        if let Some(authority) = &self.authority {
            authority.write(&mut output)?;
        } else {
            output.push(0);
        }
        output.extend_from_slice(&self.challenge);
        output.extend_from_slice(&self.binding);
        Ok(output)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_PROOF_FRAME_BYTES - HEADER_BYTES - 68 {
            return Err(WireError);
        }
        let domain = b"openpacketcore/scope/process-possession/v1\0";
        let mut reader = Reader::new(bytes);
        if reader.take(domain.len())? != domain || reader.u16()? != 1 || reader.u8()? != 0 {
            return Err(WireError);
        }
        let claims = Self {
            call: Header::decode(reader.take(HEADER_BYTES)?)?,
            caller_nonce: reader.array()?,
            execution: reader.array()?,
            public_key: reader.array()?,
            authority: AuthorityReference::read(&mut reader)?,
            challenge: reader.array()?,
            binding: reader.array()?,
        };
        reader.finish()?;
        if claims.encode()?.as_slice() != bytes {
            return Err(WireError);
        }
        Ok(claims)
    }
}
pub(super) struct PossessionProof {
    pub(super) claims: PossessionClaims,
    pub(super) signature: [u8; 64],
}
impl PossessionProof {
    pub(super) fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut output = Vec::new();
        put_lp32(&mut output, &self.claims.encode()?)?;
        output.extend_from_slice(&self.signature);
        Ok(output)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_PROOF_FRAME_BYTES - HEADER_BYTES {
            return Err(WireError);
        }
        let mut reader = Reader::new(bytes);
        let claims =
            PossessionClaims::decode(reader.lp32(MAX_PROOF_FRAME_BYTES - HEADER_BYTES - 68)?)?;
        let signature = reader.array()?;
        reader.finish()?;
        Ok(Self { claims, signature })
    }
    pub(super) fn verify_against(&self, expected: &PossessionClaims) -> Result<(), WireError> {
        let input = expected.encode()?;
        if self.claims.encode()? != input {
            return Err(WireError);
        }
        verify_signature(&expected.public_key, &input, &self.signature)
    }
}
pub(super) fn response_binding_input(
    header: &Header,
    payload: &ResultPayload,
    binding: &[u8; 32],
) -> Result<Vec<u8>, WireError> {
    if header.kind != FrameKind::Result
        || payload.encode()?.len() != header.payload_len
        || binding == &[0; 32]
    {
        return Err(WireError);
    }
    let mut output = b"openpacketcore/scope/response-binding/v1\0".to_vec();
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.push(1);
    output.extend_from_slice(&header.encode()?);
    output.extend_from_slice(&payload.nonce);
    output.push(payload.status as u8);
    output.extend_from_slice(&payload.own_execution);
    output.extend_from_slice(&hash(&payload.body));
    output.extend_from_slice(binding);
    Ok(output)
}

#[derive(Clone)]
pub(super) struct StartupRequest {
    pub(super) scope: ScopeBinding,
    pub(super) workload: [u8; 16],
    pub(super) observation: [u8; 32],
    pub(super) challenge: [u8; 32],
}
impl StartupRequest {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        let request = Self {
            scope: ScopeBinding::read(&mut reader)?,
            workload: reader.array()?,
            observation: reader.array()?,
            challenge: reader.array()?,
        };
        reader.finish()?;
        request.encode()?;
        Ok(request)
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.workload == [0; 16] || self.observation == [0; 32] || self.challenge == [0; 32] {
            return Err(WireError);
        }
        let mut output = self.scope.encode();
        output.extend_from_slice(&self.workload);
        output.extend_from_slice(&self.observation);
        output.extend_from_slice(&self.challenge);
        Ok(output)
    }
}
