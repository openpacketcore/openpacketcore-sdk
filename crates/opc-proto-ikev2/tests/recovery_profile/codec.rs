//! Strict test-only complete-row format. Fresh install only; no default reader.
//! Secret encoding buffers reserve their full bound and zeroize on drop.

use super::{
    envelope::Error,
    row::*,
    store::{RowKey, Version},
};
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{
        Ikev2CommittedExchangeRecord as Exchange, Ikev2ReservationRetryPolicy as RetryPolicy,
        Ikev2SyncClock as Clock, Ikev2SyncDisposition as Disposition,
        Ikev2SyncRecoveryPolicy as Policy, Ikev2SyncRecoveryStatus as Status,
    },
    Ikev2AesGcmIvLimits as Limits, Ikev2DhGroup as Group, Ikev2MessageIdSync as Notify,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncPending as Pending, Ikev2MessageIdSyncRole as Role,
    Ikev2MessageIdSyncSa as Sa, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const MAX_ROW: usize = 64 * 1024;

struct Writer {
    bytes: Zeroizing<Vec<u8>>,
    failed: bool,
}
impl Writer {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(MAX_ROW)),
            failed: false,
        }
    }
    fn raw(&mut self, bytes: &[u8]) {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|len| len > MAX_ROW)
        {
            self.failed = true;
        } else if !self.failed {
            self.bytes.extend_from_slice(bytes);
        }
    }
    fn u8(&mut self, value: u8) {
        self.raw(&[value]);
    }
    fn u16(&mut self, value: u16) {
        self.raw(&value.to_be_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.raw(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.raw(&value.to_be_bytes());
    }
    fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }
    fn bytes(&mut self, value: &[u8]) {
        match u32::try_from(value.len()) {
            Ok(len) => self.u32(len),
            Err(_) => self.failed = true,
        }
        self.raw(value);
    }
    fn opt32(&mut self, value: Option<u32>) {
        self.boolean(value.is_some());
        if let Some(value) = value {
            self.u32(value);
        }
    }
    fn opt64(&mut self, value: Option<u64>) {
        self.boolean(value.is_some());
        if let Some(value) = value {
            self.u64(value);
        }
    }
    fn opt_bytes(&mut self, value: Option<&[u8]>) {
        self.boolean(value.is_some());
        if let Some(value) = value {
            self.bytes(value);
        }
    }
    fn field(&mut self, tag: u8, write: impl FnOnce(&mut Writer)) -> Result<(), Error> {
        let mut value = Self::new();
        write(&mut value);
        let value = value.finish()?;
        self.u8(tag);
        self.bytes(&value);
        Ok(())
    }
    fn finish(self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.failed {
            Err(Error::Format)
        } else {
            Ok(self.bytes)
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .cursor
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(Error::Format)?;
        let out = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Format)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Format)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Format)?,
        ))
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Format),
        }
    }
    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let len = usize::try_from(self.u32()?).map_err(|_| Error::Format)?;
        self.take(len)
    }
    fn opt32(&mut self) -> Result<Option<u32>, Error> {
        if self.boolean()? {
            Ok(Some(self.u32()?))
        } else {
            Ok(None)
        }
    }
    fn opt64(&mut self) -> Result<Option<u64>, Error> {
        if self.boolean()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }
    fn opt_bytes(&mut self) -> Result<Option<&'a [u8]>, Error> {
        if self.boolean()? {
            Ok(Some(self.bytes()?))
        } else {
            Ok(None)
        }
    }
    fn end(self) -> Result<(), Error> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Format)
        }
    }
}

struct Fields<'a>(BTreeMap<u8, &'a [u8]>);
impl<'a> Fields<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_ROW {
            return Err(Error::Format);
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != b"IKER" || r.u16()? != 1 {
            return Err(Error::Format);
        }
        let mut fields = BTreeMap::new();
        while r.cursor < r.bytes.len() {
            let tag = r.u8()?;
            let value = r.bytes()?;
            if !(1..=14).contains(&tag) || fields.insert(tag, value).is_some() {
                return Err(Error::Format);
            }
        }
        Ok(Self(fields))
    }
    fn required(&mut self, tag: u8) -> Result<Reader<'a>, Error> {
        self.0.remove(&tag).map(Reader::new).ok_or(Error::Format)
    }
}

fn mode(mode: Mode) -> u8 {
    match mode {
        Mode::BaseFallback => 0,
        Mode::Negotiated => 1,
    }
}
fn read_mode(r: &mut Reader<'_>) -> Result<Mode, Error> {
    match r.u8()? {
        0 => Ok(Mode::BaseFallback),
        1 => Ok(Mode::Negotiated),
        _ => Err(Error::Format),
    }
}
fn agreement(w: &mut Writer, agreement: Agreement, expected: Sa) {
    // Every agreement/attempt belongs to the row's one explicit SPI/role tuple.
    // Check before projection instead of silently rebinding a foreign value.
    if agreement.sa() != expected {
        w.failed = true;
    }
    w.u8(mode(agreement.mode()));
}
fn read_agreement(r: &mut Reader<'_>, sa: Sa) -> Result<Agreement, Error> {
    Ok(Agreement::from_persisted(sa, read_mode(r)?))
}
fn exchange(w: &mut Writer, exchange: Option<&Exchange>) {
    w.boolean(exchange.is_some());
    if let Some(e) = exchange {
        w.bytes(e.request());
        w.opt_bytes(e.response());
        w.opt_bytes(e.outcome());
    }
}
fn read_exchange(r: &mut Reader<'_>) -> Result<Option<Exchange>, Error> {
    if !r.boolean()? {
        return Ok(None);
    }
    Exchange::from_persisted(
        Bytes::copy_from_slice(r.bytes()?),
        r.opt_bytes()?.map(Bytes::copy_from_slice),
        r.opt_bytes()?.map(Bytes::copy_from_slice),
    )
    .map(Some)
    .map_err(|_| Error::Format)
}

pub struct ProfileCodec;
impl ProfileCodec {
    pub fn encode(row: &Row) -> Result<Zeroizing<Vec<u8>>, Error> {
        if row.profile.encryption().is_aead() {
            row.gcm()?;
        } else {
            row.cbc()?;
        }
        let mut out = Writer::new();
        out.raw(b"IKER");
        out.u16(1);
        out.field(1, |w| {
            w.u64(row.key.0);
            w.u64(row.version.birth);
            w.u64(row.version.generation);
            w.u64(row.sealed_stamp);
        })?;
        out.field(2, |w| {
            w.u64(row.spis.0);
            w.u64(row.spis.1);
            w.u8(match row.direction {
                Direction::InitiatorToResponder => 0,
                Direction::ResponderToInitiator => 1,
            });
            w.u16(row.profile.prf().transform_id());
            w.u16(row.profile.dh_group().transform_id());
            w.u16(row.profile.encryption().transform_id());
            w.u16(row.profile.encryption().key_bits());
            w.boolean(row.profile.integrity().is_some());
            if let Some(i) = row.profile.integrity() {
                w.u16(i.transform_id());
            }
            w.boolean(row.marker.is_some());
            if let Some(marker) = row.marker {
                w.u8(marker);
            }
        })?;
        out.field(3, |w| {
            w.boolean(row.keys.ppk_applied());
            for key in [
                row.keys.sk_d(),
                row.keys.sk_ai(),
                row.keys.sk_ar(),
                row.keys.sk_ei(),
                row.keys.sk_er(),
                row.keys.sk_pi(),
                row.keys.sk_pr(),
            ] {
                w.bytes(key);
            }
        })?;
        let sa = row.agreement.sa();
        out.field(4, |w| agreement(w, row.agreement, sa))?;
        out.field(5, |w| w.u8(mode(row.mode)))?;
        out.field(6, |w| {
            let image = &row.window;
            w.u64(image.generation);
            w.opt32(image.next_send);
            w.opt32(image.next_receive);
            exchange(w, image.outbound.as_ref());
            exchange(w, image.inbound.as_ref());
        })?;
        out.field(7, |w| {
            w.boolean(row.window.sync.is_some());
            if let Some(s) = &row.window.sync {
                agreement(w, s.agreement, sa);
                w.opt32(s.local_request);
                w.opt32(s.peer_request);
                w.opt32(s.local_proposal);
                w.opt32(s.peer_proposal);
                let disposition = match s.disposition {
                    Disposition::Continue => 0,
                    Disposition::AwaitLocalSync => 1,
                    Disposition::OutcomeUncertain => 2,
                    Disposition::CloseIkeSa => 3,
                    _ => {
                        w.failed = true;
                        255
                    }
                };
                w.u8(disposition);
                w.opt64(s.minimum_iv_end);
            }
        })?;
        out.field(8, |w| {
            w.boolean(row.window.recovery.is_some());
            if let Some(r) = &row.window.recovery {
                let p = r.policy;
                w.u64(p.operation());
                w.u64(p.started().unix_ms());
                w.u64(p.started().epoch());
                w.u64(p.deadline_unix_ms());
                w.u8(p.max_attempts());
                w.u64(p.retry_delay_ms());
                w.u64(r.observed);
                let status = match r.status {
                    Status::Pending => 0,
                    Status::Recovered => 1,
                    Status::Closed => 2,
                    _ => {
                        w.failed = true;
                        255
                    }
                };
                w.u8(status);
                if r.attempts.len() > 3 {
                    w.failed = true;
                    return;
                }
                w.u8(u8::try_from(r.attempts.len()).unwrap());
                for a in &r.attempts {
                    if a.pending.sa() != sa {
                        w.failed = true;
                    }
                    let n = a.pending.notification();
                    w.raw(&n.nonce());
                    w.u32(n.expected_send_req_message_id());
                    w.u32(n.expected_recv_req_message_id());
                    w.u64(a.prepared);
                    w.bytes(&a.request);
                }
            }
        })?;
        out.field(9, |w| {
            w.boolean(row.iv.is_some());
            if let Some(iv) = &row.iv {
                w.u64(iv.limits.hard_ceiling());
                let (a, b, c) = iv.limits.control_budget();
                w.u32(a);
                w.u32(b);
                w.u32(c);
                w.u64(iv.end);
                let Ok(count) = u16::try_from(iv.retries.len()) else {
                    w.failed = true;
                    return;
                };
                w.u16(count);
                for (&id, retry) in &iv.retries {
                    w.u64(id);
                    let p = retry.policy;
                    w.u64(p.started_unix_ms());
                    w.u64(p.deadline_unix_ms());
                    w.u8(p.max_attempts());
                    w.u64(p.backoff_ms());
                    w.u8(retry.attempts);
                    w.opt64(retry.last_attempt);
                }
            }
        })?;
        out.field(10, |w| {
            let Ok(count) = u16::try_from(row.operations.len()) else {
                w.failed = true;
                return;
            };
            w.u16(count);
            for (&id, op) in &row.operations {
                w.u64(id);
                w.u8(match op.kind {
                    KeKind::NewChild => 0,
                    KeKind::ChildRekey => 1,
                    KeKind::IkeRekey => 2,
                });
                w.boolean(op.initiated_here);
                w.u16(op.group.transform_id());
                w.bytes(&op.public);
                w.bytes(&op.nonce_i);
                w.bytes(&op.nonce_r);
                w.u64(op.spis.0);
                w.u64(op.spis.1);
                w.u8(op.first_payload);
                w.bytes(&op.transcript);
                w.u8(match op.outcome {
                    Outcome::Pending => 0,
                    Outcome::Success => 1,
                    Outcome::CrossedLoss => 2,
                    Outcome::RetryBudget => 3,
                    Outcome::Abandoned => 4,
                    Outcome::Uncertain => 5,
                    Outcome::Teardown => 6,
                    Outcome::PeerKeRejected => 7,
                    Outcome::PeerKeDeleted => 8,
                    Outcome::InvalidSyntax => 9,
                });
                w.opt_bytes(op.checkpoint.as_ref().map(|b| b.as_slice()));
                w.opt_bytes(op.derived.as_ref().map(|b| b.as_slice()));
            }
        })?;
        out.field(11, |w| {
            w.u64(row.identity);
            w.u64(row.namespace);
            w.boolean(row.endpoint.is_some());
            if let Some((address, port)) = row.endpoint {
                w.u32(address);
                w.u16(port);
            }
            w.boolean(row.closed);
        })?;
        out.field(12, |w| {
            for intent in &row.sync_intents {
                w.boolean(intent.is_some());
                if let Some(intent) = intent {
                    let policy = intent.policy;
                    w.u64(policy.operation());
                    w.u64(policy.started().unix_ms());
                    w.u64(policy.started().epoch());
                    w.u64(policy.deadline_unix_ms());
                    w.u8(policy.max_attempts());
                    w.u64(policy.retry_delay_ms());
                    w.u64(intent.observed);
                    w.boolean(intent.pending);
                }
            }
        })?;
        out.field(13, |w| {
            w.boolean(row.challenge.is_some());
            if let Some(challenge) = &row.challenge {
                w.u32(challenge.destination.0);
                w.u16(challenge.destination.1);
                w.bytes(&challenge.request);
            }
        })?;
        out.field(14, |w| {
            w.boolean(row.contact_auth.is_some());
            if let Some(auth) = &row.contact_auth {
                w.bytes(auth);
            }
            w.u32(u32::try_from(row.contact_cleanup.len()).unwrap_or(u32::MAX));
            for victim in &row.contact_cleanup {
                w.u64(victim.key.0);
                w.u64(victim.birth);
                w.u64(victim.identity);
                w.u64(victim.namespace);
            }
        })?;
        out.finish()
    }

    pub fn decode(
        bytes: &[u8],
        expected_key: RowKey,
        expected_version: Version,
        expected_stamp: u64,
    ) -> Result<Row, Error> {
        let mut fields = Fields::parse(bytes)?;
        let mut r = fields.required(1)?;
        let key = RowKey(r.u64()?);
        let version = Version {
            birth: r.u64()?,
            generation: r.u64()?,
        };
        let sealed_stamp = r.u64()?;
        r.end()?;
        if key != expected_key || version != expected_version || sealed_stamp != expected_stamp {
            return Err(Error::Format);
        }
        let mut r = fields.required(2)?;
        let spis = (r.u64()?, r.u64()?);
        let direction = match r.u8()? {
            0 => Direction::InitiatorToResponder,
            1 => Direction::ResponderToInitiator,
            _ => return Err(Error::Format),
        };
        let role = if direction == Direction::InitiatorToResponder {
            Role::Initiator
        } else {
            Role::Responder
        };
        let sa = Sa::new(spis.0, spis.1, role).map_err(|_| Error::Format)?;
        let (prf, group, encryption, bits) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
        let integrity = if r.boolean()? { Some(r.u16()?) } else { None };
        let profile = Profile::from_transform_ids(prf, group, encryption, Some(bits), integrity)
            .map_err(|_| Error::Format)?;
        let marker = if r.boolean()? { Some(r.u8()?) } else { None };
        r.end()?;
        let mut r = fields.required(3)?;
        let ppk = r.boolean()?;
        let keys = Keys::from_established_keys(
            profile,
            ppk,
            r.bytes()?,
            r.bytes()?,
            r.bytes()?,
            r.bytes()?,
            r.bytes()?,
            r.bytes()?,
            r.bytes()?,
        )
        .map_err(|_| Error::Format)?;
        r.end()?;
        let mut r = fields.required(4)?;
        let agreement = read_agreement(&mut r, sa)?;
        r.end()?;
        let mut r = fields.required(5)?;
        let mode = read_mode(&mut r)?;
        r.end()?;
        let mut r = fields.required(6)?;
        let mut window = WindowImage {
            generation: r.u64()?,
            next_send: r.opt32()?,
            next_receive: r.opt32()?,
            outbound: read_exchange(&mut r)?,
            inbound: read_exchange(&mut r)?,
            sync: None,
            recovery: None,
        };
        r.end()?;
        let mut r = fields.required(7)?;
        if r.boolean()? {
            let agreement = read_agreement(&mut r, sa)?;
            let (local_request, peer_request, local_proposal, peer_proposal) =
                (r.opt32()?, r.opt32()?, r.opt32()?, r.opt32()?);
            let disposition = match r.u8()? {
                0 => Disposition::Continue,
                1 => Disposition::AwaitLocalSync,
                2 => Disposition::OutcomeUncertain,
                3 => Disposition::CloseIkeSa,
                _ => return Err(Error::Format),
            };
            window.sync = Some(SyncImage {
                agreement,
                local_request,
                peer_request,
                local_proposal,
                peer_proposal,
                disposition,
                minimum_iv_end: r.opt64()?,
            });
        }
        r.end()?;
        let mut r = fields.required(8)?;
        if r.boolean()? {
            let (operation, started, epoch, deadline) = (r.u64()?, r.u64()?, r.u64()?, r.u64()?);
            let policy = Policy::new(
                operation,
                Clock::new(started, epoch),
                deadline,
                r.u8()?,
                r.u64()?,
            )
            .map_err(|_| Error::Format)?;
            let observed = r.u64()?;
            let status = match r.u8()? {
                0 => Status::Pending,
                1 => Status::Recovered,
                2 => Status::Closed,
                _ => return Err(Error::Format),
            };
            let count = r.u8()?;
            if count > 3 {
                return Err(Error::Format);
            }
            let mut attempts = Vec::new();
            for _ in 0..count {
                let nonce = r.take(4)?.try_into().map_err(|_| Error::Format)?;
                let notification = Notify::new(nonce, r.u32()?, r.u32()?);
                let pending =
                    Pending::from_persisted(sa, notification).map_err(|_| Error::Format)?;
                attempts.push(AttemptImage {
                    pending,
                    prepared: r.u64()?,
                    request: Bytes::copy_from_slice(r.bytes()?),
                });
            }
            window.recovery = Some(RecoveryImage {
                policy,
                observed,
                attempts,
                status,
            });
        }
        r.end()?;
        let mut r = fields.required(9)?;
        let iv = if r.boolean()? {
            let limits =
                Limits::new(r.u64()?, r.u32()?, r.u32()?, r.u32()?).map_err(|_| Error::Format)?;
            let end = r.u64()?;
            let count = r.u16()?;
            let mut retries = BTreeMap::new();
            for _ in 0..count {
                let operation = r.u64()?;
                let policy = RetryPolicy::new(r.u64()?, r.u64()?, r.u8()?, r.u64()?)
                    .map_err(|_| Error::Format)?;
                let retry = RetryImage {
                    operation,
                    policy,
                    attempts: r.u8()?,
                    last_attempt: r.opt64()?,
                };
                if retries.insert(operation, retry).is_some() {
                    return Err(Error::Format);
                }
            }
            Some(IvImage {
                limits,
                end,
                retries,
            })
        } else {
            None
        };
        r.end()?;
        let mut r = fields.required(10)?;
        let count = r.u16()?;
        let mut operations = BTreeMap::new();
        for _ in 0..count {
            let id = r.u64()?;
            let kind = match r.u8()? {
                0 => KeKind::NewChild,
                1 => KeKind::ChildRekey,
                2 => KeKind::IkeRekey,
                _ => return Err(Error::Format),
            };
            let initiated_here = r.boolean()?;
            let group = Group::from_transform_id(r.u16()?).map_err(|_| Error::Format)?;
            let public = r.bytes()?.to_vec();
            let nonce_i = r.bytes()?.to_vec();
            let nonce_r = r.bytes()?.to_vec();
            let spis = (r.u64()?, r.u64()?);
            let first_payload = r.u8()?;
            let transcript = Bytes::copy_from_slice(r.bytes()?);
            let outcome = match r.u8()? {
                0 => Outcome::Pending,
                1 => Outcome::Success,
                2 => Outcome::CrossedLoss,
                3 => Outcome::RetryBudget,
                4 => Outcome::Abandoned,
                5 => Outcome::Uncertain,
                6 => Outcome::Teardown,
                7 => Outcome::PeerKeRejected,
                8 => Outcome::PeerKeDeleted,
                9 => Outcome::InvalidSyntax,
                _ => return Err(Error::Format),
            };
            let checkpoint = r.opt_bytes()?.map(|b| Zeroizing::new(b.to_vec()));
            let derived = r.opt_bytes()?.map(|b| Zeroizing::new(b.to_vec()));
            let operation = Operation {
                id,
                kind,
                initiated_here,
                group,
                public,
                nonce_i,
                nonce_r,
                spis,
                first_payload,
                transcript,
                checkpoint,
                outcome,
                derived,
            };
            if operations.insert(id, operation).is_some() {
                return Err(Error::Format);
            }
        }
        r.end()?;
        let mut r = fields.required(11)?;
        let (identity, namespace) = (r.u64()?, r.u64()?);
        let endpoint = if r.boolean()? {
            Some((r.u32()?, r.u16()?))
        } else {
            None
        };
        let closed = r.boolean()?;
        r.end()?;
        let mut r = fields.required(12)?;
        let mut sync_intents = [None, None];
        for intent in &mut sync_intents {
            if r.boolean()? {
                let operation = r.u64()?;
                let started = Clock::new(r.u64()?, r.u64()?);
                let policy = Policy::new(operation, started, r.u64()?, r.u8()?, r.u64()?)
                    .map_err(|_| Error::Format)?;
                *intent = Some(SyncIntent {
                    policy,
                    observed: r.u64()?,
                    pending: r.boolean()?,
                });
            }
        }
        r.end()?;
        let mut r = fields.required(13)?;
        let challenge = if r.boolean()? {
            Some(Challenge {
                destination: (r.u32()?, r.u16()?),
                request: Bytes::copy_from_slice(r.bytes()?),
            })
        } else {
            None
        };
        r.end()?;
        let mut r = fields.required(14)?;
        let contact_auth = if r.boolean()? {
            Some(Bytes::copy_from_slice(r.bytes()?))
        } else {
            None
        };
        let count = usize::try_from(r.u32()?).map_err(|_| Error::Format)?;
        if count > MAX_ROW / 32 {
            return Err(Error::Format);
        }
        let mut contact_cleanup = Vec::with_capacity(count);
        for _ in 0..count {
            contact_cleanup.push(ContactVictim {
                key: RowKey(r.u64()?),
                birth: r.u64()?,
                identity: r.u64()?,
                namespace: r.u64()?,
            });
        }
        r.end()?;
        let row = Row {
            key,
            version,
            sealed_stamp,
            spis,
            direction,
            profile,
            keys,
            agreement,
            mode,
            marker,
            iv,
            window,
            operations,
            sync_intents,
            identity,
            namespace,
            endpoint,
            challenge,
            contact_cleanup,
            contact_auth,
            closed,
        };
        if row.profile.encryption().is_aead() {
            row.gcm()?;
        } else {
            row.cbc()?;
        }
        Ok(row)
    }

    /// Malformed consumer input for omission tests; preserves all other fields.
    pub fn without_field(encoded: &[u8], omitted: u8) -> Zeroizing<Vec<u8>> {
        let fields = Fields::parse(encoded).unwrap();
        let mut out = Writer::new();
        out.raw(b"IKER");
        out.u16(1);
        for (tag, value) in fields.0 {
            if tag != omitted {
                out.u8(tag);
                out.bytes(value);
            }
        }
        out.finish().unwrap()
    }
}
