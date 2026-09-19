//! Explicit, epoch-bound direct CRLs for the generic RFC 6083 endpoint.
use super::*;
use std::collections::BTreeSet;
use tokio::sync::watch;
use x509_parser::extensions::ParsedExtension;
use x509_parser::revocation_list::CertificateRevocationList;

/// Maximum complete CRLs in one publication and remembered issuer roster.
pub const MAX_CRLS: usize = 16;
/// Maximum DER bytes in one CRL, checked before parsing.
pub const MAX_CRL_BYTES: usize = 65_536;
/// Maximum combined DER bytes in one publication.
pub const MAX_CRL_SET_BYTES: usize = 262_144;

/// Closed, value-free publication failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CrlError {
    /// Bounds, encoding, freshness or the supported CRL profile was invalid.
    #[error("rfc6083_crl_profile_rejected")]
    ProfileRejected,
    /// An issuer's number/time regressed, or the same number changed contents.
    #[error("rfc6083_crl_rollback_rejected")]
    RollbackRejected,
    /// The finite publication generation was exhausted.
    #[error("rfc6083_crl_generation_exhausted")]
    GenerationExhausted,
}

/// Opaque publication generation, meaningful only within its source.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CrlGeneration(u64);
impl fmt::Debug for CrlGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CrlGeneration([redacted])")
    }
}

/// Local authority for one credential/trust epoch's revocation input.
///
/// Publish only independently obtained, current complete direct CRLs. This
/// type does not fetch peer URLs, authenticate the publisher or authorize an
/// application. CRL signatures, signer usage and full path coverage are checked
/// during peer authentication. Rotation requires a new epoch-bound publisher.
/// Failed publication, withdrawal and publisher drop invalidate existing users.
/// A per-issuer number/time floor survives withdrawal within this publisher;
/// persistence and rollback protection across process restart are caller-owned.
pub struct CrlPublisher {
    controller: TlsMaterialController,
    epoch: TlsMaterialEpoch,
    generation: u64,
    sender: watch::Sender<Option<Arc<Snapshot>>>,
    previous: Vec<Floor>,
}

impl CrlPublisher {
    /// Create an unavailable source pinned to the exact material-controller epoch.
    pub fn new(controller: &TlsMaterialController) -> Self {
        let (sender, _) = watch::channel(None);
        Self {
            controller: controller.clone(),
            epoch: controller.status().epoch(),
            generation: 0,
            sender,
            previous: Vec::new(),
        }
    }

    /// Obtain read-only input for an endpoint; this grants no publication authority.
    pub fn source(&self) -> CrlSource {
        CrlSource {
            controller: self.controller.clone(),
            epoch: self.epoch,
            receiver: self.sender.subscribe(),
        }
    }

    /// Replace the entire bounded issuer set. Any failure withdraws the source.
    ///
    /// The profile requires v2 CRLs with noncritical Authority Key Identifier
    /// (key identifier only) and CRL Number, one complete CRL per issuer, and
    /// current thisUpdate/nextUpdate. Delta, indirect, partitioned CRLs and other
    /// CRL extensions are unsupported. Revoked entries may include noncritical
    /// reason and invalidity date. CRLs and issuer identifiers are never formatted.
    pub fn publish(&mut self, der: Vec<Vec<u8>>) -> Result<CrlGeneration, CrlError> {
        let result = self.prepare(der);
        if result.is_err() {
            self.withdraw();
        }
        result
    }

    fn prepare(&mut self, der: Vec<Vec<u8>>) -> Result<CrlGeneration, CrlError> {
        let set = CrlSet::parse(der)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(CrlError::GenerationExhausted)?;
        let mut additions = 0;
        for entry in &set.entries {
            if let Some(prior) = self.previous.iter().find(|v| v.issuer == entry.issuer) {
                if entry.number < prior.number
                    || entry.since < prior.since
                    || (entry.number == prior.number && entry.der != prior.der)
                {
                    return Err(CrlError::RollbackRejected);
                }
            } else {
                additions += 1;
            }
        }
        if self.previous.len() + additions > MAX_CRLS {
            return Err(CrlError::ProfileRejected);
        }
        for entry in &set.entries {
            let floor = Floor {
                issuer: entry.issuer.clone(),
                number: entry.number,
                since: entry.since,
                der: entry.der.clone(),
            };
            if let Some(prior) = self.previous.iter_mut().find(|v| v.issuer == entry.issuer) {
                *prior = floor;
            } else {
                self.previous.push(floor);
            }
        }
        self.generation = generation;
        let generation = CrlGeneration(generation);
        self.sender
            .send_replace(Some(Arc::new(Snapshot { generation, set })));
        Ok(generation)
    }

    /// Immediately withdraw the input while retaining the issuer rollback floors.
    pub fn withdraw(&mut self) {
        self.sender.send_replace(None);
    }
}

impl fmt::Debug for CrlPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CrlPublisher([redacted])")
    }
}

struct Floor {
    issuer: Vec<u8>,
    number: [u8; 20],
    since: Timestamp,
    der: Vec<u8>,
}

/// Read-only revocation input pinned to one exact local material epoch.
#[derive(Clone)]
pub struct CrlSource {
    controller: TlsMaterialController,
    epoch: TlsMaterialEpoch,
    receiver: watch::Receiver<Option<Arc<Snapshot>>>,
}

impl fmt::Debug for CrlSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CrlSource([redacted])")
    }
}

impl CrlSource {
    pub(super) fn controller(&self) -> TlsMaterialController {
        self.controller.clone()
    }
    pub(super) fn bind(&self, epoch: TlsMaterialEpoch) -> Result<Binding, Error> {
        if epoch != self.epoch || self.receiver.has_changed().is_err() {
            return Err(Error::MaterialNotAdmitted);
        }
        let mut source = self.clone();
        let snapshot = source
            .receiver
            .borrow_and_update()
            .clone()
            .ok_or(Error::MaterialNotAdmitted)?;
        let binding = Binding { source, snapshot };
        if !binding.retained() {
            return Err(Error::MaterialNotAdmitted);
        }
        Ok(binding)
    }
}

/// Authenticated connection's exact revocation publication observation.
#[derive(Clone, Copy)]
pub struct CrlEvidence {
    generation: CrlGeneration,
    material_epoch: TlsMaterialEpoch,
    expires_at: Timestamp,
}
impl CrlEvidence {
    /// Exact generation of this connection's local revocation source.
    pub const fn generation(self) -> CrlGeneration {
        self.generation
    }
    /// Exact local credential/trust epoch to which this source was pinned.
    pub const fn material_epoch(self) -> TlsMaterialEpoch {
        self.material_epoch
    }
    /// Earliest nextUpdate across the admitted publication.
    pub const fn expires_at(self) -> Timestamp {
        self.expires_at
    }
}
impl fmt::Debug for CrlEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CrlEvidence([redacted])")
    }
}

#[derive(Clone)]
pub(super) struct Binding {
    source: CrlSource,
    pub(super) snapshot: Arc<Snapshot>,
}
impl Binding {
    pub(super) fn retained(&self) -> bool {
        self.source.receiver.has_changed().is_ok()
            && self
                .source
                .receiver
                .borrow()
                .as_ref()
                .is_some_and(|v| Arc::ptr_eq(v, &self.snapshot))
            && self.snapshot.set.current()
    }
    pub(super) fn evidence(&self) -> CrlEvidence {
        CrlEvidence {
            generation: self.snapshot.generation,
            material_epoch: self.source.epoch,
            expires_at: self.snapshot.set.until,
        }
    }
    pub(super) async fn retired(&mut self) {
        while self.retained() {
            if self.source.receiver.changed().await.is_err() {
                break;
            }
        }
    }
    pub(super) fn spawn_retirement(
        &self,
        retired: Arc<AtomicBool>,
        close: Arc<dyn SctpTransportClose>,
    ) -> RetirementTask {
        let mut binding = self.clone();
        let task_close = Arc::clone(&close);
        let task = tokio::spawn(async move {
            binding.retired().await;
            retired.store(true, Ordering::Release);
            task_close.close();
        });
        RetirementTask { task, close }
    }
}

pub(in crate::dtls) struct Snapshot {
    generation: CrlGeneration,
    set: CrlSet,
}
impl Snapshot {
    pub(in crate::dtls) fn current(&self) -> bool {
        self.set.current()
    }
    pub(in crate::dtls) fn lists(&self) -> Vec<&webpki::CertRevocationList<'static>> {
        self.set.entries.iter().map(|v| &v.parsed).collect()
    }
    pub(in crate::dtls) fn verify_identifiers(
        &self,
        path: &webpki::VerifiedPath<'_>,
        roots: &[CertificateDer<'_>],
    ) -> Result<(), DiameterTlsError> {
        self.set.verify_identifiers(path, roots)
    }
}

struct CrlSet {
    entries: Vec<Entry>,
    since: Timestamp,
    until: Timestamp,
}
struct Entry {
    der: Vec<u8>,
    parsed: webpki::CertRevocationList<'static>,
    issuer: Vec<u8>,
    key_identifier: Vec<u8>,
    number: [u8; 20],
    since: Timestamp,
}

impl CrlSet {
    fn current(&self) -> bool {
        let now = Timestamp::now_utc();
        self.since <= now && now < self.until
    }
    fn parse(der: Vec<Vec<u8>>) -> Result<Self, CrlError> {
        let invalid = || CrlError::ProfileRejected;
        if der.is_empty() || der.len() > MAX_CRLS {
            return Err(invalid());
        }
        let mut total = 0usize;
        for value in &der {
            total = total.checked_add(value.len()).ok_or_else(invalid)?;
            if value.is_empty() || value.len() > MAX_CRL_BYTES || total > MAX_CRL_SET_BYTES {
                return Err(invalid());
            }
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(der.len());
        let mut since = None;
        let mut until = None;
        for value in der {
            let (rest, crl) = CertificateRevocationList::from_der(&value).map_err(|_| invalid())?;
            if !rest.is_empty() {
                return Err(invalid());
            }
            crl.tbs_cert_list.extensions_map().map_err(|_| invalid())?;
            let mut key_identifier = None;
            let mut number = None;
            for extension in crl.extensions() {
                if extension.critical {
                    return Err(invalid());
                }
                match extension.parsed_extension() {
                    ParsedExtension::AuthorityKeyIdentifier(aki) => {
                        let key = aki.key_identifier.as_ref().ok_or_else(invalid)?;
                        if key.0.is_empty()
                            || key.0.len() > 64
                            || aki.authority_cert_issuer.is_some()
                            || aki.authority_cert_serial.is_some()
                        {
                            return Err(invalid());
                        }
                        key_identifier = Some(key.0.to_vec());
                    }
                    ParsedExtension::CRLNumber(v) => {
                        let bytes = v.to_bytes_be();
                        if bytes.len() > 20 {
                            return Err(invalid());
                        }
                        let mut bounded = [0u8; 20];
                        bounded[20 - bytes.len()..].copy_from_slice(&bytes);
                        number = Some(bounded);
                    }
                    _ => return Err(invalid()),
                }
            }
            let mut serials = BTreeSet::new();
            for revoked in crl.iter_revoked_certificates() {
                if !serials.insert(revoked.raw_serial()) {
                    return Err(invalid());
                }
                revoked.extensions_map().map_err(|_| invalid())?;
                for extension in revoked.extensions() {
                    if extension.critical
                        || !matches!(
                            extension.parsed_extension(),
                            ParsedExtension::ReasonCode(_) | ParsedExtension::InvalidityDate(_)
                        )
                    {
                        return Err(invalid());
                    }
                }
            }
            let first = timestamp(crl.last_update().timestamp())?;
            let last = timestamp(crl.next_update().ok_or_else(invalid)?.timestamp())?;
            let now = Timestamp::now_utc();
            if first > now || last <= now || first >= last {
                return Err(invalid());
            }
            let issuer = crl.issuer().as_raw().to_vec();
            if entries.iter().any(|v| v.issuer == issuer) {
                return Err(invalid());
            }
            since = Some(since.map_or(first, |v: Timestamp| v.max(first)));
            until = Some(until.map_or(last, |v: Timestamp| v.min(last)));
            let parsed = webpki::OwnedCertRevocationList::from_der(&value)
                .map_err(|_| invalid())?
                .into();
            entries.push(Entry {
                parsed,
                issuer,
                key_identifier: key_identifier.ok_or_else(invalid)?,
                number: number.ok_or_else(invalid)?,
                since: first,
                der: value,
            });
        }
        Ok(Self {
            entries,
            since: since.ok_or_else(invalid)?,
            until: until.ok_or_else(invalid)?,
        })
    }

    fn verify_identifiers(
        &self,
        path: &webpki::VerifiedPath<'_>,
        roots: &[CertificateDer<'_>],
    ) -> Result<(), DiameterTlsError> {
        let fail = || DiameterTlsError::Authentication;
        let mut certificates = vec![path.end_entity().der()];
        certificates.extend(path.intermediate_certificates().map(|v| v.der()));
        let checked = certificates.len();
        let root = roots
            .iter()
            .find(|root| webpki::anchor_from_trusted_cert(root).is_ok_and(|v| v == *path.anchor()))
            .ok_or_else(fail)?;
        certificates.push(root.clone());
        let parsed = certificates
            .iter()
            .map(|value| {
                let (rest, cert) = X509Certificate::from_der(value).map_err(|_| fail())?;
                if !rest.is_empty() {
                    return Err(fail());
                }
                Ok(cert)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for cert in &parsed[..checked] {
            let entry = self
                .entries
                .iter()
                .find(|v| v.issuer == cert.issuer().as_raw())
                .ok_or_else(fail)?;
            let mut issuers = parsed.iter().filter(|v| v.subject() == cert.issuer());
            let issuer = issuers.next().ok_or_else(fail)?;
            if issuers.next().is_some() {
                return Err(fail());
            }
            // WebPKI's trust-anchor representation omits KeyUsage. Check
            // the actual selected issuer certificate, including the root.
            if !issuer
                .key_usage()
                .map_err(|_| fail())?
                .ok_or_else(fail)?
                .value
                .crl_sign()
            {
                return Err(fail());
            }
            let key_ids: Vec<_> = issuer
                .extensions()
                .iter()
                .filter_map(|v| match v.parsed_extension() {
                    ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0),
                    _ => None,
                })
                .collect();
            if key_ids.len() != 1 || key_ids[0] != entry.key_identifier {
                return Err(fail());
            }
        }
        Ok(())
    }
}

fn timestamp(seconds: i64) -> Result<Timestamp, CrlError> {
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map(Timestamp::from_offset_datetime)
        .map_err(|_| CrlError::ProfileRejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generation_exhaustion_withdraws_and_cannot_wrap() {
        let (_sender, receiver) = watch::channel(None);
        let controller = TlsMaterialController::new(receiver);
        let mut publisher = CrlPublisher::new(&controller);
        let row = include_str!("../../../tests/fixtures/rfc6083/revocation.tsv")
            .lines()
            .find(|v| v.starts_with("server\tvalid\t"))
            .unwrap();
        let decode = |value: &str| {
            value
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        let der: Vec<_> = row
            .split('\t')
            .nth(7)
            .unwrap()
            .split(',')
            .map(decode)
            .collect();
        publisher.publish(der.clone()).unwrap();
        publisher.generation = u64::MAX;
        for _ in 0..2 {
            assert_eq!(
                publisher.publish(der.clone()).err(),
                Some(CrlError::GenerationExhausted)
            );
            assert!(publisher.sender.borrow().is_none());
        }
    }
}
