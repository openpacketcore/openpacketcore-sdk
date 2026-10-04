use zeroize::Zeroizing;

use super::{
    CandidateImage, CleanupImage, CoverageMember, CoverageRecord, InventoryError, InventoryRecord,
    ObjectPhase, ObjectRecord, RecordLink, TransactionFamily, CANDIDATES_PER_OBJECT,
    COVERAGE_MEMBERS, POLICY_TEMPLATES,
};
use crate::{
    IpAddress, PolicyParameters, SaRelocationIdentity, SaRelocationSelector, UdpEncap, XfrmAction,
    XfrmDirection, XfrmId, XfrmLookupMark, XfrmMark, XfrmMode, XfrmRequestId, XfrmSelector,
    XfrmTemplate,
};

pub(super) struct Encoder {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl Encoder {
    pub(super) fn new(limit: usize) -> Result<Self, InventoryError> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(limit)
            .map_err(|_| InventoryError::Allocation)?;
        Ok(Self { bytes, limit })
    }

    pub(super) fn bytes(&mut self, value: &[u8]) -> Result<(), InventoryError> {
        if self
            .bytes
            .len()
            .checked_add(value.len())
            .is_none_or(|length| length > self.limit)
        {
            return Err(InventoryError::Capacity);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn u8(&mut self, value: u8) -> Result<(), InventoryError> {
        self.bytes(&[value])
    }

    pub(super) fn u16(&mut self, value: u16) -> Result<(), InventoryError> {
        self.bytes(&value.to_be_bytes())
    }

    pub(super) fn u32(&mut self, value: u32) -> Result<(), InventoryError> {
        self.bytes(&value.to_be_bytes())
    }

    pub(super) fn u64(&mut self, value: u64) -> Result<(), InventoryError> {
        self.bytes(&value.to_be_bytes())
    }

    fn optional<T>(
        &mut self,
        value: Option<T>,
        encode: impl FnOnce(&mut Self, T) -> Result<(), InventoryError>,
    ) -> Result<(), InventoryError> {
        self.u8(u8::from(value.is_some()))?;
        if let Some(value) = value {
            encode(self, value)?;
        }
        Ok(())
    }

    fn address(&mut self, value: IpAddress) -> Result<(), InventoryError> {
        match value {
            IpAddress::Ipv4(bytes) => {
                self.u8(4)?;
                self.bytes(&bytes)
            }
            IpAddress::Ipv6(bytes) => {
                self.u8(6)?;
                self.bytes(&bytes)
            }
        }
    }

    fn id(&mut self, value: XfrmId) -> Result<(), InventoryError> {
        self.address(value.destination)?;
        self.u32(value.spi)?;
        self.u8(value.protocol)
    }

    fn mode(&mut self, value: XfrmMode) -> Result<(), InventoryError> {
        self.u8(match value {
            XfrmMode::Transport => 0,
            XfrmMode::Tunnel => 1,
            XfrmMode::Beet => 2,
        })
    }

    fn selector(&mut self, value: &XfrmSelector) -> Result<(), InventoryError> {
        self.address(value.source)?;
        self.address(value.destination)?;
        self.u16(value.source_port)?;
        self.u16(value.destination_port)?;
        self.u8(value.protocol)?;
        self.u8(value.source_prefix_len)?;
        self.u8(value.destination_prefix_len)
    }

    fn mark(&mut self, value: Option<XfrmLookupMark>) -> Result<(), InventoryError> {
        self.optional(value, |encoder, mark| {
            encoder.u32(mark.value())?;
            encoder.u32(mark.mask())
        })
    }

    fn request_id(&mut self, value: Option<XfrmRequestId>) -> Result<(), InventoryError> {
        self.u32(value.map_or(0, XfrmRequestId::get))
    }

    fn link(&mut self, value: RecordLink) -> Result<(), InventoryError> {
        self.u32(value.position)?;
        self.u64(value.serial)
    }

    fn image(&mut self, image: &CleanupImage) -> Result<(), InventoryError> {
        match image {
            CleanupImage::Sa {
                identity,
                immutable_fingerprint,
            } => {
                self.u8(1)?;
                self.selector(&identity.selector.selector())?;
                self.u16(identity.selector.source_port_mask)?;
                self.u16(identity.selector.destination_port_mask)?;
                self.bytes(&identity.selector.ifindex.to_be_bytes())?;
                self.u32(identity.selector.user_id)?;
                self.id(identity.id)?;
                self.address(identity.source_address)?;
                self.request_id(identity.request_id)?;
                self.mode(identity.mode)?;
                self.optional(identity.encap, |encoder, encap| {
                    encoder.u16(encap.encap_type)?;
                    encoder.u16(encap.source_port)?;
                    encoder.u16(encap.destination_port)
                })?;
                self.mark(identity.mark)?;
                self.optional(identity.if_id, Self::u32)?;
                self.optional(identity.output_mark, |encoder, mark| {
                    encoder.u32(mark.value)?;
                    encoder.u32(mark.mask)
                })?;
                self.bytes(immutable_fingerprint)
            }
            CleanupImage::Policy(policy) => {
                self.u8(2)?;
                self.selector(&policy.selector)?;
                self.u8(match policy.direction {
                    XfrmDirection::In => 0,
                    XfrmDirection::Out => 1,
                    XfrmDirection::Forward => 2,
                })?;
                self.u8(match policy.action {
                    XfrmAction::Allow => 0,
                    XfrmAction::Block => 1,
                })?;
                self.u32(policy.priority)?;
                self.u8(
                    u8::try_from(policy.templates.len()).map_err(|_| InventoryError::Capacity)?
                )?;
                for template in &policy.templates {
                    self.id(template.id)?;
                    self.address(template.source_address)?;
                    self.request_id(template.request_id)?;
                    self.mode(template.mode)?;
                }
                self.mark(policy.mark)?;
                self.optional(policy.if_id, Self::u32)
            }
        }
    }

    pub(super) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

pub(super) struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub(super) fn new(bytes: &'a [u8], limit: usize) -> Result<Self, InventoryError> {
        if bytes.len() > limit {
            return Err(InventoryError::Capacity);
        }
        Ok(Self { bytes, position: 0 })
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], InventoryError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(InventoryError::Malformed)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(InventoryError::Malformed)?;
        self.position = end;
        Ok(bytes)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], InventoryError> {
        self.take(N)?
            .try_into()
            .map_err(|_| InventoryError::Malformed)
    }

    pub(super) fn u8(&mut self) -> Result<u8, InventoryError> {
        Ok(self.array::<1>()?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, InventoryError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(super) fn u32(&mut self) -> Result<u32, InventoryError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, InventoryError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn optional<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, InventoryError>,
    ) -> Result<Option<T>, InventoryError> {
        match self.u8()? {
            0 => Ok(None),
            1 => decode(self).map(Some),
            _ => Err(InventoryError::Malformed),
        }
    }

    fn address(&mut self) -> Result<IpAddress, InventoryError> {
        match self.u8()? {
            4 => Ok(IpAddress::Ipv4(self.array()?)),
            6 => Ok(IpAddress::Ipv6(self.array()?)),
            _ => Err(InventoryError::Malformed),
        }
    }

    fn id(&mut self) -> Result<XfrmId, InventoryError> {
        Ok(XfrmId {
            destination: self.address()?,
            spi: self.u32()?,
            protocol: self.u8()?,
        })
    }

    fn mode(&mut self) -> Result<XfrmMode, InventoryError> {
        match self.u8()? {
            0 => Ok(XfrmMode::Transport),
            1 => Ok(XfrmMode::Tunnel),
            2 => Ok(XfrmMode::Beet),
            _ => Err(InventoryError::Malformed),
        }
    }

    fn selector(&mut self) -> Result<XfrmSelector, InventoryError> {
        let value = XfrmSelector {
            source: self.address()?,
            destination: self.address()?,
            source_port: self.u16()?,
            destination_port: self.u16()?,
            protocol: self.u8()?,
            source_prefix_len: self.u8()?,
            destination_prefix_len: self.u8()?,
        };
        validate_selector(&value)?;
        Ok(value)
    }

    fn mark(&mut self) -> Result<Option<XfrmLookupMark>, InventoryError> {
        self.optional(|decoder| {
            XfrmLookupMark::new(decoder.u32()?, decoder.u32()?)
                .map_err(|_| InventoryError::Malformed)
        })
    }

    fn request_id(&mut self) -> Result<Option<XfrmRequestId>, InventoryError> {
        Ok(XfrmRequestId::new(self.u32()?))
    }

    fn link(&mut self) -> Result<RecordLink, InventoryError> {
        let link = RecordLink {
            position: self.u32()?,
            serial: self.u64()?,
        };
        if link.serial == 0 {
            return Err(InventoryError::Malformed);
        }
        Ok(link)
    }

    fn image(&mut self) -> Result<CleanupImage, InventoryError> {
        match self.u8()? {
            1 => {
                let selector = self.selector()?;
                let selector = SaRelocationSelector {
                    source_port_mask: self.u16()?,
                    destination_port_mask: self.u16()?,
                    ifindex: i32::from_be_bytes(self.array()?),
                    user_id: self.u32()?,
                    ..SaRelocationSelector::from_selector(&selector)
                };
                Ok(CleanupImage::Sa {
                    identity: SaRelocationIdentity {
                        selector,
                        id: self.id()?,
                        source_address: self.address()?,
                        request_id: self.request_id()?,
                        mode: self.mode()?,
                        encap: self.optional(|decoder| {
                            Ok(UdpEncap {
                                encap_type: decoder.u16()?,
                                source_port: decoder.u16()?,
                                destination_port: decoder.u16()?,
                            })
                        })?,
                        mark: self.mark()?,
                        if_id: self.optional(Self::u32)?,
                        output_mark: self.optional(|decoder| {
                            Ok(XfrmMark {
                                value: decoder.u32()?,
                                mask: decoder.u32()?,
                            })
                        })?,
                    },
                    immutable_fingerprint: self.array()?,
                })
            }
            2 => {
                let selector = self.selector()?;
                let direction = match self.u8()? {
                    0 => XfrmDirection::In,
                    1 => XfrmDirection::Out,
                    2 => XfrmDirection::Forward,
                    _ => return Err(InventoryError::Malformed),
                };
                let action = match self.u8()? {
                    0 => XfrmAction::Allow,
                    1 => XfrmAction::Block,
                    _ => return Err(InventoryError::Malformed),
                };
                let priority = self.u32()?;
                let count = usize::from(self.u8()?);
                if count > POLICY_TEMPLATES {
                    return Err(InventoryError::Capacity);
                }
                let mut templates = reserved_vec(count)?;
                for _ in 0..count {
                    templates.push(XfrmTemplate {
                        id: self.id()?,
                        source_address: self.address()?,
                        request_id: self.request_id()?,
                        mode: self.mode()?,
                    });
                }
                Ok(CleanupImage::Policy(PolicyParameters {
                    selector,
                    direction,
                    action,
                    priority,
                    templates,
                    mark: self.mark()?,
                    if_id: self.optional(Self::u32)?,
                }))
            }
            _ => Err(InventoryError::Malformed),
        }
    }

    pub(super) fn finish(self) -> Result<(), InventoryError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(InventoryError::Malformed)
        }
    }
}

pub(super) fn reserved_vec<T>(count: usize) -> Result<Vec<T>, InventoryError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| InventoryError::Allocation)?;
    Ok(values)
}

fn validate_selector(selector: &XfrmSelector) -> Result<(), InventoryError> {
    let maximum = if selector.source.is_ipv4() { 32 } else { 128 };
    if selector.source.is_ipv4() != selector.destination.is_ipv4()
        || selector.source_prefix_len > maximum
        || selector.destination_prefix_len > maximum
    {
        return Err(InventoryError::Malformed);
    }
    Ok(())
}

fn validate_record(record: &InventoryRecord) -> Result<(), InventoryError> {
    match record {
        InventoryRecord::Object(object) => {
            if object.serial == 0
                || object.generation == 0
                || object.candidates.is_empty()
                || object.candidates.len() > usize::from(object.reserved_images)
                || usize::from(object.reserved_images) > CANDIDATES_PER_OBJECT
                || object.coverage.is_some_and(|link| link.serial == 0)
            {
                return Err(InventoryError::Malformed);
            }
            let first = object.candidates.first().ok_or(InventoryError::Malformed)?;
            for candidate in &object.candidates {
                if std::mem::discriminant(&candidate.image) != std::mem::discriminant(&first.image)
                {
                    return Err(InventoryError::Malformed);
                }
                match &candidate.image {
                    CleanupImage::Sa { identity, .. } => {
                        validate_selector(&identity.selector.selector())?;
                        crate::model::validate_sa_query(crate::QuerySaRequest {
                            destination: identity.id.destination,
                            protocol: identity.id.protocol,
                            spi: identity.id.spi,
                            mark: identity.mark,
                        })
                        .map_err(|_| InventoryError::Malformed)?;
                        if identity.id.spi == 0
                            || identity.id.destination.is_ipv4()
                                != identity.source_address.is_ipv4()
                            || identity
                                .encap
                                .is_some_and(|encap| encap.validate_esp_in_udp().is_err())
                            || identity.output_mark == Some(XfrmMark { value: 0, mask: 0 })
                        {
                            return Err(InventoryError::Malformed);
                        }
                    }
                    CleanupImage::Policy(policy) => {
                        crate::linux::validate_policy_parameters(policy)
                            .map_err(|_| InventoryError::Malformed)?;
                        validate_selector(&policy.selector)?;
                        if policy.templates.len() > POLICY_TEMPLATES
                            || policy.templates.iter().any(|template| {
                                template.id.destination.is_ipv4()
                                    != template.source_address.is_ipv4()
                            })
                        {
                            return Err(InventoryError::Malformed);
                        }
                    }
                }
            }
        }
        InventoryRecord::Coverage(coverage) => {
            if coverage.serial == 0
                || coverage.inventory_generation == 0
                || coverage.operation_generation == 0
                || coverage.members.is_empty()
                || coverage.members.len() > COVERAGE_MEMBERS
                || coverage.members.iter().enumerate().any(|(index, member)| {
                    member.object.serial == 0
                        || coverage.members[..index].iter().any(|prior| {
                            prior.object.position == member.object.position
                                || prior.object.serial == member.object.serial
                        })
                })
            {
                return Err(InventoryError::Malformed);
            }
        }
    }
    Ok(())
}

pub(super) fn encode_record(
    record: &InventoryRecord,
    byte_limit: usize,
) -> Result<Zeroizing<Vec<u8>>, InventoryError> {
    validate_record(record)?;
    let mut encoder = Encoder::new(byte_limit)?;
    // Experimental schema; no consumer format commitment before measured review.
    encoder.u8(0)?;
    match record {
        InventoryRecord::Object(object) => {
            encoder.u8(1)?;
            encoder.u64(object.serial)?;
            encoder.u64(object.generation)?;
            encoder.u8(match object.phase {
                ObjectPhase::Reserved => 0,
                ObjectPhase::Issuing => 1,
                ObjectPhase::Owned => 2,
                ObjectPhase::Indeterminate => 3,
            })?;
            encoder.u8(object.reserved_images)?;
            encoder.optional(object.coverage, Encoder::link)?;
            encoder
                .u8(u8::try_from(object.candidates.len()).map_err(|_| InventoryError::Capacity)?)?;
            for candidate in &object.candidates {
                encoder.bytes(&candidate.pre_effect_absence)?;
                encoder.image(&candidate.image)?;
            }
        }
        InventoryRecord::Coverage(coverage) => {
            encoder.u8(2)?;
            encoder.u64(coverage.serial)?;
            encoder.u64(coverage.inventory_generation)?;
            encoder.u8(match coverage.family {
                TransactionFamily::Object => 0,
                TransactionFamily::Relocation => 1,
                TransactionFamily::Roster => 2,
            })?;
            encoder.bytes(&coverage.store_incarnation)?;
            encoder.bytes(&coverage.correlation)?;
            encoder.u64(coverage.operation_generation)?;
            encoder.bytes(&coverage.request_fingerprint)?;
            encoder.optional(coverage.settlement, |encoder, witness| {
                encoder.bytes(&witness)
            })?;
            encoder
                .u8(u8::try_from(coverage.members.len()).map_err(|_| InventoryError::Capacity)?)?;
            for member in &coverage.members {
                encoder.link(member.object)?;
                encoder.optional(member.absence, |encoder, witness| encoder.bytes(&witness))?;
            }
        }
    }
    Ok(encoder.finish())
}

// This is a locator for exact typed lookup keys, not a proof that a kernel
// lookup has one matching object. Kernel uniqueness remains a separate gate.
pub(super) fn image_locator_bytes(
    image: &CleanupImage,
) -> Result<Zeroizing<Vec<u8>>, InventoryError> {
    let mut encoder = Encoder::new(128)?;
    match image {
        CleanupImage::Sa { identity, .. } => {
            encoder.u8(1)?;
            encoder.id(identity.id)?;
            encoder.mark(identity.mark)?;
            encoder.optional(identity.if_id, Encoder::u32)?;
        }
        CleanupImage::Policy(policy) => {
            encoder.u8(2)?;
            encoder.selector(&policy.selector)?;
            encoder.u8(match policy.direction {
                XfrmDirection::In => 0,
                XfrmDirection::Out => 1,
                XfrmDirection::Forward => 2,
            })?;
            encoder.mark(policy.mark)?;
            encoder.optional(policy.if_id, Encoder::u32)?;
        }
    }
    Ok(encoder.finish())
}

pub(super) fn decode_record(
    bytes: &[u8],
    byte_limit: usize,
) -> Result<InventoryRecord, InventoryError> {
    let mut decoder = Decoder::new(bytes, byte_limit)?;
    if decoder.u8()? != 0 {
        return Err(InventoryError::Malformed);
    }
    let kind = decoder.u8()?;
    let serial = decoder.u64()?;
    let generation = decoder.u64()?;
    let record = match kind {
        1 => {
            let phase = match decoder.u8()? {
                0 => ObjectPhase::Reserved,
                1 => ObjectPhase::Issuing,
                2 => ObjectPhase::Owned,
                3 => ObjectPhase::Indeterminate,
                _ => return Err(InventoryError::Malformed),
            };
            let reserved_images = decoder.u8()?;
            let coverage = decoder.optional(Decoder::link)?;
            let count = usize::from(decoder.u8()?);
            if count > CANDIDATES_PER_OBJECT {
                return Err(InventoryError::Capacity);
            }
            let mut candidates = reserved_vec(count)?;
            for _ in 0..count {
                candidates.push(CandidateImage {
                    pre_effect_absence: decoder.array()?,
                    image: decoder.image()?,
                });
            }
            InventoryRecord::Object(ObjectRecord {
                serial,
                generation,
                phase,
                reserved_images,
                candidates,
                coverage,
            })
        }
        2 => {
            let family = match decoder.u8()? {
                0 => TransactionFamily::Object,
                1 => TransactionFamily::Relocation,
                2 => TransactionFamily::Roster,
                _ => return Err(InventoryError::Malformed),
            };
            let store_incarnation = decoder.array()?;
            let correlation = decoder.array()?;
            let operation_generation = decoder.u64()?;
            let request_fingerprint = decoder.array()?;
            let settlement = decoder.optional(Decoder::array)?;
            let count = usize::from(decoder.u8()?);
            if count > COVERAGE_MEMBERS {
                return Err(InventoryError::Capacity);
            }
            let mut members = reserved_vec(count)?;
            for _ in 0..count {
                members.push(CoverageMember {
                    object: decoder.link()?,
                    absence: decoder.optional(Decoder::array)?,
                });
            }
            InventoryRecord::Coverage(CoverageRecord {
                serial,
                inventory_generation: generation,
                family,
                store_incarnation,
                correlation,
                operation_generation,
                request_fingerprint,
                members,
                settlement,
            })
        }
        _ => return Err(InventoryError::Malformed),
    };
    decoder.finish()?;
    validate_record(&record)?;
    Ok(record)
}
