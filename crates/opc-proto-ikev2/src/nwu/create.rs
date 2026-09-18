use super::{
    configuration::{chain, notify_entry},
    once, Address, AddressFamilies, Error, Limits, Notify, Peer, QosInfo, RequestIdentity,
};
use crate::{
    build_create_child_sa_rekey_response_payloads,
    dedicated_bearer::{
        validate_ke_view, validate_sa_build, validate_sa_view, validate_selected_key_exchange,
        validate_selected_proposal,
    },
    Header, Ikev2CreateChildSaRekeyResponseBuild, Ikev2IkeAuthPayloadBuild,
    Ikev2KeyExchangePayload, Ikev2KeyExchangePayloadBuild, Ikev2NoncePayload,
    Ikev2NoncePayloadBuild, Ikev2NotifyPayload, Ikev2SaPayload, Ikev2SaPayloadBuild,
    Ikev2TrafficSelectorBuild, Ikev2TrafficSelectorPayload, Ikev2TrafficSelectorPayloadBuild,
    PayloadType, EXCHANGE_TYPE_CREATE_CHILD_SA,
};
use std::fmt;

/// All-packet selectors for the caller's admitted inner address families.
/// Protocol zero, complete ports, and complete address ranges use the existing
/// RFC 7296 TS representation; TS does not narrow to a QFI or QoS flow.
pub fn all_packet_selectors(families: AddressFamilies) -> Ikev2TrafficSelectorPayloadBuild {
    let mut selectors = Vec::new();
    for (present, len, ts_type) in [(families.ipv4(), 4, 7), (families.ipv6(), 16, 8)] {
        if present {
            selectors.push(Ikev2TrafficSelectorBuild {
                ts_type,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 65_535,
                start_address: vec![0; len],
                end_address: vec![255; len],
            });
        }
    }
    Ikev2TrafficSelectorPayloadBuild { selectors }
}
fn selector_families(value: &Ikev2TrafficSelectorPayload<'_>) -> Result<AddressFamilies, Error> {
    let mut v4 = None;
    let mut v6 = None;
    for selector in &value.selectors {
        if selector.ip_protocol_id != 0
            || selector.start_port != 0
            || selector.end_port != 65_535
            || selector.start_address.iter().any(|b| *b != 0)
            || selector.end_address.iter().any(|b| *b != 255)
        {
            return Err(Error::Incompatible);
        }
        match selector.ts_type {
            7 if selector.start_address.len() == 4 && selector.end_address.len() == 4 => {
                once(&mut v4, ())?
            }
            8 if selector.start_address.len() == 16 && selector.end_address.len() == 16 => {
                once(&mut v6, ())?
            }
            _ => return Err(Error::Incompatible),
        }
    }
    match (v4.is_some(), v6.is_some()) {
        (true, true) => Ok(AddressFamilies::Dual),
        (true, false) => Ok(AddressFamilies::Ipv4),
        (false, true) => Ok(AddressFamilies::Ipv6),
        _ => Err(Error::Missing),
    }
}
fn address_applicable(families: AddressFamilies, address: Address) -> Result<(), Error> {
    if if address.is_ipv4() {
        families.ipv4()
    } else {
        families.ipv6()
    } {
        Ok(())
    } else {
        Err(Error::Incompatible)
    }
}

/// Network-initiated new Child-SA construction input. The caller owns proposal
/// policy, SPI allocation, nonce generation, KE state and the unique-default-SA
/// invariant across its full PDU-session roster.
#[derive(Clone)]
pub struct CreateRequestBuild<'a> {
    /// ESP proposals from caller-selected cryptographic capabilities.
    pub security_association: Ikev2SaPayloadBuild,
    /// Caller-generated nonce.
    pub nonce: Ikev2NoncePayloadBuild,
    /// Optional PFS KE matching an offered DH transform.
    pub key_exchange: Option<Ikev2KeyExchangePayloadBuild>,
    /// Inner families admitted by the earlier configuration exchange.
    pub inner_families: AddressFamilies,
    /// Exactly one UP address, applicable to an admitted family.
    pub up_address: Address,
    /// Complete association; zero or more QFIs and a typed default indication.
    pub qos: QosInfo<'a>,
}
impl fmt::Debug for CreateRequestBuild<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CreateRequestBuild([REDACTED])")
    }
}
impl CreateRequestBuild<'_> {
    /// Construct SA, Nonce, optional KE, all-packet TSi/TSr and the two NWu
    /// notifies. Existing generic ESP and KE validators run before returning.
    pub fn payloads(&self) -> Result<Vec<Ikev2IkeAuthPayloadBuild>, Error> {
        address_applicable(self.inner_families, self.up_address)?;
        validate_sa_build(&self.security_association, false).map_err(|_| Error::InvalidValue)?;
        let common =
            build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
                security_association: self.security_association.clone(),
                nonce: self.nonce.clone(),
                key_exchange: self.key_exchange.clone(),
                traffic_selectors_initiator: all_packet_selectors(self.inner_families),
                traffic_selectors_responder: all_packet_selectors(self.inner_families),
            })
            .map_err(|_| Error::InvalidValue)?;
        let sa = Ikev2SaPayload::decode_body(&common.security_association.body)
            .map_err(|_| Error::Framing)?;
        let ke = common
            .key_exchange
            .as_ref()
            .map(|v| Ikev2KeyExchangePayload::decode_body(&v.body))
            .transpose()
            .map_err(|_| Error::Framing)?;
        validate_ke_view(&sa, ke.as_ref()).map_err(|_| Error::Incompatible)?;
        let mut out = common.into_payloads();
        out.push(notify_entry(Notify::Qos(self.qos))?);
        out.push(notify_entry(Notify::UpAddress(self.up_address))?);
        Ok(out)
    }
}

/// Opened, structurally validated NWu Child-SA creation request. This value is
/// not evidence of peer authentication or cryptographic policy acceptance.
#[derive(Clone)]
pub struct CreateRequest<'a> {
    identity: RequestIdentity,
    sa: Ikev2SaPayload<'a>,
    nonce: Ikev2NoncePayload<'a>,
    ke: Option<Ikev2KeyExchangePayload<'a>>,
    families: AddressFamilies,
    address: Address,
    qos: QosInfo<'a>,
}
impl fmt::Debug for CreateRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CreateRequest([REDACTED])")
    }
}
impl<'a> CreateRequest<'a> {
    /// Decode a network-initiated request against the admitted inner families.
    /// Reject rekey notifications, missing or duplicate required fields, several
    /// UP addresses, narrowed selectors, and inconsistent KE/proposal shape.
    pub fn decode(
        header: &Header,
        first: PayloadType,
        bytes: &'a [u8],
        admitted: AddressFamilies,
        limits: Limits,
    ) -> Result<Self, Error> {
        let identity =
            RequestIdentity::from_request(header, Peer::Network, EXCHANGE_TYPE_CREATE_CHILD_SA)?;
        let mut common = Common::default();
        let mut address = None;
        let mut qos = None;
        for raw in chain(first, bytes, limits)? {
            let raw = raw.map_err(|_| Error::Framing)?;
            if raw.payload_type == PayloadType::Notify {
                let n = Ikev2NotifyPayload::decode(raw).map_err(|_| Error::Framing)?;
                if n.notify_message_type < 16_384 || n.notify_message_type == 16_393 {
                    return Err(Error::Incompatible);
                }
                match Notify::decode(n)? {
                    Some(Notify::UpAddress(v)) => once(&mut address, v)?,
                    Some(Notify::Qos(v)) => once(&mut qos, v)?,
                    Some(_) => return Err(Error::Incompatible),
                    None => (),
                }
            } else {
                common.add(raw)?;
            }
        }
        let (sa, nonce, ke, families) = common.finish(false)?;
        if families != admitted {
            return Err(Error::Incompatible);
        }
        let address = address.ok_or(Error::Missing)?;
        address_applicable(admitted, address)?;
        Ok(Self {
            identity,
            sa,
            nonce,
            ke,
            families,
            address,
            qos: qos.ok_or(Error::Missing)?,
        })
    }
    /// Original request identity for matching the eventual response.
    pub const fn identity(&self) -> RequestIdentity {
        self.identity
    }
    /// ESP proposals, ready for caller-ordered policy selection.
    pub fn security_association(&self) -> &Ikev2SaPayload<'a> {
        &self.sa
    }
    /// Caller-visible nonce for the existing key-derivation boundary.
    pub const fn nonce(&self) -> Ikev2NoncePayload<'a> {
        self.nonce
    }
    /// Optional KE for the existing key-agreement boundary.
    pub const fn key_exchange(&self) -> Option<Ikev2KeyExchangePayload<'a>> {
        self.ke
    }
    /// One applicable user-plane address.
    pub const fn up_address(&self) -> Address {
        self.address
    }
    /// Complete QoS association.
    pub const fn qos(&self) -> QosInfo<'a> {
        self.qos
    }
    /// All-packet selector families.
    pub const fn families(&self) -> AddressFamilies {
        self.families
    }
    /// Validate an accepted opened response against this request. Exact header
    /// correlation, selected-proposal membership and KE relationship are
    /// checked, and the NWu all-packet selector invariant is retained.
    pub fn accepted_response<'b>(
        &self,
        header: &Header,
        first: PayloadType,
        bytes: &'b [u8],
        limits: Limits,
    ) -> Result<CreateAccepted<'b>, Error> {
        self.identity.validate_response(header)?;
        let mut common = Common::default();
        for raw in chain(first, bytes, limits)? {
            let raw = raw.map_err(|_| Error::Framing)?;
            if raw.payload_type == PayloadType::Notify {
                let n = Ikev2NotifyPayload::decode(raw).map_err(|_| Error::Framing)?;
                if n.notify_message_type < 16_384
                    || n.notify_message_type == 16_393
                    || Notify::decode(n)?.is_some()
                {
                    return Err(Error::Incompatible);
                }
            } else {
                common.add(raw)?;
            }
        }
        let (sa, nonce, ke, families) = common.finish(true)?;
        if families != self.families {
            return Err(Error::Incompatible);
        }
        let selected = sa.proposals.first().ok_or(Error::Missing)?;
        let offered = self
            .sa
            .proposals
            .iter()
            .find(|p| p.proposal_number == selected.proposal_number)
            .ok_or(Error::Incompatible)?;
        validate_selected_proposal(offered, selected).map_err(|_| Error::Incompatible)?;
        let selected_group = selected
            .transforms
            .iter()
            .find(|t| t.transform_type == 4)
            .map(|t| t.transform_id);
        validate_selected_key_exchange(
            self.ke.as_ref().map(|k| k.dh_group),
            ke.as_ref(),
            selected_group,
        )
        .map_err(|_| Error::Incompatible)?;
        Ok(CreateAccepted { sa, nonce, ke })
    }
}
/// Accepted response payloads after exact request correlation, before key
/// derivation and caller-owned SA installation.
#[derive(Clone)]
pub struct CreateAccepted<'a> {
    sa: Ikev2SaPayload<'a>,
    nonce: Ikev2NoncePayload<'a>,
    ke: Option<Ikev2KeyExchangePayload<'a>>,
}
impl fmt::Debug for CreateAccepted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CreateAccepted([REDACTED])")
    }
}
impl<'a> CreateAccepted<'a> {
    /// Selected ESP proposal.
    pub fn security_association(&self) -> &Ikev2SaPayload<'a> {
        &self.sa
    }
    /// Peer nonce.
    pub const fn nonce(&self) -> Ikev2NoncePayload<'a> {
        self.nonce
    }
    /// Optional peer KE.
    pub const fn key_exchange(&self) -> Option<Ikev2KeyExchangePayload<'a>> {
        self.ke
    }
}

#[derive(Default)]
struct Common<'a> {
    sa: Option<Ikev2SaPayload<'a>>,
    nonce: Option<Ikev2NoncePayload<'a>>,
    ke: Option<Ikev2KeyExchangePayload<'a>>,
    tsi: Option<Ikev2TrafficSelectorPayload<'a>>,
    tsr: Option<Ikev2TrafficSelectorPayload<'a>>,
}
impl<'a> Common<'a> {
    fn add(&mut self, raw: crate::RawPayload<'a>) -> Result<(), Error> {
        match raw.payload_type {
            PayloadType::SecurityAssociation => once(
                &mut self.sa,
                Ikev2SaPayload::decode(raw).map_err(|_| Error::Framing)?,
            )?,
            PayloadType::Nonce => once(
                &mut self.nonce,
                Ikev2NoncePayload::decode(raw).map_err(|_| Error::Framing)?,
            )?,
            PayloadType::KeyExchange => once(
                &mut self.ke,
                Ikev2KeyExchangePayload::decode(raw).map_err(|_| Error::Framing)?,
            )?,
            PayloadType::TrafficSelectorInitiator => once(
                &mut self.tsi,
                Ikev2TrafficSelectorPayload::decode(raw).map_err(|_| Error::Framing)?,
            )?,
            PayloadType::TrafficSelectorResponder => once(
                &mut self.tsr,
                Ikev2TrafficSelectorPayload::decode(raw).map_err(|_| Error::Framing)?,
            )?,
            PayloadType::Unknown(_) | PayloadType::VendorId => (),
            _ => return Err(Error::Incompatible),
        }
        Ok(())
    }
    fn finish(
        self,
        response: bool,
    ) -> Result<
        (
            Ikev2SaPayload<'a>,
            Ikev2NoncePayload<'a>,
            Option<Ikev2KeyExchangePayload<'a>>,
            AddressFamilies,
        ),
        Error,
    > {
        let sa = self.sa.ok_or(Error::Missing)?;
        let nonce = self.nonce.ok_or(Error::Missing)?;
        validate_sa_view(&sa, response).map_err(|_| Error::InvalidValue)?;
        validate_ke_view(&sa, self.ke.as_ref()).map_err(|_| Error::Incompatible)?;
        let tsi = selector_families(&self.tsi.ok_or(Error::Missing)?)?;
        let tsr = selector_families(&self.tsr.ok_or(Error::Missing)?)?;
        if tsi != tsr {
            return Err(Error::Incompatible);
        }
        Ok((sa, nonce, self.ke, tsi))
    }
}
