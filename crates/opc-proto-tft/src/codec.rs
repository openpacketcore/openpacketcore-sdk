use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, EncodeErrorCode, OwnedDecode, SpecRef,
};

use crate::{
    AuthorizationToken, FlowIdentifier, Ipv6AddressPrefix, Ipv6FlowLabel, PacketFilter,
    PacketFilterComponent, PacketFilterComponentKind, PacketFilterDirection,
    PacketFilterIdentifier, PacketFilterIdentifierList, PacketFilterList, PortRange, TftError,
    TftErrorKind, TftOperation, TftParameter, TrafficFlowTemplate, UnknownTftParameter,
    VlanIdentifier, VlanPriority, TFT_MAX_VALUE_LEN, TFT_MIN_VALUE_LEN,
};

const AUTHORIZATION_TOKEN_PARAMETER: u8 = 0x01;
const FLOW_IDENTIFIER_PARAMETER: u8 = 0x02;
const PACKET_FILTER_IDENTIFIER_PARAMETER: u8 = 0x03;

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS24008", "10.5.6.12").with_table("10.5.162")
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    const fn remaining_len(&self) -> usize {
        self.input.len()
    }

    const fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, TftError> {
        let value = self
            .input
            .first()
            .copied()
            .ok_or_else(|| TftError::new(TftErrorKind::Truncated { field }).at(self.offset))?;
        self.input = self
            .input
            .get(1..)
            .ok_or_else(|| TftError::new(TftErrorKind::Truncated { field }).at(self.offset))?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or_else(|| TftError::new(TftErrorKind::LengthOverflow).at(self.offset))?;
        Ok(value)
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], TftError> {
        if self.input.len() < length {
            return Err(TftError::new(TftErrorKind::Truncated { field }).at(self.offset));
        }
        let value = self
            .input
            .get(..length)
            .ok_or_else(|| TftError::new(TftErrorKind::Truncated { field }).at(self.offset))?;
        self.input = self
            .input
            .get(length..)
            .ok_or_else(|| TftError::new(TftErrorKind::Truncated { field }).at(self.offset))?;
        self.offset = self
            .offset
            .checked_add(length)
            .ok_or_else(|| TftError::new(TftErrorKind::LengthOverflow).at(self.offset))?;
        Ok(value)
    }

    fn take_component(
        &mut self,
        component_type: u8,
        expected: usize,
    ) -> Result<&'a [u8], TftError> {
        if self.input.len() < expected {
            return Err(TftError::new(TftErrorKind::InvalidComponentLength {
                component_type,
                expected,
                actual: self.input.len(),
            })
            .at(self.offset));
        }
        self.take(expected, "packet filter component value")
    }
}

struct ElementBudget {
    used: usize,
    limit: usize,
}

impl ElementBudget {
    const fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    fn consume(&mut self, offset: usize) -> Result<(), TftError> {
        self.used = self
            .used
            .checked_add(1)
            .ok_or_else(|| TftError::new(TftErrorKind::LengthOverflow).at(offset))?;
        if self.used > self.limit {
            return Err(
                TftError::new(TftErrorKind::ElementLimitExceeded { limit: self.limit }).at(offset),
            );
        }
        Ok(())
    }
}

impl TrafficFlowTemplate {
    /// Strictly decode one complete TS 24.008 TFT value part.
    ///
    /// This convenience entry point uses the normative 255-octet limit and an
    /// element budget large enough for every value representable within it.
    /// Use [`Self::decode_value_with_context`] to impose a smaller caller limit.
    pub fn decode_value(input: &[u8]) -> Result<Self, TftError> {
        let mut context = DecodeContext::conservative();
        context.max_message_len = TFT_MAX_VALUE_LEN;
        context.max_ies = TFT_MAX_VALUE_LEN;
        Self::decode_value_with_context(input, context)
    }

    /// Strictly decode one complete TFT value under caller-supplied size and
    /// element limits.
    ///
    /// `max_message_len` and `max_ies` are enforced. TFTs are non-recursive, so
    /// `max_depth` is not consumed. Unsupported parameter IDs are preserved as
    /// required by TS 24.008 rather than applying the generic unknown-IE policy.
    /// Protocol-mandated duplicate rejection likewise takes precedence over the
    /// generic duplicate-IE policy.
    pub fn decode_value_with_context(
        input: &[u8],
        context: DecodeContext,
    ) -> Result<Self, TftError> {
        if !(TFT_MIN_VALUE_LEN..=TFT_MAX_VALUE_LEN).contains(&input.len()) {
            return Err(TftError::new(TftErrorKind::InvalidValueLength {
                actual: input.len(),
                minimum: TFT_MIN_VALUE_LEN,
                maximum: TFT_MAX_VALUE_LEN,
            })
            .at(0));
        }
        if input.len() > context.max_message_len {
            return Err(TftError::new(TftErrorKind::InvalidValueLength {
                actual: input.len(),
                minimum: 0,
                maximum: context.max_message_len,
            })
            .at(0));
        }

        let mut cursor = Cursor::new(input);
        let operation_octet = cursor.read_u8("TFT operation header")?;
        let operation_code = operation_octet >> 5;
        let operation = TftOperation::from_code(operation_code).map_err(|error| error.at(0))?;
        let parameters_present = (operation_octet & 0x10) != 0;
        let filter_count = usize::from(operation_octet & 0x0f);

        if operation == TftOperation::Ignore {
            if parameters_present || filter_count != 0 {
                return Err(TftError::new(TftErrorKind::InvalidOperationHeader {
                    operation: operation.code(),
                })
                .at(0));
            }
            let ignored = cursor
                .take(cursor.remaining_len(), "ignored TFT contents")?
                .to_vec();
            return TrafficFlowTemplate::ignore_with_contents(ignored).map_err(|error| error.at(0));
        }

        let mut budget = ElementBudget::new(context.max_ies);
        let packet_filters = match operation {
            TftOperation::CreateNew
            | TftOperation::AddPacketFilters
            | TftOperation::ReplacePacketFilters => {
                validate_wire_filter_count(operation, filter_count)?;
                let mut filters = Vec::with_capacity(filter_count);
                for _ in 0..filter_count {
                    filters.push(decode_full_filter(&mut cursor, &mut budget)?);
                }
                PacketFilterList::Filters(filters)
            }
            TftOperation::DeletePacketFilters => {
                validate_wire_filter_count(operation, filter_count)?;
                let mut identifiers = Vec::with_capacity(filter_count);
                for _ in 0..filter_count {
                    let offset = cursor.offset();
                    budget.consume(offset)?;
                    let octet = cursor.read_u8("packet filter identifier")?;
                    if octet & 0xf0 != 0 {
                        return Err(TftError::new(TftErrorKind::NonZeroSpareBits {
                            field: "packet filter identifier",
                        })
                        .at(offset));
                    }
                    identifiers.push(
                        PacketFilterIdentifier::new(octet & 0x0f)
                            .map_err(|error| error.at(offset))?,
                    );
                }
                PacketFilterList::Identifiers(identifiers)
            }
            TftOperation::DeleteExisting | TftOperation::NoOperation => {
                if filter_count != 0 {
                    return Err(TftError::new(TftErrorKind::InvalidOperationHeader {
                        operation: operation.code(),
                    })
                    .at(0));
                }
                PacketFilterList::None
            }
            TftOperation::Ignore => PacketFilterList::None,
        };

        let parameters = if parameters_present {
            if cursor.is_empty() {
                return Err(TftError::new(TftErrorKind::EmptyParameterList).at(cursor.offset()));
            }
            decode_parameters(&mut cursor, &mut budget)?
        } else {
            if !cursor.is_empty() {
                return Err(TftError::new(TftErrorKind::UnexpectedTrailingData).at(cursor.offset()));
            }
            Vec::new()
        };

        TrafficFlowTemplate::new(operation, packet_filters, parameters).map_err(|error| error.at(0))
    }

    /// Return the exact TS 24.008 value-part encoded length.
    pub fn encoded_value_len(&self) -> Result<usize, TftError> {
        self.validate()?;
        self.encoded_value_len_internal()
    }

    /// Deterministically append the TS 24.008 value part to `destination`.
    ///
    /// Validation and encoding happen in a bounded temporary buffer, so a
    /// returned error leaves `destination` unchanged. Valid filter/component/
    /// parameter order and permitted unknown parameter bytes are preserved.
    pub fn encode_value(&self, destination: &mut BytesMut) -> Result<(), TftError> {
        self.validate()?;
        let expected_len = self.encoded_value_len_internal()?;
        let mut encoded = BytesMut::with_capacity(expected_len);
        encode_value_inner(self, &mut encoded)?;
        if encoded.len() != expected_len {
            return Err(TftErrorKind::EncodedLengthMismatch.into());
        }
        destination.reserve(expected_len);
        destination.put_slice(&encoded);
        Ok(())
    }
}

fn validate_wire_filter_count(
    operation: TftOperation,
    filter_count: usize,
) -> Result<(), TftError> {
    if !(1..=15).contains(&filter_count) {
        return Err(TftError::new(TftErrorKind::InvalidPacketFilterCount {
            operation: operation.code(),
            count: filter_count,
        })
        .at(0));
    }
    Ok(())
}

fn decode_full_filter(
    cursor: &mut Cursor<'_>,
    budget: &mut ElementBudget,
) -> Result<PacketFilter, TftError> {
    let filter_offset = cursor.offset();
    budget.consume(filter_offset)?;
    let identifier_direction = cursor.read_u8("packet filter identifier and direction")?;
    if identifier_direction & 0xc0 != 0 {
        return Err(TftError::new(TftErrorKind::NonZeroSpareBits {
            field: "packet filter identifier and direction",
        })
        .at(filter_offset));
    }
    let identifier = PacketFilterIdentifier::new(identifier_direction & 0x0f)
        .map_err(|error| error.at(filter_offset))?;
    let direction = PacketFilterDirection::from_code((identifier_direction >> 4) & 0x03);
    let precedence = cursor.read_u8("packet filter evaluation precedence")?;
    let contents_length = usize::from(cursor.read_u8("packet filter contents length")?);
    if contents_length == 0 {
        return Err(TftError::new(TftErrorKind::EmptyPacketFilterContents).at(cursor.offset()));
    }
    let contents_offset = cursor.offset();
    let contents = cursor.take(contents_length, "packet filter contents")?;
    let mut component_cursor = Cursor {
        input: contents,
        offset: contents_offset,
    };
    let mut components = Vec::new();
    while !component_cursor.is_empty() {
        components.push(decode_component(&mut component_cursor, budget)?);
    }
    PacketFilter::new(identifier, direction, precedence, components)
        .map_err(|error| error.at(filter_offset))
}

fn decode_component(
    cursor: &mut Cursor<'_>,
    budget: &mut ElementBudget,
) -> Result<PacketFilterComponent, TftError> {
    let component_offset = cursor.offset();
    budget.consume(component_offset)?;
    let component_type = cursor.read_u8("packet filter component type")?;
    let kind = PacketFilterComponentKind::from_type_code(component_type)
        .map_err(|error| error.at(component_offset))?;

    let component = match kind {
        PacketFilterComponentKind::Ipv4RemoteAddress
        | PacketFilterComponentKind::Ipv4LocalAddress => {
            let raw = cursor.take_component(component_type, 8)?;
            let bytes = copy_array::<8>(raw, "IPv4 address and mask", component_offset)?;
            let [a0, a1, a2, a3, m0, m1, m2, m3] = bytes;
            let address = Ipv4Addr::new(a0, a1, a2, a3);
            let mask = Ipv4Addr::new(m0, m1, m2, m3);
            if kind == PacketFilterComponentKind::Ipv4RemoteAddress {
                PacketFilterComponent::Ipv4RemoteAddress { address, mask }
            } else {
                PacketFilterComponent::Ipv4LocalAddress { address, mask }
            }
        }
        PacketFilterComponentKind::Ipv6RemoteAddress => {
            let raw = cursor.take_component(component_type, 32)?;
            let address_raw = raw.get(..16).ok_or_else(|| {
                TftError::new(TftErrorKind::InvalidComponentLength {
                    component_type,
                    expected: 32,
                    actual: raw.len(),
                })
                .at(component_offset)
            })?;
            let mask_raw = raw.get(16..).ok_or_else(|| {
                TftError::new(TftErrorKind::InvalidComponentLength {
                    component_type,
                    expected: 32,
                    actual: raw.len(),
                })
                .at(component_offset)
            })?;
            let address = Ipv6Addr::from(copy_array::<16>(
                address_raw,
                "IPv6 remote address",
                component_offset,
            )?);
            let mask = Ipv6Addr::from(copy_array::<16>(
                mask_raw,
                "IPv6 remote mask",
                component_offset,
            )?);
            PacketFilterComponent::Ipv6RemoteAddress { address, mask }
        }
        PacketFilterComponentKind::Ipv6RemoteAddressPrefix
        | PacketFilterComponentKind::Ipv6LocalAddressPrefix => {
            let raw = cursor.take_component(component_type, 17)?;
            let address_raw = raw.get(..16).ok_or_else(|| {
                TftError::new(TftErrorKind::InvalidComponentLength {
                    component_type,
                    expected: 17,
                    actual: raw.len(),
                })
                .at(component_offset)
            })?;
            let prefix_length = raw.get(16).copied().ok_or_else(|| {
                TftError::new(TftErrorKind::InvalidComponentLength {
                    component_type,
                    expected: 17,
                    actual: raw.len(),
                })
                .at(component_offset)
            })?;
            let address = Ipv6Addr::from(copy_array::<16>(
                address_raw,
                "IPv6 address",
                component_offset,
            )?);
            let value = Ipv6AddressPrefix::new(address, prefix_length)
                .map_err(|error| error.at(component_offset))?;
            if kind == PacketFilterComponentKind::Ipv6RemoteAddressPrefix {
                PacketFilterComponent::Ipv6RemoteAddressPrefix(value)
            } else {
                PacketFilterComponent::Ipv6LocalAddressPrefix(value)
            }
        }
        PacketFilterComponentKind::ProtocolIdentifierNextHeader => {
            PacketFilterComponent::ProtocolIdentifierNextHeader(read_component_u8(
                cursor,
                component_type,
            )?)
        }
        PacketFilterComponentKind::SingleLocalPort
        | PacketFilterComponentKind::SingleRemotePort => {
            let raw = cursor.take_component(component_type, 2)?;
            let value = u16::from_be_bytes(copy_array::<2>(raw, "single port", component_offset)?);
            if kind == PacketFilterComponentKind::SingleLocalPort {
                PacketFilterComponent::SingleLocalPort(value)
            } else {
                PacketFilterComponent::SingleRemotePort(value)
            }
        }
        PacketFilterComponentKind::LocalPortRange | PacketFilterComponentKind::RemotePortRange => {
            let raw = cursor.take_component(component_type, 4)?;
            let bytes = copy_array::<4>(raw, "port range", component_offset)?;
            let [low0, low1, high0, high1] = bytes;
            let range = PortRange::new(
                u16::from_be_bytes([low0, low1]),
                u16::from_be_bytes([high0, high1]),
            )
            .map_err(|error| error.at(component_offset))?;
            if kind == PacketFilterComponentKind::LocalPortRange {
                PacketFilterComponent::LocalPortRange(range)
            } else {
                PacketFilterComponent::RemotePortRange(range)
            }
        }
        PacketFilterComponentKind::SecurityParameterIndex => {
            let raw = cursor.take_component(component_type, 4)?;
            let value = u32::from_be_bytes(copy_array::<4>(
                raw,
                "security parameter index",
                component_offset,
            )?);
            PacketFilterComponent::SecurityParameterIndex(value)
        }
        PacketFilterComponentKind::TypeOfServiceTrafficClass => {
            let raw = cursor.take_component(component_type, 2)?;
            let [value, mask] =
                copy_array::<2>(raw, "type of service or traffic class", component_offset)?;
            PacketFilterComponent::TypeOfServiceTrafficClass { value, mask }
        }
        PacketFilterComponentKind::FlowLabel => {
            let raw = cursor.take_component(component_type, 3)?;
            let [high, middle, low] = copy_array::<3>(raw, "IPv6 flow label", component_offset)?;
            if high & 0xf0 != 0 {
                return Err(TftError::new(TftErrorKind::NonZeroSpareBits {
                    field: "IPv6 flow label",
                })
                .at(component_offset));
            }
            let value = u32::from_be_bytes([0, high, middle, low]);
            PacketFilterComponent::FlowLabel(
                Ipv6FlowLabel::new(value).map_err(|error| error.at(component_offset))?,
            )
        }
        PacketFilterComponentKind::DestinationMacAddress
        | PacketFilterComponentKind::SourceMacAddress => {
            let raw = cursor.take_component(component_type, 6)?;
            let value = copy_array::<6>(raw, "MAC address", component_offset)?;
            if kind == PacketFilterComponentKind::DestinationMacAddress {
                PacketFilterComponent::DestinationMacAddress(value)
            } else {
                PacketFilterComponent::SourceMacAddress(value)
            }
        }
        PacketFilterComponentKind::CustomerVlanId | PacketFilterComponentKind::ServiceVlanId => {
            let raw = cursor.take_component(component_type, 2)?;
            let bytes = copy_array::<2>(raw, "VLAN identifier", component_offset)?;
            let [high, low] = bytes;
            if high & 0xf0 != 0 {
                return Err(TftError::new(TftErrorKind::NonZeroSpareBits {
                    field: "VLAN identifier",
                })
                .at(component_offset));
            }
            let value = VlanIdentifier::new(u16::from_be_bytes([high, low]))
                .map_err(|error| error.at(component_offset))?;
            if kind == PacketFilterComponentKind::CustomerVlanId {
                PacketFilterComponent::CustomerVlanId(value)
            } else {
                PacketFilterComponent::ServiceVlanId(value)
            }
        }
        PacketFilterComponentKind::CustomerVlanPriority
        | PacketFilterComponentKind::ServiceVlanPriority => {
            let value = read_component_u8(cursor, component_type)?;
            if value & 0xf0 != 0 {
                return Err(TftError::new(TftErrorKind::NonZeroSpareBits {
                    field: "VLAN PCP/DEI",
                })
                .at(component_offset));
            }
            let priority = VlanPriority::new((value >> 1) & 0x07, value & 0x01 != 0)
                .map_err(|error| error.at(component_offset))?;
            if kind == PacketFilterComponentKind::CustomerVlanPriority {
                PacketFilterComponent::CustomerVlanPriority(priority)
            } else {
                PacketFilterComponent::ServiceVlanPriority(priority)
            }
        }
        PacketFilterComponentKind::EtherType => {
            let raw = cursor.take_component(component_type, 2)?;
            PacketFilterComponent::EtherType(u16::from_be_bytes(copy_array::<2>(
                raw,
                "EtherType",
                component_offset,
            )?))
        }
    };
    Ok(component)
}

fn read_component_u8(cursor: &mut Cursor<'_>, component_type: u8) -> Result<u8, TftError> {
    let raw = cursor.take_component(component_type, 1)?;
    raw.first().copied().ok_or_else(|| {
        TftError::new(TftErrorKind::InvalidComponentLength {
            component_type,
            expected: 1,
            actual: raw.len(),
        })
        .at(cursor.offset())
    })
}

fn decode_parameters(
    cursor: &mut Cursor<'_>,
    budget: &mut ElementBudget,
) -> Result<Vec<TftParameter>, TftError> {
    let mut parameters = Vec::new();
    while !cursor.is_empty() {
        let parameter_offset = cursor.offset();
        budget.consume(parameter_offset)?;
        let identifier = cursor.read_u8("TFT parameter identifier")?;
        let contents_length = usize::from(cursor.read_u8("TFT parameter length")?);
        let contents_offset = cursor.offset();
        let contents = cursor.take(contents_length, "TFT parameter contents")?;
        let parameter = match identifier {
            AUTHORIZATION_TOKEN_PARAMETER => TftParameter::AuthorizationToken(
                AuthorizationToken::new(contents.to_vec())
                    .map_err(|error| error.at(contents_offset))?,
            ),
            FLOW_IDENTIFIER_PARAMETER => {
                if contents.len() != 4 {
                    return Err(TftError::new(TftErrorKind::InvalidParameterLength {
                        identifier,
                        actual: contents.len(),
                        minimum: 4,
                        maximum: 4,
                    })
                    .at(contents_offset));
                }
                let [media0, media1, flow0, flow1] =
                    copy_array::<4>(contents, "flow identifier", contents_offset)?;
                TftParameter::FlowIdentifier(FlowIdentifier::new(
                    u16::from_be_bytes([media0, media1]),
                    u16::from_be_bytes([flow0, flow1]),
                ))
            }
            PACKET_FILTER_IDENTIFIER_PARAMETER => {
                if contents.is_empty() {
                    return Err(TftError::new(TftErrorKind::InvalidParameterLength {
                        identifier,
                        actual: 0,
                        minimum: 1,
                        maximum: usize::from(u8::MAX),
                    })
                    .at(contents_offset));
                }
                let mut identifiers = Vec::with_capacity(contents.len());
                for (index, octet) in contents.iter().copied().enumerate() {
                    let offset = contents_offset
                        .checked_add(index)
                        .ok_or_else(|| TftError::new(TftErrorKind::LengthOverflow))?;
                    budget.consume(offset)?;
                    if octet & 0xf0 != 0 {
                        return Err(TftError::new(TftErrorKind::NonZeroSpareBits {
                            field: "packet-filter-identifier parameter",
                        })
                        .at(offset));
                    }
                    identifiers.push(
                        PacketFilterIdentifier::new(octet & 0x0f)
                            .map_err(|error| error.at(offset))?,
                    );
                }
                TftParameter::PacketFilterIdentifiers(
                    PacketFilterIdentifierList::new(identifiers)
                        .map_err(|error| error.at(contents_offset))?,
                )
            }
            _ => TftParameter::Unknown(
                UnknownTftParameter::new(identifier, contents.to_vec())
                    .map_err(|error| error.at(contents_offset))?,
            ),
        };
        parameters.push(parameter);
    }
    Ok(parameters)
}

fn copy_array<const N: usize>(
    input: &[u8],
    field: &'static str,
    offset: usize,
) -> Result<[u8; N], TftError> {
    <[u8; N]>::try_from(input)
        .map_err(|_| TftError::new(TftErrorKind::Truncated { field }).at(offset))
}

fn encode_value_inner(
    value: &TrafficFlowTemplate,
    destination: &mut BytesMut,
) -> Result<(), TftError> {
    let count =
        u8::try_from(value.packet_filters().len()).map_err(|_| TftErrorKind::LengthOverflow)?;
    let mut operation_octet = value.operation().code() << 5;
    if !value.parameters().is_empty() {
        operation_octet |= 0x10;
    }
    operation_octet |= count;
    destination.put_u8(operation_octet);

    match value.packet_filters() {
        PacketFilterList::None => {}
        PacketFilterList::Identifiers(identifiers) => {
            for identifier in identifiers {
                destination.put_u8(identifier.value());
            }
        }
        PacketFilterList::Filters(filters) => {
            for filter in filters {
                destination.put_u8((filter.direction().code() << 4) | filter.identifier().value());
                destination.put_u8(filter.evaluation_precedence());
                let contents_len = u8::try_from(filter.contents_len()?)
                    .map_err(|_| TftErrorKind::LengthOverflow)?;
                destination.put_u8(contents_len);
                for component in filter.components() {
                    encode_component(component, destination);
                }
            }
        }
    }

    for parameter in value.parameters() {
        destination.put_u8(parameter.identifier());
        let contents_len =
            u8::try_from(parameter.contents_len()).map_err(|_| TftErrorKind::LengthOverflow)?;
        destination.put_u8(contents_len);
        match parameter {
            TftParameter::AuthorizationToken(token) => destination.put_slice(token.as_bytes()),
            TftParameter::FlowIdentifier(flow) => {
                destination.put_u16(flow.media_component_number());
                destination.put_u16(flow.ip_flow_number());
            }
            TftParameter::PacketFilterIdentifiers(value) => {
                for identifier in value.identifiers() {
                    destination.put_u8(identifier.value());
                }
            }
            TftParameter::Unknown(value) => destination.put_slice(value.contents()),
        }
    }

    destination.put_slice(value.ignored_contents());
    Ok(())
}

fn encode_component(component: &PacketFilterComponent, destination: &mut BytesMut) {
    destination.put_u8(component.kind().type_code());
    match component {
        PacketFilterComponent::Ipv4RemoteAddress { address, mask }
        | PacketFilterComponent::Ipv4LocalAddress { address, mask } => {
            destination.put_slice(&address.octets());
            destination.put_slice(&mask.octets());
        }
        PacketFilterComponent::Ipv6RemoteAddress { address, mask } => {
            destination.put_slice(&address.octets());
            destination.put_slice(&mask.octets());
        }
        PacketFilterComponent::Ipv6RemoteAddressPrefix(value)
        | PacketFilterComponent::Ipv6LocalAddressPrefix(value) => {
            destination.put_slice(&value.address().octets());
            destination.put_u8(value.prefix_length());
        }
        PacketFilterComponent::ProtocolIdentifierNextHeader(value) => {
            destination.put_u8(*value);
        }
        PacketFilterComponent::SingleLocalPort(value)
        | PacketFilterComponent::SingleRemotePort(value) => destination.put_u16(*value),
        PacketFilterComponent::LocalPortRange(value)
        | PacketFilterComponent::RemotePortRange(value) => {
            destination.put_u16(value.low());
            destination.put_u16(value.high());
        }
        PacketFilterComponent::SecurityParameterIndex(value) => destination.put_u32(*value),
        PacketFilterComponent::TypeOfServiceTrafficClass { value, mask } => {
            destination.put_u8(*value);
            destination.put_u8(*mask);
        }
        PacketFilterComponent::FlowLabel(value) => {
            let [_, high, middle, low] = value.value().to_be_bytes();
            destination.put_u8(high);
            destination.put_u8(middle);
            destination.put_u8(low);
        }
        PacketFilterComponent::DestinationMacAddress(value)
        | PacketFilterComponent::SourceMacAddress(value) => destination.put_slice(value),
        PacketFilterComponent::CustomerVlanId(value)
        | PacketFilterComponent::ServiceVlanId(value) => destination.put_u16(value.value()),
        PacketFilterComponent::CustomerVlanPriority(value)
        | PacketFilterComponent::ServiceVlanPriority(value) => {
            destination.put_u8((value.pcp() << 1) | u8::from(value.drop_eligible()));
        }
        PacketFilterComponent::EtherType(value) => destination.put_u16(*value),
    }
}

fn protocol_decode_error(error: TftError) -> DecodeError {
    let offset = error.offset().unwrap_or_default();
    let code = match error.kind() {
        TftErrorKind::Truncated { .. } => DecodeErrorCode::Truncated,
        TftErrorKind::LengthOverflow => DecodeErrorCode::LengthOverflow,
        TftErrorKind::ElementLimitExceeded { .. } => DecodeErrorCode::IeCountExceeded,
        TftErrorKind::InvalidValueLength {
            actual, maximum, ..
        } if actual > maximum => DecodeErrorCode::MessageLengthExceeded,
        TftErrorKind::InvalidValueLength { .. }
        | TftErrorKind::InvalidComponentLength { .. }
        | TftErrorKind::InvalidParameterLength { .. } => DecodeErrorCode::InvalidLength {
            reason: "invalid TFT length",
        },
        TftErrorKind::ReservedOperation { value } => DecodeErrorCode::InvalidEnumValue {
            field: "tft_operation",
            value: u64::from(*value),
        },
        TftErrorKind::ReservedComponentType { component_type } => {
            DecodeErrorCode::InvalidEnumValue {
                field: "tft_component_type",
                value: u64::from(*component_type),
            }
        }
        _ => DecodeErrorCode::Structural {
            reason: "invalid traffic flow template",
        },
    };
    DecodeError::new(code, offset).with_spec_ref(spec_ref())
}

fn protocol_encode_error(error: TftError) -> EncodeError {
    let code = match error.kind() {
        TftErrorKind::LengthOverflow => EncodeErrorCode::LengthOverflow,
        _ => EncodeErrorCode::Structural {
            reason: "invalid traffic flow template",
        },
    };
    EncodeError::new(code).with_spec_ref(spec_ref())
}

impl<'a> BorrowDecode<'a> for TrafficFlowTemplate {
    fn decode(input: &'a [u8], context: DecodeContext) -> DecodeResult<'a, Self> {
        let value =
            Self::decode_value_with_context(input, context).map_err(protocol_decode_error)?;
        Ok((&[], value))
    }
}

impl OwnedDecode for TrafficFlowTemplate {
    fn decode_owned(input: Bytes, context: DecodeContext) -> Result<Self, DecodeError> {
        Self::decode_value_with_context(&input, context).map_err(protocol_decode_error)
    }
}

impl Encode for TrafficFlowTemplate {
    fn encode(
        &self,
        destination: &mut BytesMut,
        context: EncodeContext,
    ) -> Result<(), EncodeError> {
        let length = self.encoded_value_len().map_err(protocol_encode_error)?;
        context.check_capacity(length)?;
        self.encode_value(destination)
            .map_err(protocol_encode_error)
    }

    fn wire_len(&self, context: EncodeContext) -> Result<usize, EncodeError> {
        let length = self.encoded_value_len().map_err(protocol_encode_error)?;
        context.check_capacity(length)?;
        Ok(length)
    }
}
