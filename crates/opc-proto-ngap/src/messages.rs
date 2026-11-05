//! Owned message containers with zeroizing opaque IE values.
//!
//! These retain the public `protocol_ies.0` traversal shape. IE identifiers are
//! uniformly `u16` and criticality is [`Criticality`]. Nested ASN.1 values remain
//! opaque until admitted by the appropriate typed N3IWF field decoder.

use crate::{Criticality, SensitiveBytes};

/// One owned protocol IE. Its opaque value may contain security material.
#[derive(Debug)]
pub struct ProtocolIeField {
    /// Protocol IE identifier.
    pub id: u16,
    /// Criticality received on the wire.
    pub criticality: Criticality,
    /// Encoded value, cleared when dropped or removed by receive policy.
    pub value: SensitiveBytes,
}

/// Selected protocol IEs in receive order, each with independent wiping custody.
#[derive(Debug, Default)]
pub struct ProtocolIeContainer(pub Vec<ProtocolIeField>);

macro_rules! messages {
    ($($name:ident),+ $(,)?) => {$(
        #[doc = concat!("Owned ", stringify!($name), " message body.")]
        #[derive(Debug)]
        pub struct $name {
            /// Policy-selected protocol IE container.
            pub protocol_ies: ProtocolIeContainer,
        }

        impl $name {
            /// Construct a body; enclosing PDU encoding revalidates IE policy.
            pub fn new(protocol_ies: ProtocolIeContainer) -> Self {
                Self { protocol_ies }
            }
        }
    )+};
}

messages! {
    DownlinkNASTransport, ErrorIndication, InitialContextSetupFailure,
    InitialContextSetupRequest, InitialContextSetupResponse, InitialUEMessage,
    NASNonDeliveryIndication, NGReset, NGResetAcknowledge, NGSetupFailure, NGSetupRequest,
    NGSetupResponse, PDUSessionResourceModifyRequest, PDUSessionResourceModifyResponse,
    PDUSessionResourceNotify, PDUSessionResourceReleaseCommand,
    PDUSessionResourceReleaseResponse, PDUSessionResourceSetupRequest,
    PDUSessionResourceSetupResponse, Paging, UEContextReleaseCommand, UEContextReleaseComplete,
    UEContextReleaseRequest, UplinkNASTransport,
}
