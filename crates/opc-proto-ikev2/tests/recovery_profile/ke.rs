//! KE operation planning through SDK payload builders and KDFs. Only the
//! initiating operation has a row checkpoint; no private handle leaves a call.

use super::{
    authority::Transport,
    driver::{self, Cut, Runtime},
    envelope::{Error, Provider},
    row::{KeKind, Operation, Outcome, Row},
    store::CasStore,
    wire::{Packet, Wire, WireError},
};
use bytes::Bytes;
use opc_proto_ikev2::{
    build_create_child_sa_rekey_request_payloads, build_create_child_sa_rekey_response_payloads,
    build_delete_payload_body, build_ike_auth_cleartext_payload_chain, build_ike_auth_sa_payload,
    build_ike_sa_rekey_request, decode_ike_sa_rekey_response, derive_child_sa_key_material,
    derive_ike_sa_rekey_key_material, Ikev2ChildSaCryptoProfile as ChildProfile,
    Ikev2CreateChildSaRekeyRequestBuild as ChildRequest,
    Ikev2CreateChildSaRekeyResponseBuild as ChildResponse, Ikev2DhGroup as Group,
    Ikev2EphemeralDhKey as Dh, Ikev2ExchangeKind as Exchange,
    Ikev2IkeAuthPayloadBuild as PayloadBuild, Ikev2IkeSaRekeyRequestBuild as IkeRequest,
    Ikev2IkeSaRekeySentRequest as Sent, Ikev2KeyExchangePayload as KePayload,
    Ikev2KeyExchangePayloadBuild as KeBuild, Ikev2NoncePayload as Nonce,
    Ikev2NoncePayloadBuild as NonceBuild, Ikev2SaPayload as SaPayload,
    Ikev2SaPayloadBuild as SaBuild, Ikev2SaProposalBuild as Proposal,
    Ikev2SaTransformBuild as Transform, Ikev2TrafficSelectorBuild as Selector,
    Ikev2TrafficSelectorPayloadBuild as Selectors, Ikev2TransformAttributeBuild as Attribute,
    Ikev2TransformAttributeBuildValue as AttributeValue, PayloadChain, PayloadType,
};
use zeroize::Zeroizing;

fn crypto_error(error: opc_proto_ikev2::Ikev2SaInitCryptoError) -> Error {
    use opc_crypto_provider::CryptoOperationErrorCode as Code;
    use opc_proto_ikev2::{Ikev2CryptoModuleErrorCode as ModuleCode, Ikev2SaInitCryptoError};
    match error {
        Ikev2SaInitCryptoError::InvalidPeerPublicKey { .. }
        | Ikev2SaInitCryptoError::MalformedKeyExchange { .. }
        | Ikev2SaInitCryptoError::KeyAgreementFailed { .. } => Error::PeerKeyExchange,
        Ikev2SaInitCryptoError::CryptoModuleFailure { error }
            if error.code() == ModuleCode::InvalidOutput
                || matches!(
                    error.operation_code(),
                    Some(Code::InvalidCheckpoint | Code::CheckpointPublicValueMismatch)
                ) =>
        {
            Error::Integrity
        }
        // Module health, capability, admission and generation failures do not
        // prove loss of the committed checkpoint. Identity/validation changes
        // also require a process-level alarm and admission stop, never SA loss.
        // Key revocation and positive NotFound are classified by the envelope.
        Ikev2SaInitCryptoError::CryptoModuleFailure { .. }
        | Ikev2SaInitCryptoError::KeyGenerationFailed { .. } => Error::Backpressure,
        _ => Error::Format,
    }
}

#[test]
fn invalid_peer_ke_is_never_backpressure() {
    use opc_proto_ikev2::Ikev2SaInitCryptoError as Crypto;
    let group = Group::Ecp256;
    for error in [
        Crypto::InvalidPeerPublicKey {
            group,
            actual_len: 64,
        },
        Crypto::MalformedKeyExchange {
            group,
            expected_len: 64,
            actual_len: 63,
        },
        Crypto::KeyAgreementFailed { group },
    ] {
        assert_eq!(crypto_error(error), Error::PeerKeyExchange);
    }
}

pub const INVALID_SYNTAX: &[u8] = &[0, 0, 0, 8, 0, 0, 0, 7];

fn invalid_syntax(packet: &Packet) -> bool {
    packet.header.exchange_type == 36
        && packet.header.flags.response()
        && packet.first == PayloadType::Notify
        && packet.body.as_ref() == INVALID_SYNTAX
}

fn wire_error(error: WireError, invalid: Error) -> Error {
    match error {
        WireError::CryptoModule(error) => {
            crypto_error(opc_proto_ikev2::Ikev2SaInitCryptoError::CryptoModuleFailure { error })
        }
        _ => invalid,
    }
}

#[test]
fn key_generation_failure_is_backpressure() {
    assert_eq!(
        crypto_error(
            opc_proto_ikev2::Ikev2SaInitCryptoError::KeyGenerationFailed {
                group: Group::Ecp256
            }
        ),
        Error::Backpressure
    );
}

pub const GROUPS: [Group; 6] = [
    Group::Modp768,
    Group::Modp1024,
    Group::Modp2048,
    Group::Ecp256,
    Group::Ecp384,
    Group::Ecp521,
];
pub const KINDS: [KeKind; 3] = [KeKind::NewChild, KeKind::ChildRekey, KeKind::IkeRekey];

pub fn selectors(initiator: bool) -> Selectors {
    let address = if initiator {
        vec![192, 0, 2, 10]
    } else {
        vec![198, 51, 100, 20]
    };
    Selectors {
        selectors: vec![Selector {
            ts_type: 7,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: u16::MAX,
            start_address: address.clone(),
            end_address: address,
        }],
    }
}
pub fn child_sa(row: &Row, group: Group, spi: u64) -> SaBuild {
    let mut transforms = vec![Transform {
        transform_type: 1,
        transform_id: row.profile.encryption().transform_id(),
        attributes: vec![Attribute {
            attribute_type: 14,
            value: AttributeValue::Tv(row.profile.encryption().key_bits()),
        }],
    }];
    if let Some(integrity) = row.profile.integrity() {
        transforms.push(Transform {
            transform_type: 3,
            transform_id: integrity.transform_id(),
            attributes: vec![],
        });
    }
    transforms.push(Transform {
        transform_type: 4,
        transform_id: group.transform_id(),
        attributes: vec![],
    });
    transforms.push(Transform {
        transform_type: 5,
        transform_id: 0,
        attributes: vec![],
    });
    SaBuild {
        proposals: vec![Proposal {
            proposal_number: 1,
            protocol_id: 3,
            spi: u32::try_from(spi).unwrap().to_be_bytes().to_vec(),
            transforms,
        }],
    }
}

pub fn payload(
    row: &Row,
    kind: KeKind,
    response: bool,
    group: Group,
    spi: u64,
    nonce: &[u8],
    public: &[u8],
) -> (PayloadType, Bytes) {
    let ke = KeBuild {
        dh_group: group.transform_id(),
        key_exchange_data: public.to_vec(),
    };
    let nonce = NonceBuild {
        nonce: nonce.to_vec(),
    };
    if kind == KeKind::IkeRekey {
        // Both directions have the exact SA, Nonce, KE cleartext shape. The
        // response boundary below checks the selected proposal against the offer.
        return build_ike_sa_rekey_request(&IkeRequest {
            profile: row.profile,
            new_initiator_spi: spi.to_be_bytes(),
            nonce,
            key_exchange: ke,
        })
        .unwrap()
        .into_parts();
    }
    let sa = child_sa(row, group, spi);
    let mut entries = if response {
        build_create_child_sa_rekey_response_payloads(&ChildResponse {
            security_association: sa,
            nonce,
            key_exchange: Some(ke),
            traffic_selectors_initiator: selectors(true),
            traffic_selectors_responder: selectors(false),
        })
        .unwrap()
        .into_payloads()
    } else {
        build_create_child_sa_rekey_request_payloads(&ChildRequest {
            rekeyed_protocol_id: 3,
            rekeyed_spi: vec![0x11, 0x12, 0x13, 0x14],
            security_association: sa,
            nonce,
            key_exchange: Some(ke),
            traffic_selectors_initiator: selectors(true),
            traffic_selectors_responder: selectors(false),
        })
        .unwrap()
        .into_payloads()
    };
    if !response && kind == KeKind::NewChild {
        entries.remove(0);
    }
    build_ike_auth_cleartext_payload_chain(&entries).unwrap()
}

pub struct Parts {
    pub spi: u64,
    pub nonce: Vec<u8>,
    pub public: Vec<u8>,
}

/// Strict selected fixture profile: exact SA/Nonce/KE/selectors and correlation.
/// Generic SDK packet/crypto codecs are shared; peer counters remain independent.
pub fn parts(
    row: &Row,
    kind: KeKind,
    group: Group,
    packet: &Packet,
    response: bool,
) -> Result<Parts, Error> {
    if packet.header.exchange_type != 36 || packet.header.flags.response() != response {
        return Err(Error::Format);
    }
    let entries = PayloadChain::new(packet.first, &packet.body)
        .iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Format)?;
    let offset = usize::from(kind == KeKind::ChildRekey && !response);
    if entries.len() != offset + if kind == KeKind::IkeRekey { 3 } else { 5 }
        || entries[offset].payload_type != PayloadType::SecurityAssociation
        || entries[offset + 1].payload_type != PayloadType::Nonce
        || entries[offset + 2].payload_type != PayloadType::KeyExchange
    {
        return Err(Error::Format);
    }
    let sa = SaPayload::decode_body(entries[offset].body).map_err(|_| Error::Format)?;
    if sa.proposals.len() != 1 {
        return Err(Error::Format);
    }
    let proposal = &sa.proposals[0];
    let spi = if kind == KeKind::IkeRekey {
        if proposal.protocol_id != 1 {
            return Err(Error::Format);
        }
        u64::from_be_bytes(proposal.spi.try_into().map_err(|_| Error::Format)?)
    } else {
        if proposal.protocol_id != 3 {
            return Err(Error::Format);
        }
        u64::from(u32::from_be_bytes(
            proposal.spi.try_into().map_err(|_| Error::Format)?,
        ))
    };
    if spi == 0 {
        return Err(Error::Format);
    }
    let nonce = Nonce::decode_body(entries[offset + 1].body)
        .map_err(|_| Error::Format)?
        .nonce;
    let ke = KePayload::decode_body(entries[offset + 2].body).map_err(|_| Error::Format)?;
    if ke.dh_group != group.transform_id() {
        return Err(Error::Format);
    }
    // Keep all proposal/selector/framing checks, but let agreement classify a
    // wrong-width peer value as a protocol error. The IKE builder itself only
    // accepts fixed-width values, so normalize that one field for comparison.
    let wrong_width = ke.key_exchange_data.len() != group.public_value_len();
    let placeholder = vec![0; group.public_value_len()];
    let (first, mut rebuilt) = payload(
        row,
        kind,
        response,
        group,
        spi,
        nonce,
        if wrong_width {
            &placeholder
        } else {
            ke.key_exchange_data
        },
    );
    if wrong_width {
        let entries = PayloadChain::new(first, &rebuilt)
            .iter()
            .map(|entry| {
                let entry = entry.unwrap();
                let mut body = entry.body.to_vec();
                if entry.payload_type == PayloadType::KeyExchange {
                    body.truncate(4);
                    body.extend_from_slice(ke.key_exchange_data);
                }
                PayloadBuild {
                    payload_type: entry.payload_type,
                    body,
                }
            })
            .collect::<Vec<_>>();
        rebuilt = build_ike_auth_cleartext_payload_chain(&entries)
            .map_err(|_| Error::Format)?
            .1;
    }
    if packet.first != first || packet.body != rebuilt {
        return Err(Error::Format);
    }
    if kind == KeKind::IkeRekey && response && !wrong_width {
        decode_ike_sa_rekey_response(
            &packet.header,
            &Sent {
                old_initiator_spi: row.spis.0,
                old_responder_spi: row.spis.1,
                profile: row.profile,
            },
            packet.first,
            &packet.body,
        )
        .map_err(|_| Error::Format)?;
    } else if kind != KeKind::IkeRekey
        && build_ike_auth_sa_payload(&child_sa(row, group, spi)).map_err(|_| Error::Format)?
            != entries[offset].body
    {
        return Err(Error::Format);
    }
    Ok(Parts {
        spi,
        nonce: nonce.to_vec(),
        public: ke.key_exchange_data.to_vec(),
    })
}

pub fn draft(row: &Row, id: u64, kind: KeKind) -> Operation {
    try_draft(row, id, kind).unwrap()
}

pub fn try_draft(row: &Row, id: u64, kind: KeKind) -> Result<Operation, Error> {
    let group = row.profile.dh_group();
    Dh::checkpoint_readiness(group).map_err(|error| {
        crypto_error(opc_proto_ikev2::Ikev2SaInitCryptoError::CryptoModuleFailure { error })
    })?;
    let mut dh = Dh::generate(group).map_err(crypto_error)?;
    let nonce_i = vec![0x41; 64];
    let spi = if kind == KeKind::IkeRekey {
        0x3132_3334_3536_3738
    } else {
        0x3132_3334
    };
    let public = dh.public_value().to_vec();
    let checkpoint = dh.export_private_checkpoint().map_err(crypto_error)?;
    drop(dh);
    let (first, transcript) = payload(row, kind, false, group, spi, &nonce_i, &public);
    Ok(Operation {
        id,
        kind,
        initiated_here: true,
        group,
        public,
        nonce_i,
        nonce_r: vec![],
        spis: (spi, 0),
        first_payload: first.as_u8(),
        transcript,
        checkpoint: Some(checkpoint),
        outcome: Outcome::Pending,
        derived: None,
    })
}

pub fn persist_ke(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    operation: Operation,
    cut: Cut,
) -> Result<bool, driver::Error> {
    runtime.permit().check()?;
    let control = operation.kind == KeKind::IkeRekey;
    let transcript = operation.transcript.clone();
    let payload = PayloadChain::new(PayloadType::from_u8(operation.first_payload), &transcript);
    let update = |row: &mut Row| {
        row.operations.insert(operation.id, operation);
    };
    if control {
        runtime.publish_control_request(
            provider,
            store,
            Exchange::CreateChildSa,
            payload,
            update,
            cut,
        )
    } else {
        runtime.publish_request(
            provider,
            store,
            Exchange::CreateChildSa,
            payload,
            update,
            cut,
        )
    }
}

pub fn derive(
    row: &Row,
    kind: KeKind,
    spis: (u64, u64),
    nonce_i: &[u8],
    nonce_r: &[u8],
    secret: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(1024));
    if kind == KeKind::IkeRekey {
        let keys = derive_ike_sa_rekey_key_material(
            row.profile.prf(),
            row.keys.sk_d(),
            row.profile,
            spis.0.to_be_bytes(),
            spis.1.to_be_bytes(),
            nonce_i,
            nonce_r,
            secret,
        )
        .unwrap();
        for key in [
            keys.sk_d(),
            keys.sk_ai(),
            keys.sk_ar(),
            keys.sk_ei(),
            keys.sk_er(),
            keys.sk_pi(),
            keys.sk_pr(),
        ] {
            bytes.extend_from_slice(key);
        }
    } else {
        let profile = ChildProfile::from_transform_ids(
            row.profile.prf().transform_id(),
            row.profile.encryption().transform_id(),
            Some(row.profile.encryption().key_bits()),
            row.profile.integrity().map(|i| i.transform_id()),
        )
        .unwrap();
        let keys =
            derive_child_sa_key_material(profile, row.keys.sk_d(), nonce_i, nonce_r, Some(secret))
                .unwrap();
        for key in [
            keys.initiator_to_responder_encryption(),
            keys.initiator_to_responder_integrity(),
            keys.responder_to_initiator_encryption(),
            keys.responder_to_initiator_integrity(),
        ] {
            bytes.extend_from_slice(key);
        }
    }
    bytes
}

/// No operation/private material is included in any diagnostic representation.
pub fn restore_checkpoint(runtime: &Runtime, operation: &Operation) -> Result<Dh, Error> {
    runtime.permit().check().map_err(|_| Error::Format)?;
    let row = &runtime.row;
    let request = row.window.outbound.as_ref().ok_or(Error::Format)?;
    if operation.outcome != Outcome::Pending || request.response().is_some() {
        return Err(Error::Format);
    }
    let wire = Wire::new(
        row.profile,
        &row.keys,
        row.spis,
        crate::canonical_fixtures::opposite(row.direction),
    );
    let opened = wire
        .open(request.request())
        .map_err(|error| wire_error(error, Error::Format))?;
    let fields = parts(row, operation.kind, operation.group, &opened, false)?;
    if opened.first.as_u8() != operation.first_payload
        || opened.body != operation.transcript
        || fields.spi != operation.spis.0
        || fields.nonce != operation.nonce_i
        || fields.public != operation.public
    {
        return Err(Error::Format);
    }
    Dh::import_private_checkpoint(
        operation.group,
        operation.checkpoint.as_ref().ok_or(Error::Format)?,
        &operation.public,
    )
    .map_err(crypto_error)
}

pub fn finish_operation(
    row: &mut Row,
    id: u64,
    outcome: Outcome,
    derived: Option<Zeroizing<Vec<u8>>>,
) {
    settle_operation(row.operations.get_mut(&id).unwrap(), outcome, derived);
}

fn settle_operation(
    operation: &mut Operation,
    outcome: Outcome,
    derived: Option<Zeroizing<Vec<u8>>>,
) {
    operation.outcome = outcome;
    operation.checkpoint = None;
    operation.derived = derived;
}

pub fn plan_initiator(
    runtime: &Runtime,
    id: u64,
    response: &[u8],
) -> Result<Operation, driver::Error> {
    let row = &runtime.row;
    let operation = row.operations.get(&id).ok_or(Error::Format)?;
    let packet = Wire::new(row.profile, &row.keys, row.spis, row.direction)
        .open(response)
        .map_err(|error| wire_error(error, Error::Integrity))?;
    let request = Wire::new(
        row.profile,
        &row.keys,
        row.spis,
        crate::canonical_fixtures::opposite(row.direction),
    )
    .open(row.window.outbound.as_ref().ok_or(Error::Format)?.request())
    .map_err(|error| wire_error(error, Error::Integrity))?;
    if packet.header.message_id != request.header.message_id
        || operation.outcome != Outcome::Pending
        || operation.transcript != request.body
        || operation.first_payload != request.first.as_u8()
    {
        return Err(Error::Format.into());
    }
    if invalid_syntax(&packet) {
        let mut completed = operation.clone();
        settle_operation(&mut completed, Outcome::InvalidSyntax, None);
        return Ok(completed);
    }
    let parts = parts(row, operation.kind, operation.group, &packet, true)?;
    let private = restore_checkpoint(runtime, operation)?;
    let secret = private.agree(&parts.public).map_err(crypto_error);
    drop(private);
    let mut completed = operation.clone();
    match secret {
        Ok(secret) => {
            let derived = derive(
                row,
                operation.kind,
                (operation.spis.0, parts.spi),
                &operation.nonce_i,
                &parts.nonce,
                &secret,
            );
            settle_operation(&mut completed, Outcome::Success, Some(derived));
        }
        Err(Error::PeerKeyExchange) => {
            settle_operation(&mut completed, Outcome::PeerKeRejected, None);
        }
        Err(error) => return Err(error.into()),
    }
    completed.nonce_r = parts.nonce;
    completed.spis.1 = parts.spi;
    Ok(completed)
}

pub fn complete_initiator(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    id: u64,
    response: &[u8],
    cut: Cut,
) -> Result<Option<Bytes>, driver::Error> {
    let completed = plan_initiator(runtime, id, response)?;
    commit_initiator_plan(runtime, provider, store, completed, response, cut)
}

pub fn close_row(row: &mut Row) {
    for operation in row.operations.values_mut() {
        if operation.outcome == Outcome::Pending {
            settle_operation(operation, Outcome::Abandoned, None);
        }
    }
    row.closed = true;
}

pub fn commit_initiator_plan(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    completed: Operation,
    response: &[u8],
    cut: Cut,
) -> Result<Option<Bytes>, driver::Error> {
    let failed = completed.outcome != Outcome::Success;
    let close = completed.outcome == Outcome::InvalidSyntax
        || (failed && completed.kind == KeKind::IkeRekey);
    runtime.complete(
        provider,
        store,
        response,
        Bytes::from_static(if failed {
            b"peer-ke-rejected"
        } else {
            b"ke-established"
        }),
        |row| {
            row.operations.insert(completed.id, completed);
            if close {
                close_row(row);
            }
        },
        cut,
    )
}

/// The responder derives and discards its private handle before one response
/// commit. Its operation row contains derived keys and no private checkpoint.
pub fn plan_responder(
    runtime: &Runtime,
    id: u64,
    kind: KeKind,
    request: &[u8],
) -> Result<(Operation, PayloadType, Bytes), Error> {
    runtime.permit().check().map_err(|_| Error::Format)?;
    let row = &runtime.row;
    let group = row.profile.dh_group();
    let packet = Wire::new(row.profile, &row.keys, row.spis, row.direction)
        .open(request)
        .map_err(|error| wire_error(error, Error::Integrity))?;
    let parts = parts(row, kind, group, &packet, false)?;
    let private = Dh::generate(group).map_err(crypto_error)?;
    let public = private.public_value().to_vec();
    let nonce_r = vec![0x82; 64];
    let spi = if kind == KeKind::IkeRekey {
        0x5152_5354_5556_5758
    } else {
        0x5152_5354
    };
    let secret = private.agree(&parts.public).map_err(crypto_error);
    drop(private);
    let (outcome, derived) = match secret {
        Ok(secret) => (
            Outcome::Success,
            Some(derive(
                row,
                kind,
                (parts.spi, spi),
                &parts.nonce,
                &nonce_r,
                &secret,
            )),
        ),
        Err(Error::PeerKeyExchange) => (Outcome::InvalidSyntax, None),
        Err(error) => return Err(error),
    };
    let (first, reply) = if outcome == Outcome::Success {
        payload(row, kind, true, group, spi, &nonce_r, &public)
    } else {
        (PayloadType::Notify, Bytes::from_static(INVALID_SYNTAX))
    };
    let mut operation = Operation {
        id,
        kind,
        initiated_here: false,
        group,
        public,
        nonce_i: parts.nonce,
        nonce_r,
        spis: (parts.spi, spi),
        first_payload: packet.first.as_u8(),
        transcript: packet.body,
        checkpoint: None,
        outcome,
        derived,
    };
    if outcome == Outcome::InvalidSyntax {
        operation.spis.1 = 0;
        operation.nonce_r.clear();
    }
    Ok((operation, first, reply))
}

pub fn commit_responder(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    id: u64,
    kind: KeKind,
    request: &[u8],
    cut: Cut,
) -> Result<Option<Bytes>, driver::Error> {
    let (operation, first, reply) = plan_responder(runtime, id, kind, request)?;
    commit_responder_plan(
        runtime, provider, store, operation, request, first, &reply, cut,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep the planned reply and fault cut explicit."
)]
pub fn commit_responder_plan(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    operation: Operation,
    request: &[u8],
    first: PayloadType,
    reply: &[u8],
    cut: Cut,
) -> Result<Option<Bytes>, driver::Error> {
    if operation.outcome == Outcome::InvalidSyntax {
        return runtime.publish_error_response(
            provider,
            store,
            request,
            PayloadChain::new(first, reply),
            |row| {
                row.operations.insert(operation.id, operation);
            },
            cut,
        );
    }
    runtime.publish_response(
        provider,
        store,
        request,
        PayloadChain::new(first, reply),
        Bytes::from_static(b"ke-established"),
        |row| {
            row.operations.insert(operation.id, operation);
        },
        cut,
    )
}

fn failed_child(row: &Row, id: u64) -> Result<&Operation, Error> {
    let operation = row.operations.get(&id).ok_or(Error::Format)?;
    if !operation.initiated_here
        || operation.kind == KeKind::IkeRekey
        || !matches!(
            operation.outcome,
            Outcome::PeerKeRejected | Outcome::PeerKeDeleted
        )
    {
        return Err(Error::Format);
    }
    Ok(operation)
}

fn child_delete(spi: u64) -> Result<(PayloadType, Bytes), Error> {
    let spi = u32::try_from(spi).map_err(|_| Error::Format)?.to_be_bytes();
    let body = build_delete_payload_body(3, 4, &[&spi]).map_err(|_| Error::Format)?;
    build_ike_auth_cleartext_payload_chain(&[PayloadBuild {
        payload_type: PayloadType::Delete,
        body,
    }])
    .map_err(|_| Error::Format)
}

/// The terminal KE row is also the durable cleanup intent. RFC 7296 section
/// 3.11 sends our inbound SPI, not the peer's inbound SPI. A committed Delete
/// is replayed after loss; no retry can allocate a second Message ID for it.
#[expect(
    clippy::too_many_arguments,
    reason = "Keep cleanup identity and fault boundaries explicit."
)]
pub fn send_failed_child_delete(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    id: u64,
    cleanup_id: u64,
    now: u64,
    cut: Cut,
    transport: &mut Transport,
) -> Result<bool, driver::Error> {
    let operation = failed_child(&runtime.row, id)?;
    if operation.outcome == Outcome::PeerKeDeleted {
        return Ok(false);
    }
    let (first, body) = child_delete(operation.spis.0)?;
    if let Some(entry) = &runtime.row.window.outbound {
        if entry.response().is_none() {
            let request = Wire::new(
                runtime.row.profile,
                &runtime.row.keys,
                runtime.row.spis,
                crate::canonical_fixtures::opposite(runtime.row.direction),
            )
            .open(entry.request())
            .map_err(|error| wire_error(error, Error::Integrity))?;
            if request.header.exchange_type != 37 || request.first != first || request.body != body
            {
                return Err(opc_proto_ikev2::recovery::Ikev2WindowError::RequestOutstanding.into());
            }
            return runtime.dispatch_replay(transport);
        }
    }
    runtime.reserve_control(
        provider,
        store,
        cleanup_id,
        1,
        now,
        Cut::Complete,
        Cut::Complete,
    )?;
    if !runtime.publish_control_request(
        provider,
        store,
        Exchange::Informational,
        PayloadChain::new(first, &body),
        |_| {},
        cut,
    )? {
        return Ok(false);
    }
    runtime.dispatch_replay(transport)
}

pub fn finish_failed_child_delete(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    id: u64,
    response: &[u8],
    cut: Cut,
) -> Result<Option<Bytes>, driver::Error> {
    let row = &runtime.row;
    let operation = failed_child(row, id)?;
    if operation.outcome == Outcome::PeerKeDeleted {
        return Ok(None);
    }
    let entry = row.window.outbound.as_ref().ok_or(Error::Format)?;
    let request = Wire::new(
        row.profile,
        &row.keys,
        row.spis,
        crate::canonical_fixtures::opposite(row.direction),
    )
    .open(entry.request())
    .map_err(|error| wire_error(error, Error::Integrity))?;
    let expected = child_delete(operation.spis.0)?;
    if entry.response().is_some()
        || request.header.exchange_type != 37
        || request.first != expected.0
        || request.body != expected.1
    {
        return Err(Error::Format.into());
    }
    let packet = Wire::new(row.profile, &row.keys, row.spis, row.direction)
        .open(response)
        .map_err(|error| wire_error(error, Error::Integrity))?;
    let paired = child_delete(operation.spis.1)?;
    if packet.header.exchange_type != 37
        || !packet.header.flags.response()
        || packet.header.message_id != request.header.message_id
        || !((packet.first == PayloadType::NoNext && packet.body.is_empty())
            || (packet.first == paired.0 && packet.body == paired.1))
    {
        return Err(Error::Format.into());
    }
    runtime.complete(
        provider,
        store,
        response,
        Bytes::from_static(b"peer-child-deleted"),
        |row| finish_operation(row, id, Outcome::PeerKeDeleted, None),
        cut,
    )
}

pub fn checkpoint_diagnostics(operation: &Operation) -> String {
    format!("{operation:?}")
}

/// A present but empty operation map is not a valid omission of the operation
/// associated with an authenticated KE exchange. Bind the entire retained
/// transcript before a reconstructed runtime can replay any packet.
pub fn validate_row(row: &Row) -> Result<(), Error> {
    let mut pending_matches = 0;
    for (entry, local) in [
        (row.window.outbound.as_ref(), true),
        (row.window.inbound.as_ref(), false),
    ] {
        let Some(entry) = entry else {
            continue;
        };
        let sending = if local {
            crate::canonical_fixtures::opposite(row.direction)
        } else {
            row.direction
        };
        let packet = Wire::new(row.profile, &row.keys, row.spis, sending)
            .open(entry.request())
            .map_err(|error| wire_error(error, Error::Integrity))?;
        let has_ke = PayloadChain::new(packet.first, &packet.body)
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Format)?
            .iter()
            .any(|payload| payload.payload_type == PayloadType::KeyExchange);
        if !has_ke {
            continue;
        }
        let matching: Vec<_> = row
            .operations
            .values()
            .filter(|op| {
                op.initiated_here == local
                    && op.transcript == packet.body
                    && op.first_payload == packet.first.as_u8()
            })
            .collect();
        if matching.len() != 1 {
            return Err(Error::Format);
        }
        let operation = matching[0];
        pending_matches += usize::from(operation.outcome == Outcome::Pending);
        let request = parts(row, operation.kind, operation.group, &packet, false)?;
        if (request.public.len() != operation.group.public_value_len()
            && (local || operation.outcome != Outcome::InvalidSyntax))
            || operation.spis.0 != request.spi
            || operation.nonce_i != request.nonce
            || (local && operation.public != request.public)
            || (local
                && entry.response().is_none()
                && operation.outcome != Outcome::Pending
                && !row.closed)
            || (local && entry.response().is_some() && operation.outcome == Outcome::Pending)
            || (!local && operation.checkpoint.is_some())
        {
            return Err(Error::Format);
        }
        if matches!(
            operation.outcome,
            Outcome::Success | Outcome::PeerKeRejected | Outcome::InvalidSyntax
        ) {
            let response = Wire::new(
                row.profile,
                &row.keys,
                row.spis,
                crate::canonical_fixtures::opposite(sending),
            )
            .open(entry.response().ok_or(Error::Format)?)
            .map_err(|_| Error::Integrity)?;
            if response.header.message_id != packet.header.message_id {
                return Err(Error::Format);
            }
            if operation.outcome == Outcome::InvalidSyntax {
                if !invalid_syntax(&response) || (local && !row.closed) {
                    return Err(Error::Format);
                }
                continue;
            }
            let reply = parts(row, operation.kind, operation.group, &response, true)?;
            if operation.spis.1 != reply.spi
                || operation.nonce_r != reply.nonce
                || (!local && operation.public != reply.public)
                || (operation.outcome == Outcome::PeerKeRejected && !local)
                || (operation.outcome == Outcome::Success
                    && reply.public.len() != operation.group.public_value_len())
            {
                return Err(Error::Format);
            }
        }
    }
    if pending_matches
        != row
            .operations
            .values()
            .filter(|op| op.outcome == Outcome::Pending)
            .count()
    {
        return Err(Error::Format);
    }
    Ok(())
}
