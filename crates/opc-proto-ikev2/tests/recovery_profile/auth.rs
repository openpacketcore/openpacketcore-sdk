//! Final authenticated exchange inputs after the fixture's completed EAP rounds.
//! Signed octets and verified identity are explicit prior-handshake inputs; this
//! fixture qualifies their durable hand-off, not an AAA or EAP implementation.

use super::{envelope::Error, ke, row::Row, wire::Packet};
use bytes::Bytes;
use opc_proto_ikev2::{
    build_ike_auth_authentication_payload, build_ike_auth_cleartext_payload_chain,
    build_ike_auth_identification_payload, build_ike_auth_sa_payload,
    build_ike_auth_traffic_selector_payload, compute_ike_auth_shared_key_mic,
    decode_ike_auth_cleartext_payloads, verify_ike_auth_shared_key_mic,
    Ikev2AuthenticationPayloadBuild as AuthBuild, Ikev2IdentificationPayloadBuild as IdBuild,
    Ikev2IkeAuthPayloadBuild as Payload, Ikev2IkeAuthPeer as Peer,
    Ikev2IkeAuthSignedOctets as Signed, Ikev2ProtectedPayloadDirection as Direction, PayloadType,
    IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
};

pub const FINAL_ID: u32 = 5;
const AUTH_KEY: &[u8] = &[0x95; 64];

pub fn initiator(row: &Row) -> bool {
    row.direction == Direction::InitiatorToResponder
}

pub fn before_final(mut row: Row) -> Row {
    let (send, receive) = if initiator(&row) {
        (FINAL_ID, 0)
    } else {
        (0, FINAL_ID)
    };
    row.window.next_send = Some(send);
    row.window.next_receive = Some(receive);
    if let Some(sync) = &mut row.window.sync {
        sync.local_request = send.checked_sub(1);
        sync.peer_request = receive.checked_sub(1);
    }
    row.validate().unwrap();
    row
}

pub fn identity(response: bool) -> Vec<u8> {
    build_ike_auth_identification_payload(&IdBuild {
        id_type: 2,
        id_data: if response {
            b"gateway.example".to_vec()
        } else {
            b"peer.example".to_vec()
        },
    })
    .unwrap()
}

fn signed(response: bool, id: &[u8]) -> Signed<'_> {
    Signed {
        peer: if response {
            Peer::Responder
        } else {
            Peer::Initiator
        },
        ike_sa_init_message: if response {
            b"fixture-exact-initial-response"
        } else {
            b"fixture-exact-initial-request"
        },
        peer_nonce: if response { &[0x31; 64] } else { &[0x62; 64] },
        identity_payload_body: id,
    }
}

pub fn payload(row: &Row, response: bool) -> (PayloadType, Bytes) {
    let id = identity(response);
    let mic =
        compute_ike_auth_shared_key_mic(row.profile, &row.keys, signed(response, &id), AUTH_KEY)
            .unwrap();
    let mut entries = vec![Payload {
        payload_type: PayloadType::Authentication,
        body: build_ike_auth_authentication_payload(&AuthBuild {
            auth_method: IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
            auth_data: mic,
        })
        .unwrap(),
    }];
    if response {
        let mut sa = ke::child_sa(row, row.profile.dh_group(), 0x2526_2728);
        // The first Child uses the IKE_AUTH key material and no independent KE.
        sa.proposals[0].transforms.retain(|t| t.transform_type != 4);
        entries.push(Payload {
            payload_type: PayloadType::SecurityAssociation,
            body: build_ike_auth_sa_payload(&sa).unwrap(),
        });
        for (kind, sender) in [
            (PayloadType::TrafficSelectorInitiator, true),
            (PayloadType::TrafficSelectorResponder, false),
        ] {
            entries.push(Payload {
                payload_type: kind,
                body: build_ike_auth_traffic_selector_payload(&ke::selectors(sender)).unwrap(),
            });
        }
    }
    build_ike_auth_cleartext_payload_chain(&entries).unwrap()
}

pub fn verify(row: &Row, packet: &Packet, response: bool) -> Result<(), Error> {
    if packet.header.exchange_type != 35
        || packet.header.message_id != FINAL_ID
        || packet.header.flags.response() != response
    {
        return Err(Error::Format);
    }
    let payloads = decode_ike_auth_cleartext_payloads(packet.first, &packet.body)
        .map_err(|_| Error::Format)?;
    if payloads.authentications.len() != 1 {
        return Err(Error::Format);
    }
    let id = identity(response);
    verify_ike_auth_shared_key_mic(
        row.profile,
        &row.keys,
        signed(response, &id),
        AUTH_KEY,
        &payloads.authentications[0],
    )
    .map_err(|_| Error::Integrity)?;
    let (first, expected) = payload(row, response);
    if packet.first != first || packet.body != expected {
        return Err(Error::Format);
    }
    Ok(())
}
