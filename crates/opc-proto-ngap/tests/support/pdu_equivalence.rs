//! Explicit comparison of synthetic test values without production equality
//! implementations on security-bearing containers.

use opc_proto_ngap::{messages::ProtocolIeField, Criticality, Message, PduKind};

fn parts(kind: &PduKind) -> (u8, Criticality, &Message) {
    match kind {
        PduKind::Initiating {
            procedure_code,
            criticality,
            message,
        }
        | PduKind::Successful {
            procedure_code,
            criticality,
            message,
        }
        | PduKind::Unsuccessful {
            procedure_code,
            criticality,
            message,
        } => (*procedure_code, *criticality, message),
    }
}

fn entries(message: &Message) -> Option<&[ProtocolIeField]> {
    macro_rules! containers {
        ($($variant:ident),+ $(,)?) => {
            match message {
                $(Message::$variant(value) => Some(&value.protocol_ies.0),)+
                Message::Unknown(_) => None,
            }
        };
    }
    containers! {
        NgSetupRequest, NgSetupResponse, NgSetupFailure, InitialUeMessage,
        UplinkNasTransport, DownlinkNasTransport, NasNonDeliveryIndication,
        InitialContextSetupRequest, InitialContextSetupResponse, InitialContextSetupFailure,
        PduSessionResourceSetupRequest, PduSessionResourceSetupResponse,
        PduSessionResourceModifyRequest, PduSessionResourceModifyResponse,
        PduSessionResourceNotify, PduSessionResourceReleaseCommand,
        PduSessionResourceReleaseResponse, UeContextReleaseRequest,
        UeContextReleaseCommand, UeContextReleaseComplete, ErrorIndication,
        NgReset, NgResetAcknowledge, Paging,
    }
}

pub fn equivalent(left: &PduKind, right: &PduKind) -> bool {
    let (left_code, left_criticality, left_message) = parts(left);
    let (right_code, right_criticality, right_message) = parts(right);
    if std::mem::discriminant(left) != std::mem::discriminant(right)
        || left_code != right_code
        || left_criticality != right_criticality
        || std::mem::discriminant(left_message) != std::mem::discriminant(right_message)
    {
        return false;
    }
    match (entries(left_message), entries(right_message)) {
        (Some(left), Some(right)) => {
            left.len() == right.len()
                && left.iter().zip(right).all(|(left, right)| {
                    left.id == right.id
                        && left.criticality == right.criticality
                        && left.value.as_bytes() == right.value.as_bytes()
                })
        }
        (None, None) => match (left_message, right_message) {
            (Message::Unknown(left), Message::Unknown(right)) => {
                left.as_bytes() == right.as_bytes()
            }
            _ => false,
        },
        _ => false,
    }
}
