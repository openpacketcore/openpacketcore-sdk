//! Shared semantic reconstruction checks for NAS corpus replay and libFuzzer.
use bytes::Bytes;
use opc_proto_ngap::n3iwf::nas::NasMessage;
use opc_proto_ngap::{encode, Pdu};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode};

pub fn reconstruct(message: &NasMessage<'_>, ctx: DecodeContext, output: EncodeContext) {
    let constructed = message.construct(ctx).unwrap();
    let wire = encode(&constructed, output).unwrap();
    let received = Pdu::decode_owned(Bytes::from(wire), ctx).unwrap();
    let readmitted = NasMessage::from_pdu(&received, ctx).unwrap();
    assert_eq!(readmitted.ignored_ie_count, 0);
    assert!(readmitted.notify_ie_ids.is_empty());
    let equal = match (message, &readmitted.message) {
        (
            NasMessage::InitialUe {
                ran: a_ran,
                nas: a_nas,
                location: a_location,
                cause: a_cause,
                selected_plmn: a_plmn,
                context_requested: a_context,
                allowed_nssai: a_allowed,
                partially_allowed_nssai: a_partial,
                selected_nid: a_nid,
                amf_set_id: a_set,
                fiveg_s_tmsi: a_tmsi,
                reroute: a_reroute,
            },
            NasMessage::InitialUe {
                ran: b_ran,
                nas: b_nas,
                location: b_location,
                cause: b_cause,
                selected_plmn: b_plmn,
                context_requested: b_context,
                allowed_nssai: b_allowed,
                partially_allowed_nssai: b_partial,
                selected_nid: b_nid,
                amf_set_id: b_set,
                fiveg_s_tmsi: b_tmsi,
                reroute: b_reroute,
            },
        ) => {
            a_ran == b_ran
                && a_nas.as_bytes() == b_nas.as_bytes()
                && a_location == b_location
                && a_cause == b_cause
                && a_plmn == b_plmn
                && a_context == b_context
                && a_allowed == b_allowed
                && a_partial == b_partial
                && a_nid == b_nid
                && a_set == b_set
                && a_tmsi == b_tmsi
                && a_reroute == b_reroute
        }
        (
            NasMessage::Downlink {
                amf: a_amf,
                ran: a_ran,
                nas: a_nas,
                aggregate_bit_rate: a_rate,
                allowed_nssai: a_allowed,
                old_amf: a_old,
                masked_imeisv: a_masked,
                extended_old_amf: a_extended,
                partially_allowed_nssai: a_partial,
            },
            NasMessage::Downlink {
                amf: b_amf,
                ran: b_ran,
                nas: b_nas,
                aggregate_bit_rate: b_rate,
                allowed_nssai: b_allowed,
                old_amf: b_old,
                masked_imeisv: b_masked,
                extended_old_amf: b_extended,
                partially_allowed_nssai: b_partial,
            },
        ) => {
            a_amf == b_amf
                && a_ran == b_ran
                && a_nas.as_bytes() == b_nas.as_bytes()
                && a_rate == b_rate
                && a_allowed == b_allowed
                && a_old == b_old
                && a_masked == b_masked
                && a_extended == b_extended
                && a_partial == b_partial
        }
        (
            NasMessage::Uplink {
                amf: a_amf,
                ran: a_ran,
                nas: a_nas,
                location: a_location,
            },
            NasMessage::Uplink {
                amf: b_amf,
                ran: b_ran,
                nas: b_nas,
                location: b_location,
            },
        ) => {
            a_amf == b_amf
                && a_ran == b_ran
                && a_nas.as_bytes() == b_nas.as_bytes()
                && a_location == b_location
        }
        _ => false,
    };
    assert!(equal, "admitted NAS field changed during reconstruction");
}
