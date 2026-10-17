//! Ordinary APCO values for an S2b Create Session exchange.
use opc_proto_gtpv2c::n1_mode::{
    IndicationFlag, N1ModeApcoRequest, N1ModeApcoResponse, PduSessionId, PlmnIdentity, SnssaiValue,
};
use opc_proto_gtpv2c::{AdditionalProtocolConfigurationOptions, Indication};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let request = N1ModeApcoRequest::new(PduSessionId::new(7)?);
    // Preserve an existing DNS IPv4 request while adding the N1 container.
    let existing = AdditionalProtocolConfigurationOptions {
        value: vec![0x80, 0, 0x0d, 0],
    };
    let request_apco = request.append_to(&existing)?;
    assert_eq!(N1ModeApcoRequest::decode(&request_apco)?, Some(request));
    // Supply request_apco to S2bCreateSessionContext::apco. For callers using
    // the typed IE layer, to_s2b_ie emits APCO type 163 at instance zero.
    assert_eq!(request.to_s2b_ie().instance, 0);

    let response = N1ModeApcoResponse::new(
        SnssaiValue::from_bytes(&[1, 0x12, 0x34, 0x56])?,
        PlmnIdentity::from_bytes([0x00, 0xf1, 0x10])?,
    );
    assert_eq!(
        N1ModeApcoResponse::decode(&response.encode_apco())?,
        Some(response)
    );

    let mut indication = Indication { flags: vec![0] };
    indication.set_flag(IndicationFlag::FiveGsInterworking, true);
    indication.set_flag(IndicationFlag::FiveGcNotRestrictedSupport, true);
    assert!(indication.flag(IndicationFlag::FiveGsInterworking));
    // Setting support does not infer the independent network indication.
    assert!(!indication.flag(IndicationFlag::FiveGcNotRestricted));
    Ok(())
}
