#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_gtpv2c::n1_mode::{
    N1ModeApcoRequest, N1ModeApcoResponse, PduSessionId, N1_MODE_APCO_MAX_CONTENTS_LEN,
};
use opc_proto_gtpv2c::AdditionalProtocolConfigurationOptions;

fuzz_target!(|data: &[u8]| {
    // Include the first over-limit length, without allocating unbounded input.
    if data.len() > N1_MODE_APCO_MAX_CONTENTS_LEN + 1 {
        return;
    }
    let apco = AdditionalProtocolConfigurationOptions {
        value: data.to_vec(),
    };
    if let Ok(Some(value)) = N1ModeApcoRequest::decode(&apco) {
        assert_eq!(
            N1ModeApcoRequest::decode(&value.encode_apco()),
            Ok(Some(value))
        );
        assert!(value.append_to(&apco).is_err());
    }
    if let Ok(Some(value)) = N1ModeApcoResponse::decode(&apco) {
        assert_eq!(
            N1ModeApcoResponse::decode(&value.encode_apco()),
            Ok(Some(value))
        );
        assert!(value.append_to(&apco).is_err());
    }
    let request = N1ModeApcoRequest::new(PduSessionId::UNASSIGNED);
    if let Ok(extended) = request.append_to(&apco) {
        assert!(extended.value.starts_with(data));
        assert_eq!(N1ModeApcoRequest::decode(&extended), Ok(Some(request)));
    }
});
