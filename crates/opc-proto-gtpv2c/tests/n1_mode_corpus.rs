use opc_proto_gtpv2c::n1_mode::{N1ModeApcoRequest, N1ModeApcoResponse};
use opc_proto_gtpv2c::AdditionalProtocolConfigurationOptions;

#[test]
fn independent_apco_fixtures_have_exact_fuzz_seed_mirrors() {
    let cases = [
        (
            include_str!("fixtures/spec/n1_mode_apco_request.hex"),
            include_bytes!("../fuzz/corpus/n1_mode/apco_request.bin").as_slice(),
            true,
        ),
        (
            include_str!("fixtures/spec/n1_mode_apco_response.hex"),
            include_bytes!("../fuzz/corpus/n1_mode/apco_response.bin").as_slice(),
            false,
        ),
    ];
    for (fixture, seed, request) in cases {
        let value: Vec<_> = fixture
            .split_ascii_whitespace()
            .map(|octet| u8::from_str_radix(octet, 16).unwrap())
            .collect();
        assert_eq!(seed, value);
        let apco = AdditionalProtocolConfigurationOptions { value };
        if request {
            let typed = N1ModeApcoRequest::decode(&apco).unwrap().unwrap();
            assert_eq!(typed.encode_apco(), apco);
            assert_eq!(N1ModeApcoResponse::decode(&apco), Ok(None));
        } else {
            let typed = N1ModeApcoResponse::decode(&apco).unwrap().unwrap();
            assert_eq!(typed.encode_apco(), apco);
            assert_eq!(N1ModeApcoRequest::decode(&apco), Ok(None));
        }
    }
}
