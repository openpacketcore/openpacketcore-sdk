//! Shared semantic reconstruction for resource-security fuzz and replay.
use opc_proto_ngap::n3iwf::network_fields::CommonNetworkInstance;
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_proto_ngap::n3iwf::resource_results::SetupResponseTransfer;
#[path = "setup_tunnels.rs"]
pub mod setup_tunnels;
use opc_proto_ngap::n3iwf::resource_setup::ResourceSetupMessage;
use opc_proto_ngap::n3iwf::security_fields::{
    MaximumIntegrityRate, NetworkInstance, ProtectionRequirement, SecurityIndication,
    SecurityResult,
};
use opc_proto_ngap::n3iwf::session_lists::{SessionResults, SessionSetupRequests};
use opc_protocol::{DecodeContext, EncodeContext};

pub fn indication(value: SecurityIndication) -> SecurityIndication {
    SecurityIndication::new(
        ProtectionRequirement::new(value.integrity().value()).unwrap(),
        ProtectionRequirement::new(value.confidentiality().value()).unwrap(),
        value
            .uplink_rate()
            .map(|rate| MaximumIntegrityRate::new(rate.value()).unwrap()),
    )
    .unwrap()
}
pub fn result(value: SecurityResult) -> SecurityResult {
    SecurityResult::new(
        value.integrity_performed(),
        value.confidentiality_performed(),
    )
}
pub fn request(value: &SetupRequestTransfer) -> SetupRequestTransfer {
    let mut reconstructed = value.clone();
    reconstructed.security = value.security.map(indication);
    reconstructed.network_instance = value
        .network_instance
        .map(|v| NetworkInstance::new(v.value()).unwrap());
    reconstructed.common_network_instance = value
        .common_network_instance
        .as_ref()
        .map(|v| CommonNetworkInstance::new(v.as_bytes().to_vec()));
    assert!(reconstructed == *value);
    reconstructed
}
pub fn response(value: &SetupResponseTransfer) -> SetupResponseTransfer {
    let reconstructed = setup_tunnels::rebuild(value);
    assert!(reconstructed == *value);
    reconstructed
}
pub fn outer(message: &ResourceSetupMessage<'_>) {
    fn requests(values: &SessionSetupRequests<'_>) {
        for item in values.values() {
            request(&item.transfer);
        }
    }
    fn results(values: &SessionResults) {
        if let Some(values) = values.successful() {
            for item in values.values() {
                response(&item.transfer);
            }
        }
    }
    match message {
        ResourceSetupMessage::InitialRequest(value) => {
            if let Some(values) = &value.sessions {
                requests(values);
            }
        }
        ResourceSetupMessage::InitialResponse(value) => results(&value.sessions),
        ResourceSetupMessage::SessionRequest(value) => requests(&value.sessions),
        ResourceSetupMessage::SessionResponse(value) => results(&value.sessions),
        ResourceSetupMessage::InitialFailure(_) => {}
    }
}
pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    if let Ok(value) = SecurityIndication::decode(data, ctx) {
        let wire = indication(value).encode(output).unwrap();
        assert!(wire.as_bytes() == data);
        assert!(SecurityIndication::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = SecurityResult::decode(data, ctx) {
        let wire = result(value).encode(output).unwrap();
        assert!(wire.as_bytes() == data);
        assert!(SecurityResult::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = NetworkInstance::decode(data, ctx) {
        let wire = NetworkInstance::new(value.value())
            .unwrap()
            .encode(output)
            .unwrap();
        assert!(wire.as_bytes() == data);
        assert!(NetworkInstance::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
    if let Ok(value) = SetupRequestTransfer::decode(data, ctx) {
        let wire = request(&value.transfer).encode(output).unwrap();
        let received = SetupRequestTransfer::decode(wire.as_bytes(), ctx).unwrap();
        assert!(received.transfer == value.transfer);
        assert_eq!(received.ignored_ie_count, 0);
        assert!(received.notify_ie_ids.is_empty());
    }
    setup_tunnels::exercise(data, ctx, output);
}
