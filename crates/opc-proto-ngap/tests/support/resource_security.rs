//! Shared semantic reconstruction for resource-security fuzz and replay.
use opc_proto_ngap::n3iwf::release::Cause;
use opc_proto_ngap::n3iwf::resource_fields::{DownlinkTransport, QosFlowId};
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_proto_ngap::n3iwf::resource_results::{FailedQosFlow, SetupResponseTransfer};
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
    assert!(reconstructed == *value);
    reconstructed
}
pub fn response(value: &SetupResponseTransfer) -> SetupResponseTransfer {
    let reconstructed = SetupResponseTransfer::new(
        DownlinkTransport::new(value.downlink().address(), value.downlink().teid()),
        value
            .accepted()
            .iter()
            .map(|qfi| QosFlowId::new(qfi.value()).unwrap())
            .collect(),
        value
            .failed()
            .iter()
            .map(|failed| FailedQosFlow {
                qfi: QosFlowId::new(failed.qfi.value()).unwrap(),
                cause: Cause::new(failed.cause.class(), failed.cause.code()).unwrap(),
            })
            .collect(),
    )
    .unwrap()
    .with_security_result(value.security_result().map(result));
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
    if let Ok(value) = SetupResponseTransfer::decode(data, ctx) {
        let wire = response(&value).encode(output).unwrap();
        assert!(SetupResponseTransfer::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
}
