#![allow(clippy::unwrap_used)]
use opc_proto_ngap::n3iwf::release::Cause;
use opc_proto_ngap::n3iwf::resource_fields::{DownlinkTransport, QosFlowId};
use opc_proto_ngap::n3iwf::resource_results::{
    AssociatedQosFlow, DownlinkQosTunnel, FailedQosFlow, SetupResponseTransfer,
};
use opc_proto_ngap::n3iwf::security_fields::SecurityResult;
use opc_protocol::{DecodeContext, EncodeContext};

fn rebuild_tunnel(value: &DownlinkQosTunnel) -> DownlinkQosTunnel {
    DownlinkQosTunnel::new(
        DownlinkTransport::new(value.downlink().address(), value.downlink().teid()),
        value
            .flows()
            .map(|flow| AssociatedQosFlow {
                qfi: QosFlowId::new(flow.qfi.value()).unwrap(),
                mapping: flow.mapping,
            })
            .collect(),
    )
    .unwrap()
}

pub fn rebuild(value: &SetupResponseTransfer) -> SetupResponseTransfer {
    SetupResponseTransfer::with_tunnels(
        rebuild_tunnel(value.primary()),
        value.additional().iter().map(rebuild_tunnel).collect(),
        value
            .failed()
            .iter()
            .map(|flow| FailedQosFlow {
                qfi: QosFlowId::new(flow.qfi.value()).unwrap(),
                cause: Cause::new(flow.cause.class(), flow.cause.code()).unwrap(),
            })
            .collect(),
    )
    .unwrap()
    .with_security_result(value.security_result().map(|value| {
        SecurityResult::new(
            value.integrity_performed(),
            value.confidentiality_performed(),
        )
    }))
}

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    if let Ok(value) = SetupResponseTransfer::decode(data, ctx) {
        let rebuilt = rebuild(&value);
        assert!(rebuilt == value);
        let wire = rebuilt.encode(output).unwrap();
        assert_eq!(wire.as_bytes(), data);
        assert!(SetupResponseTransfer::decode(wire.as_bytes(), ctx).unwrap() == rebuilt);
        assert_eq!(format!("{value:?}"), "SetupResponseTransfer([REDACTED])");
    }
}
