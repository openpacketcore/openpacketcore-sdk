//! Shared semantic reconstruction for additional request/result tunnel fuzzing.
use opc_proto_ngap::n3iwf::modify_request::ModifyRequestTransfer;
use opc_proto_ngap::n3iwf::modify_results::ModifyResponseTransfer;
use opc_proto_ngap::n3iwf::resource_fields::{
    DownlinkTransport, QosFlowId, UplinkTransport, UplinkTransportList,
};
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_proto_ngap::n3iwf::resource_results::{AssociatedQosFlow, DownlinkQosTunnel};
use opc_protocol::{DecodeContext, EncodeContext};

pub fn uplinks(value: &UplinkTransportList) -> UplinkTransportList {
    UplinkTransportList::new(
        value
            .values()
            .iter()
            .map(|v| UplinkTransport::new(v.address(), v.teid()))
            .collect(),
    )
    .unwrap()
}
pub fn response(value: &ModifyResponseTransfer) -> ModifyResponseTransfer {
    let mut rebuilt = value.clone();
    rebuilt.additional = value
        .additional
        .iter()
        .map(|tunnel| {
            DownlinkQosTunnel::new(
                DownlinkTransport::new(tunnel.downlink().address(), tunnel.downlink().teid()),
                tunnel
                    .flows()
                    .map(|flow| AssociatedQosFlow {
                        qfi: QosFlowId::new(flow.qfi.value()).unwrap(),
                        mapping: flow.mapping,
                    })
                    .collect(),
            )
            .unwrap()
        })
        .collect();
    assert!(rebuilt == *value);
    rebuilt
}
pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    if let Ok(value) = UplinkTransportList::decode(data, ctx) {
        let rebuilt = uplinks(&value);
        assert!(rebuilt == value);
        let wire = rebuilt.encode(output).unwrap();
        assert_eq!(wire.as_bytes(), data);
        assert!(UplinkTransportList::decode(wire.as_bytes(), ctx).unwrap() == rebuilt);
    }
    if let Ok(value) = SetupRequestTransfer::decode(data, ctx) {
        let mut rebuilt = value.transfer.clone();
        rebuilt.additional_uplink = value.transfer.additional_uplink.as_ref().map(uplinks);
        assert!(rebuilt == value.transfer);
        let wire = rebuilt.encode(output).unwrap();
        assert!(
            SetupRequestTransfer::decode(wire.as_bytes(), ctx)
                .unwrap()
                .transfer
                == rebuilt
        );
    }
    if let Ok(value) = ModifyRequestTransfer::decode(data, ctx) {
        let mut rebuilt = value.transfer.clone();
        rebuilt.additional_uplink = value.transfer.additional_uplink.as_ref().map(uplinks);
        assert!(rebuilt == value.transfer);
        let wire = rebuilt.encode(output).unwrap();
        assert!(
            ModifyRequestTransfer::decode(wire.as_bytes(), ctx)
                .unwrap()
                .transfer
                == rebuilt
        );
    }
    if let Ok(value) = ModifyResponseTransfer::decode(data, ctx) {
        let wire = response(&value).encode(output).unwrap();
        assert_eq!(wire.as_bytes(), data);
        assert!(ModifyResponseTransfer::decode(wire.as_bytes(), ctx).unwrap() == value);
    }
}
