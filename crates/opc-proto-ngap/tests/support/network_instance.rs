//! Shared bounded network-instance fuzz/replay assertions; no identifier output.
use opc_proto_ngap::n3iwf::modify_request::ModifyRequestTransfer;
use opc_proto_ngap::n3iwf::network_fields::{CommonNetworkInstance, TransportNetworkInstance};
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_proto_ngap::n3iwf::security_fields::NetworkInstance;
use opc_protocol::{DecodeContext, EncodeContext};

fn same_preference(
    value: Option<TransportNetworkInstance<'_>>,
    numeric: Option<NetworkInstance>,
    common: Option<&CommonNetworkInstance>,
) {
    match (common, numeric) {
        (Some(expected), _) => {
            assert!(matches!(value, Some(TransportNetworkInstance::Common(v)) if v == expected))
        }
        (None, Some(expected)) => {
            assert!(matches!(value, Some(TransportNetworkInstance::Network(v)) if v == expected))
        }
        (None, None) => assert!(value.is_none()),
    }
}

pub fn exercise(data: &[u8], ctx: DecodeContext, output: EncodeContext) {
    if let Ok(value) = CommonNetworkInstance::decode(data, ctx) {
        let constructed = CommonNetworkInstance::new(value.as_bytes().to_vec());
        let wire = constructed.encode(output).unwrap();
        let received = CommonNetworkInstance::decode(wire.as_bytes(), ctx).unwrap();
        assert!(received == value);
    }
    if let Ok(value) = SetupRequestTransfer::decode(data, ctx) {
        same_preference(
            value.transfer.transport_network_instance(),
            value.transfer.network_instance,
            value.transfer.common_network_instance.as_ref(),
        );
        let mut rebuilt = value.transfer.clone();
        rebuilt.common_network_instance = value
            .transfer
            .common_network_instance
            .as_ref()
            .map(|v| CommonNetworkInstance::new(v.as_bytes().to_vec()));
        rebuilt.network_instance = value
            .transfer
            .network_instance
            .map(|v| NetworkInstance::new(v.value()).unwrap());
        let wire = rebuilt.encode(output).unwrap();
        let received = SetupRequestTransfer::decode(wire.as_bytes(), ctx).unwrap();
        assert!(received.transfer == value.transfer);
        assert_eq!(received.ignored_ie_count, 0);
        assert!(received.notify_ie_ids.is_empty());
    }
    if let Ok(value) = ModifyRequestTransfer::decode(data, ctx) {
        same_preference(
            value.transfer.transport_network_instance(),
            value.transfer.network_instance,
            value.transfer.common_network_instance.as_ref(),
        );
        let mut rebuilt = value.transfer.clone();
        rebuilt.common_network_instance = value
            .transfer
            .common_network_instance
            .as_ref()
            .map(|v| CommonNetworkInstance::new(v.as_bytes().to_vec()));
        rebuilt.network_instance = value
            .transfer
            .network_instance
            .map(|v| NetworkInstance::new(v.value()).unwrap());
        let wire = rebuilt.encode(output).unwrap();
        let received = ModifyRequestTransfer::decode(wire.as_bytes(), ctx).unwrap();
        assert!(received.transfer == value.transfer);
        assert_eq!(received.ignored_ie_count, 0);
        assert!(received.notify_ie_ids.is_empty());
    }
}
