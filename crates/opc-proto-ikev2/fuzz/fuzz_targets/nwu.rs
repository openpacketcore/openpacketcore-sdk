#![no_main]
use libfuzzer_sys::fuzz_target;
use opc_proto_ikev2::{
    nwu::*, Header, HeaderFlags, PayloadChain, PayloadType, EXCHANGE_TYPE_CREATE_CHILD_SA,
    EXCHANGE_TYPE_INFORMATIONAL,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let limits = Limits {
        bytes: 8192,
        entries: 128,
    };
    for body in [Some(data), data.get(4..)].into_iter().flatten() {
        if let Ok(Some(value)) = mobike::Notify::decode_body(body) {
            let canonical = value.encode_body().expect("mobility Notify encodes");
            assert_eq!(
                mobike::Notify::decode_body(&canonical).expect("mobility Notify parses"),
                Some(value)
            );
        }
        if let Ok(Some(notify)) = Notify::decode_body(body) {
            let canonical = notify.encode_body().expect("accepted Notify encodes");
            let again = Notify::decode_body(&canonical)
                .expect("canonical Notify parses")
                .expect("known type");
            assert_eq!(
                again.encode_body().expect("canonical Notify encodes"),
                canonical
            );
        }
        if let Ok(qos) = QosInfo::decode(body) {
            let canonical = qos.encode().expect("accepted QoS encodes");
            assert_eq!(
                QosInfo::decode(&canonical)
                    .expect("canonical QoS parses")
                    .encode()
                    .expect("canonical QoS encodes"),
                canonical
            );
        }
        let _ = AdditionalQos::new(body);
    }
    let header = Header::new(
        1,
        2,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_INFORMATIONAL,
        HeaderFlags::from_bits(false, false, false),
        7,
    );
    for first in [
        PayloadType::Notify,
        PayloadType::Configuration,
        PayloadType::Delete,
        PayloadType::SecurityAssociation,
        PayloadType::Unknown(250),
    ] {
        for p in PayloadChain::new(first, data).iter() {
            if let Ok(p) = p {
                if p.payload_type == PayloadType::Notify {
                    let _ = Notify::decode_body(p.body);
                }
            }
        }
        let _ = ConfigurationRequest::decode(first, data, limits);
        let _ = mobike::Request::decode(first, data, limits);
        for families in [
            AddressFamilies::Ipv4,
            AddressFamilies::Ipv6,
            AddressFamilies::Dual,
        ] {
            for mobike_supported in [false, true] {
                let request = ConfigurationRequest {
                    families,
                    mobike_supported,
                };
                if let Ok(reply) = ConfigurationReply::decode(request, first, data, limits) {
                    let (first, bytes) = encode_payloads(&reply.payloads().expect("reply builds"))
                        .expect("reply encodes");
                    assert_eq!(
                        ConfigurationReply::decode(request, first, &bytes, limits)
                            .expect("canonical reply parses"),
                        reply
                    );
                }
            }
            let mut create = header.clone();
            create.exchange_type = EXCHANGE_TYPE_CREATE_CHILD_SA;
            let _ = CreateRequest::decode(&create, first, data, families, limits);
        }
        if let Ok((_, value)) = Modification::decode(&header, first, data, limits) {
            let (first, canonical) =
                encode_payloads(&value.payloads().expect("modification builds"))
                    .expect("modification encodes");
            assert!(Modification::decode(&header, first, &canonical, limits).is_ok());
        }
        if let Ok((_, delete)) = ChildDelete::decode(&header, Peer::Network, first, data, limits) {
            let (first, canonical) = encode_payloads(&delete.payloads().expect("delete builds"))
                .expect("delete encodes");
            assert_eq!(
                ChildDelete::decode(&header, Peer::Network, first, &canonical, limits)
                    .expect("canonical delete parses")
                    .1,
                delete
            );
        }
        let _ = PendingIkeDelete::decode_request(&header, Peer::Network, first, data, limits);
    }
});
