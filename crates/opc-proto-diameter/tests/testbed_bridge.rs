use opc_proto_diameter::{
    base,
    peer::{build_capabilities_exchange_request, HostIpAddress, PeerCapabilities, PeerIdentity},
    ApplicationId, OwnedMessage as DiameterOwnedMessage, RawAvpIterator, VendorId,
};
use opc_testbed::simulators::epc::{
    DiameterApplication, DiameterMessageView, DiameterPeerSimulator, DiameterPeerState,
    PeerMessageDirection, SdkDecodeProfile,
};

struct DiameterCodecView<'a> {
    message: &'a DiameterOwnedMessage,
    decode_profile: SdkDecodeProfile,
}

impl DiameterMessageView for DiameterCodecView<'_> {
    fn command_code(&self) -> u32 {
        self.message.header.command_code.get()
    }

    fn application_id(&self) -> u32 {
        self.message.header.application_id.get()
    }

    fn direction(&self) -> PeerMessageDirection {
        if self.message.header.flags.is_request() {
            PeerMessageDirection::Request
        } else {
            PeerMessageDirection::Response
        }
    }

    fn has_session_id(&self) -> bool {
        RawAvpIterator::new(self.message.raw_avps.as_ref(), self.decode_profile.context)
            .any(|avp| matches!(avp, Ok(avp) if avp.header.code == base::AVP_SESSION_ID))
    }
}

fn sample_diameter_capabilities() -> PeerCapabilities {
    let mut capabilities = PeerCapabilities::new(
        PeerIdentity::new("aaa-testbed.example.net", "example.net"),
        vec![HostIpAddress::ipv4([192, 0, 2, 55])],
        VendorId::new(10415),
        "opc-testbed-diameter",
    );
    capabilities
        .acct_application_ids
        .push(ApplicationId::new(3));
    capabilities
}

#[test]
fn diameter_peer_simulator_accepts_opc_proto_diameter_peer_message() {
    let mut sim = DiameterPeerSimulator::new("aaa-hss");
    let message = build_capabilities_exchange_request(
        &sample_diameter_capabilities(),
        0x0102_0304,
        0x0506_0708,
        Default::default(),
    )
    .expect("opc-proto-diameter builds a CER");
    let view = DiameterCodecView {
        message: &message,
        decode_profile: sim.decode_profile,
    };

    assert_eq!(view.command_code(), 257);
    assert_eq!(view.application_id(), 0);
    assert_eq!(view.direction(), PeerMessageDirection::Request);
    assert!(!view.has_session_id());

    let event = sim
        .handle_sdk_message(&view)
        .expect("Diameter peer accepts opc-proto-diameter decoded metadata");
    assert_eq!(event.application, DiameterApplication::Base);
    assert_eq!(event.state, DiameterPeerState::CapabilitiesExchanged);
    assert_eq!(sim.capability_messages, 1);
}
