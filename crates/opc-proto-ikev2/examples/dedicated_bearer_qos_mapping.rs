//! Map integer-kbps dedicated-bearer QoS into TS 24.301 Notify values.

use opc_proto_ikev2::{
    Ikev2ApnAmbrKbps, Ikev2ApnAmbrMapping, Ikev2EpsBearerBitRatesKbps, Ikev2EpsQosKbps,
    Ikev2EpsQosMapping, Ikev2QosMappingError, Ikev2QosQuantization,
};

fn main() -> Result<(), Ikev2QosMappingError> {
    let bearer = Ikev2EpsQosMapping::from_kbps(
        Ikev2EpsQosKbps::Gbr {
            // The GBR variant explicitly classifies this operator-specific QCI.
            qci: 200,
            rates: Ikev2EpsBearerBitRatesKbps {
                maximum_uplink: 10_000_001,
                maximum_downlink: 9_900_000,
                guaranteed_uplink: 9_000_000,
                guaranteed_downlink: 9_000_000,
            },
        },
        Ikev2QosQuantization::Ceiling,
    )?;
    let apn = Ikev2ApnAmbrMapping::from_kbps(
        Ikev2ApnAmbrKbps {
            downlink: 65_280_001,
            uplink: 65_280_000,
        },
        Ikev2QosQuantization::Ceiling,
    )?;

    // These typed values can be inserted directly into dedicated-bearer
    // CREATE_CHILD_SA or INFORMATIONAL request builders.
    assert!(bearer.extended_eps_qos().is_some());
    assert!(apn.extended_apn_ambr().is_some());
    assert_eq!(
        bearer.represented_rates().map(|rates| rates.maximum_uplink),
        Some(10_000_200),
    );
    assert_eq!(apn.represented_rates().downlink, 65_284_000);
    Ok(())
}
