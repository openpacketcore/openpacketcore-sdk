//! Mixed-family configuration admission; native coverage lives with the socket tests.

#![allow(clippy::unwrap_used)]

use opc_sctp::{SctpConnectConfig, SctpEndpointConfig};

#[test]
fn mixed_address_sets_share_a_family_without_requiring_the_same_first_address() {
    let mut endpoint = SctpEndpointConfig::one_to_one("127.0.0.1:38412".parse().unwrap());
    endpoint.local_addrs.push("[::1]:38412".parse().unwrap());
    endpoint.validate().unwrap();

    let mut client = SctpConnectConfig::new("[::1]:38412".parse().unwrap());
    client.remote_addrs.push("127.0.0.1:38412".parse().unwrap());
    client.local_addrs.push("127.0.0.2:0".parse().unwrap());
    client.validate().unwrap();
    client.local_addrs.push("[::1]:0".parse().unwrap());
    client.validate().unwrap();
    client.remote_addrs.reverse();
    client.validate().unwrap();

    client.remote_addrs = vec!["[::ffff:127.0.0.1]:38412".parse().unwrap()];
    client.local_addrs = vec!["127.0.0.2:0".parse().unwrap()];
    client.validate().unwrap();
}
