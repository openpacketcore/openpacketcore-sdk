//! Independent RFC 7383 known answers and SDK packet export for the Python/OpenSSL oracle.
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{
        Ikev2CbcEpochInputs, Ikev2CbcEpochRecord, Ikev2CbcRecoveryProfile,
        Ikev2CommittedWindow as Window, Ikev2CommittedWindowDomain as Domain,
        Ikev2CommittedWindowRecord as Record, Ikev2FragmentReceive as Receive,
        Ikev2FragmentationSize as Size,
    },
    Ikev2AesGcmIvPurpose as Purpose, Ikev2ExchangeKind as Exchange,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys, PayloadChain, PayloadType,
};
#[path = "support/canonical.rs"]
mod canonical_fixtures;
#[path = "support/fragmentation.rs"]
mod fragmentation_fixtures;
mod support;
use canonical_fixtures::{opposite, Fixture, DIRECTIONS, SPIS};
use std::num::NonZeroU32;

fn unhex(value: &str) -> Vec<u8> {
    if value == "-" {
        return Vec::new();
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

macro_rules! negotiate {
    ($window:expr, $profile:expr, $keys:expr) => {{
        let prepared = $window
            .prepare_fragmentation(
                $profile,
                $keys,
                &fragmentation_fixtures::offers(SPIS, false, true),
                &fragmentation_fixtures::offers(SPIS, true, true),
                NonZeroU32::new(50).unwrap(),
            )
            .unwrap();
        let record = prepared.record().clone();
        let token = prepared.commit_after_durable(&record).unwrap();
        $window.apply_committed(token).unwrap();
    }};
}
macro_rules! receive {
    ($window:expr, $profile:expr, $keys:expr, $packets:expr, $clear:expr) => {{
        negotiate!($window, $profile, $keys);
        for (index, packet) in $packets.iter().rev().enumerate() {
            let received = $window
                .receive_peer_packet($profile, $keys, packet, 0)
                .unwrap();
            if index + 1 == $packets.len() {
                let Receive::Message(message) = received else {
                    panic!("whole vector required");
                };
                assert_eq!(message.payloads().first_payload(), PayloadType::Delete);
                assert_eq!(message.payloads().bytes(), $clear);
            } else {
                assert!(matches!(received, Receive::Incomplete));
            }
        }
    }};
}

#[test]
fn independent_openssl_vectors_cover_gcm_cbc_key_sizes_and_both_original_roles() {
    support::ensure_ike_crypto();
    let mut export = Vec::new();
    for line in include_str!("vectors/ikev2_fragments.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        let gcm = fields[0] == "gcm";
        let profile = Profile::from_transform_ids(
            5,
            19,
            if gcm { 20 } else { 12 },
            Some(fields[1].parse().unwrap()),
            if gcm { None } else { Some(12) },
        )
        .unwrap();
        let direction = if fields[2] == "I" {
            DIRECTIONS[0]
        } else {
            DIRECTIONS[1]
        };
        let keys = Keys::from_established_keys(
            profile,
            false,
            &[0x11; 32],
            &unhex(fields[5]),
            &unhex(fields[6]),
            &unhex(fields[3]),
            &unhex(fields[4]),
            &[0x22; 32],
            &[0x33; 32],
        )
        .unwrap();
        let clear = unhex(fields[7]);
        assert_eq!(clear, fragmentation_fixtures::large_delete());
        let packets: Vec<Bytes> = fields[8..]
            .iter()
            .map(|value| Bytes::from(unhex(value)))
            .collect();
        let payload = PayloadChain::new(PayloadType::Delete, &clear);
        let actual;
        if gcm {
            let mut receiver = Fixture::from_keys(profile, keys.clone(), opposite(direction), SPIS);
            receive!(receiver.window, profile, &keys, packets, clear);
            let mut sender = Fixture::from_keys(profile, keys.clone(), direction, SPIS);
            negotiate!(sender.window, profile, &keys);
            let prepared = sender
                .window
                .prepare_fragmented_request(
                    profile,
                    &keys,
                    &mut sender.allocator,
                    Purpose::Ordinary,
                    Exchange::Informational,
                    payload,
                    Size::ipv4(None, true).unwrap(),
                )
                .unwrap();
            let row = prepared.record().clone();
            let token = prepared.commit_after_durable(&row).unwrap();
            sender.window.apply_committed(token).unwrap();
            actual = sender
                .window
                .replay_request()
                .unwrap()
                .unwrap()
                .packets()
                .to_vec();
            assert_eq!(actual, packets);
        } else {
            let build = |direction| {
                let epoch = Ikev2CbcEpochRecord::fresh(Ikev2CbcEpochInputs {
                    initiator_spi: SPIS.0,
                    responder_spi: SPIS.1,
                    sending_direction: direction,
                    profile,
                    keys: &keys,
                })
                .unwrap();
                let domain = Domain::from_cbc_epoch(&epoch);
                Window::<Ikev2CbcRecoveryProfile>::restore(
                    &domain,
                    profile,
                    &keys,
                    &Record::initial(domain.clone(), 0, 0),
                    &epoch,
                )
                .unwrap()
            };
            let mut receiver = build(opposite(direction));
            receive!(receiver, profile, &keys, packets, clear);
            let mut sender = build(direction);
            negotiate!(sender, profile, &keys);
            let prepared = sender
                .prepare_fragmented_request(
                    profile,
                    &keys,
                    Exchange::Informational,
                    payload,
                    Size::ipv4(None, true).unwrap(),
                )
                .unwrap();
            let row = prepared.record().clone();
            let token = prepared.commit_after_durable(&row).unwrap();
            sender.apply_committed(token).unwrap();
            actual = sender.replay_request().unwrap().unwrap().packets().to_vec();
        }
        assert!(actual.iter().all(|packet| packet.len() <= 544));
        let mut columns: Vec<String> = fields[..8].iter().map(|s| (*s).to_owned()).collect();
        columns.extend(actual.iter().map(|packet| hex(packet)));
        export.push(columns.join(" "));
    }
    assert_eq!(export.len(), 12);
    if let Some(path) = std::env::var_os("OPC_FRAGMENT_VECTOR_EXPORT") {
        std::fs::write(path, export.join("\n") + "\n").unwrap();
    }
}
