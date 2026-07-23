#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_eap::EapAkaPacket;

fn hex_nibble(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet - b'0'),
        b'a'..=b'f' => Some(octet - b'a' + 10),
        b'A'..=b'F' => Some(octet - b'A' + 10),
        _ => None,
    }
}

fn decode_seed_envelope(data: &[u8]) -> Option<Vec<u8>> {
    let data = data.strip_suffix(b"\n").unwrap_or(data);
    let encoded = data.strip_prefix(b"hex:")?;
    if encoded.len() % 2 != 0 {
        return None;
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.chunks_exact(2) {
        decoded.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    Some(decoded)
}

fuzz_target!(|data: &[u8]| {
    if let Some(decoded) = decode_seed_envelope(data) {
        let _ = EapAkaPacket::parse(&decoded);
    } else {
        let _ = EapAkaPacket::parse(data);
    }
});
