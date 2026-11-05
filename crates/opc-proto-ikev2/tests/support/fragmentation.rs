//! Public synthetic fragmentation test inputs.

pub fn offers(spis: (u64, u64), response: bool, support: bool) -> Vec<u8> {
    let mut wire = vec![0; 28];
    wire[..8].copy_from_slice(&spis.0.to_be_bytes());
    wire[8..16].copy_from_slice(&(if response { spis.1 } else { 0 }).to_be_bytes());
    wire[16] = if support { 41 } else { 0 };
    wire[17] = 0x20;
    wire[18] = 34;
    wire[19] = if response { 32 } else { 8 };
    if support {
        wire.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0x40, 0x2e]);
    }
    let length = u32::try_from(wire.len()).unwrap();
    wire[24..28].copy_from_slice(&length.to_be_bytes());
    wire
}

pub fn large_delete() -> Vec<u8> {
    let count = 300u16;
    let length = 8 + count * 4;
    let mut bytes = vec![0, 0];
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&[3, 4]);
    bytes.extend_from_slice(&count.to_be_bytes());
    for spi in 1..=u32::from(count) {
        bytes.extend_from_slice(&spi.to_be_bytes());
    }
    bytes
}
