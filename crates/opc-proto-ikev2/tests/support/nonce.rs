//! Raw peer nonce fixtures, independent of typed local send validation.

pub fn replace_nonce(first_payload: u8, bytes: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut kind = first_payload;
    let mut offset = 0;
    while offset < bytes.len() {
        assert!(offset + 4 <= bytes.len(), "fixture payload header");
        let len = usize::from(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
        assert!(
            len >= 4 && offset + len <= bytes.len(),
            "fixture payload bounds"
        );
        if kind == 40 {
            let new_len = u16::try_from(4 + nonce.len()).expect("fixture nonce length");
            let mut out = bytes[..offset + 2].to_vec();
            out.extend_from_slice(&new_len.to_be_bytes());
            out.extend_from_slice(nonce);
            out.extend_from_slice(&bytes[offset + len..]);
            return out;
        }
        kind = bytes[offset];
        offset += len;
    }
    panic!("fixture has no nonce payload")
}
