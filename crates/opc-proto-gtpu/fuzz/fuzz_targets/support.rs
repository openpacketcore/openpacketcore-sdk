pub fn decode_hex_seed(input: &[u8]) -> Option<Vec<u8>> {
    let encoded = input.strip_prefix(b"hex:")?;
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    let mut high = None;
    for byte in encoded.iter().copied() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        if let Some(upper) = high.take() {
            decoded.push((upper << 4) | nibble);
        } else {
            high = Some(nibble);
        }
    }
    if high.is_some() {
        None
    } else {
        Some(decoded)
    }
}
