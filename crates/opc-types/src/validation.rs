use crate::ParseError;

pub(crate) fn validate_slug(
    kind: &'static str,
    value: &str,
    max_len: usize,
) -> Result<String, ParseError> {
    if value.is_empty() {
        return Err(ParseError::new(kind, "cannot be empty"));
    }

    if value.trim() != value {
        return Err(ParseError::new(
            kind,
            "must not contain leading or trailing whitespace",
        ));
    }

    if value.len() > max_len {
        return Err(ParseError::new(
            kind,
            format!("must be at most {max_len} characters"),
        ));
    }

    if value.starts_with('-') || value.ends_with('-') {
        return Err(ParseError::new(kind, "must not start or end with '-'"));
    }

    for ch in value.chars() {
        if !matches!(ch, 'a'..='z' | '0'..='9' | '-') {
            return Err(ParseError::new(
                kind,
                "must contain only lowercase ascii letters, digits, and '-'",
            ));
        }
    }

    Ok(value.to_owned())
}

pub(crate) fn validate_trust_domain(kind: &'static str, value: &str) -> Result<String, ParseError> {
    if value.is_empty() {
        return Err(ParseError::new(kind, "trust domain cannot be empty"));
    }

    if value.trim() != value {
        return Err(ParseError::new(
            kind,
            "trust domain must not contain leading or trailing whitespace",
        ));
    }

    for label in value.split('.') {
        if label.is_empty() {
            return Err(ParseError::new(
                kind,
                "trust domain labels must not be empty",
            ));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(ParseError::new(
                kind,
                "trust domain labels must not start or end with '-'",
            ));
        }

        for ch in label.chars() {
            if !matches!(ch, 'a'..='z' | '0'..='9' | '-') {
                return Err(ParseError::new(
                    kind,
                    "trust domain labels must contain only lowercase ascii letters, digits, and '-'",
                ));
            }
        }
    }

    Ok(value.to_owned())
}

pub(crate) fn validate_spiffe_path(kind: &'static str, value: &str) -> Result<String, ParseError> {
    if !value.starts_with('/') {
        return Err(ParseError::new(kind, "path must start with '/'"));
    }

    if value == "/" {
        return Err(ParseError::new(
            kind,
            "path must include at least one segment",
        ));
    }

    if value.ends_with('/') {
        return Err(ParseError::new(kind, "path must not end with '/'"));
    }

    for segment in value[1..].split('/') {
        if segment.is_empty() {
            return Err(ParseError::new(kind, "path segments must not be empty"));
        }

        for ch in segment.chars() {
            if !matches!(ch, 'a'..='z' | '0'..='9' | '.' | '_' | '-') {
                return Err(ParseError::new(
                    kind,
                    "path segments must contain only lowercase ascii letters, digits, '.', '_', and '-'",
                ));
            }
        }
    }

    Ok(value.to_owned())
}

pub(crate) fn validate_digits(
    kind: &'static str,
    value: &str,
    allowed_lengths: &[usize],
) -> Result<String, ParseError> {
    if !allowed_lengths.contains(&value.len()) {
        let expected = allowed_lengths
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(" or ");
        return Err(ParseError::new(
            kind,
            format!("must be {expected} digits long"),
        ));
    }

    if !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(ParseError::new(kind, "must contain only digits"));
    }

    Ok(value.to_owned())
}

pub(crate) fn validate_hex(
    kind: &'static str,
    value: &str,
    exact_len: usize,
) -> Result<String, ParseError> {
    if value.len() != exact_len {
        return Err(ParseError::new(
            kind,
            format!("must be exactly {exact_len} hexadecimal characters"),
        ));
    }

    if !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ParseError::new(
            kind,
            "must contain only hexadecimal characters",
        ));
    }

    Ok(value.to_ascii_lowercase())
}

/// Convert a single lowercase ASCII hex digit to its numeric value.
///
/// Callers are expected to normalize input to lowercase first (e.g. via
/// `validate_hex`), so only `a`–`f` is handled here.
pub(crate) fn hex_nibble(kind: &'static str, value: u8) -> Result<u8, ParseError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ParseError::new(
            kind,
            "must contain only hexadecimal characters",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_nibble_lowercase_ok() {
        assert_eq!(hex_nibble("test", b'0').unwrap(), 0);
        assert_eq!(hex_nibble("test", b'9').unwrap(), 9);
        assert_eq!(hex_nibble("test", b'a').unwrap(), 10);
        assert_eq!(hex_nibble("test", b'f').unwrap(), 15);
    }

    #[test]
    fn hex_nibble_uppercase_rejected() {
        // Callers are expected to normalize to lowercase first (e.g. via validate_hex).
        // The uppercase arm was removed as dead code; verify it is indeed rejected.
        assert!(hex_nibble("test", b'A').is_err());
        assert!(hex_nibble("test", b'F').is_err());
    }

    #[test]
    fn hex_nibble_non_hex_rejected() {
        assert!(hex_nibble("test", b'g').is_err());
        assert!(hex_nibble("test", b'x').is_err());
        assert!(hex_nibble("test", b' ').is_err());
    }
}
