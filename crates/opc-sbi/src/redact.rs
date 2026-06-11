use std::fmt;

pub(crate) struct SensitivePresence(pub(crate) bool);

impl fmt::Debug for SensitivePresence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 {
            f.write_str("Some(<redacted>)")
        } else {
            f.write_str("None")
        }
    }
}

pub(crate) struct SensitiveValue;

impl fmt::Debug for SensitiveValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

pub(crate) fn sanitize_error_message(input: impl AsRef<str>) -> String {
    let input = input.as_ref();
    let lower = input.to_ascii_lowercase();
    if lower.contains("token")
        || lower.contains("authorization")
        || lower.contains("bearer")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("private_key")
        || lower.contains("client_secret")
        || lower.contains("-----begin")
        || lower.contains("spiffe://")
        || lower.contains("select ")
        || lower.contains("insert ")
        || lower.contains("delete from")
        || lower.contains("update ")
        || lower.contains("sqlite")
        || lower.contains(".db")
        || contains_path(input)
        || contains_ipv4(input)
        || contains_raw_identifier_context(input)
    {
        return "redacted internal error".to_string();
    }

    input
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect::<String>()
}

pub(crate) fn safe_metric_label(input: &str) -> String {
    opc_redaction::metrics_label_safe(input)
}

fn contains_path(input: &str) -> bool {
    input.contains("/Users/")
        || input.contains("/home/")
        || input.contains("/var/")
        || input.contains("/etc/")
        || input.contains('\\')
}

fn contains_ipv4(input: &str) -> bool {
    input
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|candidate| {
            let parts: Vec<&str> = candidate.split('.').collect();
            parts.len() == 4
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.len() <= 3 && part.parse::<u8>().is_ok())
        })
}

fn contains_raw_identifier_context(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    const MARKERS: [&str; 7] = [
        "subscriber",
        "supi",
        "gpsi",
        "imsi",
        "msisdn",
        "guti",
        "pei",
    ];
    MARKERS.iter().any(|marker| lower.contains(marker))
        && input
            .split(|c: char| !c.is_ascii_digit())
            .any(|candidate| candidate.len() >= 8)
}
