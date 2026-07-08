use crate::telco::TELCO_MARKER_KEYS;
use crate::TelcoIdentifier;
use opc_data_governance::{DataClass, IdentifierType};
use serde::{Deserialize, Serialize};
use std::str::from_utf8;

/// Diagnostic entry types for support bundle collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticEntry {
    Log(String),
    ConfigSnapshot(String),
    HealthDebugJson(String),
    AlarmSnapshot(String),
    MetricsText(String),
    RuntimeTaskState(String),
    PersistenceError(String),
    ArbitraryDiagnosticAttachment {
        name: String,
        content: Vec<u8>,
        is_safe_metadata: bool,
    },
    Unknown {
        name: String,
        content: Vec<u8>,
    },
}

impl DiagnosticEntry {
    pub fn name(&self) -> &str {
        match self {
            Self::Log(_) => "log",
            Self::ConfigSnapshot(_) => "config_snapshot",
            Self::HealthDebugJson(_) => "health_debug_json",
            Self::AlarmSnapshot(_) => "alarm_snapshot",
            Self::MetricsText(_) => "metrics_text",
            Self::RuntimeTaskState(_) => "runtime_task_state",
            Self::PersistenceError(_) => "persistence_error",
            Self::ArbitraryDiagnosticAttachment { name, .. } => name,
            Self::Unknown { name, .. } => name,
        }
    }

    pub fn entry_type(&self) -> &'static str {
        match self {
            Self::Log(_) => "log",
            Self::ConfigSnapshot(_) => "config-snapshot",
            Self::HealthDebugJson(_) => "health-debug-json",
            Self::AlarmSnapshot(_) => "alarm-snapshot",
            Self::MetricsText(_) => "metrics-text",
            Self::RuntimeTaskState(_) => "runtime-task-state",
            Self::PersistenceError(_) => "persistence-error",
            Self::ArbitraryDiagnosticAttachment { .. } => "arbitrary-attachment",
            Self::Unknown { .. } => "unknown",
        }
    }
}

/// Execution mode for bundle redaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleMode {
    Production,
    Development,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum RedactionError {
    #[error("Production safety violation: unknown or unsafe diagnostic entry '{0}' rejected")]
    ProductionSafetyViolation(String),
}

/// A summary of the redactions applied to the support bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RedactionSummary {
    /// Subscriber identifiers such as IMSI, MSISDN, IMEI, NAI, and SUPI.
    pub subscriber_identifiers: usize,
    /// Secret-bearing values such as JWTs, private key material, and SPIs.
    ///
    /// The `security_secrets` name is also accepted during deserialization for
    /// compatibility with summaries produced during the short-lived rename.
    #[serde(alias = "security_secrets")]
    pub secrets: usize,
    /// Session endpoint identifiers such as TEIDs.
    pub session_endpoints: usize,
    /// Lawful-intercept identifiers such as LI ID, warrant ID, and correlation ID.
    pub lawful_intercept_identifiers: usize,
    /// Network-sensitive identifiers such as APN, DNN, SIP URIs, and Diameter Session-Id.
    pub network_sensitive_identifiers: usize,
    /// IPv4/IPv6 addresses (with or without ports) observed in the bundle.
    pub ip_addresses: usize,
    /// SPIFFE IDs observed in the bundle.
    pub spiffe_ids: usize,
    /// File-system paths and database file names observed in the bundle.
    pub paths_and_files: usize,
    /// SQL statements and database error strings observed in the bundle.
    pub sql_statements_or_errors: usize,
    /// Diagnostic entries rejected in production mode because they were unsafe or unknown.
    pub unknown_entries_rejected: usize,
}

impl RedactionSummary {
    pub fn total_redactions(&self) -> usize {
        self.subscriber_identifiers
            + self.secrets
            + self.session_endpoints
            + self.lawful_intercept_identifiers
            + self.network_sensitive_identifiers
            + self.ip_addresses
            + self.spiffe_ids
            + self.paths_and_files
            + self.sql_statements_or_errors
            + self.unknown_entries_rejected
    }
}

/// Configurable policy for support-bundle/text redaction.
///
/// The default policy is fail-closed: APN, DNN, SIP URIs, and Diameter
/// Session-Id are treated as [`DataClass::NetworkSensitive`]. Callers that
/// deploy APN/DNN as subscriber-sensitive can override just that mapping;
/// all other identifier types keep their SDK-mandated classification.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedactionPolicy {
    /// How to classify APN and DNN values for redaction.
    pub apn_dnn_class: ApnDnnClass,
}

impl RedactionPolicy {
    /// The default fail-closed policy.
    pub const DEFAULT: Self = Self {
        apn_dnn_class: ApnDnnClass::NetworkSensitive,
    };

    /// Builds a redaction policy with a specific APN/DNN classification.
    pub const fn with_apn_dnn_class(apn_dnn_class: ApnDnnClass) -> Self {
        Self { apn_dnn_class }
    }

    /// Returns the [`DataClass`] to use for a given identifier type under this
    /// policy.
    pub const fn data_class_for(self, id_type: IdentifierType) -> DataClass {
        match id_type {
            IdentifierType::Apn | IdentifierType::Dnn => self.apn_dnn_class.data_class(),
            _ => match id_type.telco_class() {
                Some(class) => class.default_data_class(),
                None => DataClass::SubscriberId,
            },
        }
    }
}

/// APN/DNN sensitivity override.
///
/// Some deployments treat APN/DNN as public/operational data; the SDK default
/// is fail-closed (`NetworkSensitive`). This enum lets those deployments move
/// APN/DNN values into the subscriber-identifier redaction bucket instead.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApnDnnClass {
    /// Treat APN/DNN as network-sensitive (default, fail-closed).
    #[default]
    NetworkSensitive,
    /// Treat APN/DNN as subscriber identifiers.
    SubscriberId,
}

impl ApnDnnClass {
    pub const fn data_class(self) -> DataClass {
        match self {
            Self::NetworkSensitive => DataClass::NetworkSensitive,
            Self::SubscriberId => DataClass::SubscriberId,
        }
    }
}

/// Returns the placeholder string for a given data class.
///
/// APN/DNN classification can be adjusted through [`RedactionPolicy`]; SIP
/// URIs and Diameter Session-Id are always treated as `NetworkSensitive` at
/// this SDK layer.
fn placeholder_for_class(data_class: DataClass) -> &'static str {
    match data_class {
        DataClass::SubscriberId => "[REDACTED_SUBSCRIBER_ID]",
        DataClass::LawfulIntercept => "[REDACTED_LAWFUL_INTERCEPT_ID]",
        DataClass::SecuritySecret => "[REDACTED_SECURITY_SECRET]",
        DataClass::SubscriberSession => "[REDACTED_SESSION_ENDPOINT]",
        DataClass::NetworkSensitive => "[REDACTED_NETWORK_SENSITIVE]",
        _ => "[REDACTED]",
    }
}

/// Records a telco redaction in the appropriate summary counter and returns the
/// production-safe placeholder to use for the redacted value.
fn record_telco_redaction(
    summary: &mut RedactionSummary,
    id: &TelcoIdentifier,
    policy: RedactionPolicy,
) -> &'static str {
    record_telco_redaction_by_type(summary, id.id_type, policy)
}

/// Records a telco redaction by identifier type, used when the full
/// [`TelcoIdentifier`] value is not available.
fn record_telco_redaction_by_type(
    summary: &mut RedactionSummary,
    id_type: IdentifierType,
    policy: RedactionPolicy,
) -> &'static str {
    let data_class = policy.data_class_for(id_type);
    match data_class {
        DataClass::SubscriberId => summary.subscriber_identifiers += 1,
        DataClass::LawfulIntercept => summary.lawful_intercept_identifiers += 1,
        DataClass::SecuritySecret => summary.secrets += 1,
        DataClass::SubscriberSession => summary.session_endpoints += 1,
        DataClass::NetworkSensitive => summary.network_sensitive_identifiers += 1,
        _ => summary.subscriber_identifiers += 1,
    }
    placeholder_for_class(data_class)
}

/// Returns true if `value` is already a redaction placeholder inserted by an
/// earlier pass. This prevents double-counting when multiple scanners process
/// the same line.
fn is_already_redacted(value: &str) -> bool {
    value.starts_with("[REDACTED_")
}

/// Redacted support bundle output structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactedSupportBundle {
    pub entries: Vec<RedactedEntry>,
    pub redaction_applied: bool,
    pub redaction_summary: RedactionSummary,
}

/// An individual redacted entry inside the support bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactedEntry {
    pub name: String,
    pub entry_type: String,
    pub content: String,
}

/// Redacts a single text block according to production data privacy rules.
pub fn redact_text(input: &str, summary: &mut RedactionSummary) -> String {
    redact_text_with_policy(input, summary, RedactionPolicy::DEFAULT)
}

/// Redacts a single text block according to production data privacy rules and
/// the supplied [`RedactionPolicy`].
pub fn redact_text_with_policy(
    input: &str,
    summary: &mut RedactionSummary,
    policy: RedactionPolicy,
) -> String {
    // If the whole input is JSON, redact it structurally so numeric/boolean/null
    // telco-marker values are caught and the output stays valid JSON.
    match serde_json::from_str::<serde_json::Value>(input) {
        Ok(value)
            if matches!(
                value,
                serde_json::Value::Object(_) | serde_json::Value::Array(_)
            ) =>
        {
            let mut value = value;
            redact_json_value(&mut value, summary, policy);
            return value.to_string();
        }
        _ => {}
    }

    let mut output_lines = Vec::new();
    let mut in_pem_block = false;
    for line in input.lines() {
        let mut redacted_line = line.to_string();
        let lower_line = redacted_line.to_lowercase();

        // 1. Check for PEM/cert material blocks or lines
        if lower_line.contains("-----begin") {
            in_pem_block = true;
            summary.secrets += 1;
            output_lines.push("[REDACTED_PEM_CERT_MATERIAL]".to_string());
            continue;
        }
        if in_pem_block {
            if lower_line.contains("-----end") {
                in_pem_block = false;
            }
            // we don't output anything for internal lines, or we can output redacted placeholder
            // let's just not append the cleartext line, or keep it redacted
            continue;
        }
        if lower_line.contains("-----end") || lower_line.contains("ssh-rsa") {
            summary.secrets += 1;
            output_lines.push("[REDACTED_PEM_CERT_MATERIAL]".to_string());
            continue;
        }

        // 2. Check for SQL statements or database errors.
        if line_contains_sql_or_db_error(&lower_line) {
            summary.sql_statements_or_errors += 1;
            output_lines.push("[REDACTED_SQL_OR_DB_ERROR]".to_string());
            continue;
        }

        if line_contains_secret_marker(&lower_line) {
            summary.secrets += 1;
            output_lines.push("[REDACTED_LINE_CONTAINING_SECRET]".to_string());
            continue;
        }

        // 3. Redact telco marker values in JSON-like or config-like text
        // (e.g. {"dnn":"internet"} or dnn: internet) before token-based
        // scanning, because the tokenizer below splits on quote characters and
        // would otherwise lose the key:value context.
        redacted_line = redact_labeled_spaced_subscriber_ids(&redacted_line, summary, policy);
        redacted_line = redact_marker_value_pairs(&redacted_line, summary, policy);

        // 4. Token-based scanning for IPs, IDs, Paths, JWTs, Spiffe IDs.
        // Split by characters that commonly bound sensitive terms. Do NOT split
        // on '=' or ';' here: telco identifiers use marker=value forms (APN,
        // LI ID, Diameter Session-Id) and Diameter Session-Id values contain
        // ';' as a field separator.
        let tokens: Vec<&str> = redacted_line
            .split(|c: char| {
                c == ' '
                    || c == '\t'
                    || c == ','
                    || c == '\''
                    || c == '"'
                    || c == '['
                    || c == ']'
                    || c == '('
                    || c == ')'
                    || c == '{'
                    || c == '}'
                    || c == '<'
                    || c == '>'
            })
            .collect();

        let mut replacements = Vec::new();
        for &token in &tokens {
            if token.trim().is_empty() {
                continue;
            }

            // If the whole token is a telco marker=value form (e.g.
            // diameter-session-id=...), redact the full value without splitting
            // on ';' so Diameter Session-Id values keep their internal
            // semicolons.
            //
            // If a telco marker value itself contains ';', defer to the
            // subfield scanner below so each key=value subfield is classified
            // independently. This prevents over-redaction where a leading
            // marker such as `li-id=target-42` would swallow a trailing
            // `imsi=208950000000001` as part of the same identifier. Non-marker
            // keys such as `session=operator.example.com;123;0` keep the
            // whole-token path so bare Diameter Session-Id values are still
            // recognized and redacted.
            //
            // Use `token.contains(';')` rather than `value.contains(';')` so
            // that identifiers whose first '=' is inside a trailing parameter
            // (e.g. `sip:+15551234567@operator.com;transport=udp`) are also
            // deferred to the subfield scanner.
            if let Some((_, value)) = token.split_once('=') {
                if !(value.is_empty()
                    || is_already_redacted(value)
                    || (token.contains(';') && starts_with_telco_marker(token)))
                {
                    if let Some(id) = TelcoIdentifier::classify(token) {
                        let placeholder = record_telco_redaction(summary, &id, policy);
                        replacements.push((value.to_string(), placeholder.to_string()));
                        continue;
                    }
                }
            }

            // Otherwise scan semicolon-delimited subfields for embedded
            // marker=value identifiers (e.g. state=ok;li-id=target-42). A
            // Diameter Session-Id marker/value may span multiple ';'-separated
            // parts, so when we see it we consume subsequent parts until the
            // next key=value subfield.
            if token.contains('=') && token.contains(';') {
                let subfields: Vec<&str> = token.split(';').collect();
                let mut subfield_replacements = Vec::new();
                let mut i = 0;
                while i < subfields.len() {
                    let subfield = subfields[i];
                    if subfield.trim().is_empty() {
                        i += 1;
                        continue;
                    }

                    if let Some((_, sub_value)) = subfield.split_once('=') {
                        if !sub_value.is_empty() && !is_already_redacted(sub_value) {
                            if let Some(id) = TelcoIdentifier::classify(subfield) {
                                if id.id_type == IdentifierType::DiameterSessionId {
                                    let mut diameter_parts = vec![sub_value];
                                    let mut j = i + 1;
                                    while j < subfields.len() && !subfields[j].contains('=') {
                                        diameter_parts.push(subfields[j]);
                                        j += 1;
                                    }
                                    let diameter_value = diameter_parts.join(";");
                                    if !diameter_value.is_empty() {
                                        let placeholder =
                                            record_telco_redaction(summary, &id, policy);
                                        subfield_replacements
                                            .push((diameter_value, placeholder.to_string()));
                                    }
                                    i = j;
                                    continue;
                                }

                                let placeholder = record_telco_redaction(summary, &id, policy);
                                subfield_replacements
                                    .push((sub_value.to_string(), placeholder.to_string()));
                                i += 1;
                                continue;
                            }
                        }
                        if !is_already_redacted(sub_value) {
                            if let Some(replacement) = classify_token(sub_value, summary, policy) {
                                subfield_replacements.push((sub_value.to_string(), replacement));
                                i += 1;
                                continue;
                            }
                        }
                    }

                    if let Some(replacement) = classify_token(subfield, summary, policy) {
                        subfield_replacements.push((subfield.to_string(), replacement));
                    }
                    i += 1;
                }
                if !subfield_replacements.is_empty() {
                    replacements.extend(subfield_replacements);
                    continue;
                }
            }

            // Fallback: generic key=value or bare token classification.
            if let Some((_, value)) = token.split_once('=') {
                if let Some(replacement) = classify_token(value, summary, policy) {
                    replacements.push((value.to_string(), replacement));
                    continue;
                }
            }

            if let Some(replacement) = classify_token(token, summary, policy) {
                replacements.push((token.to_string(), replacement));
            }
        }

        // Apply replacements from longest to shortest token
        replacements.sort_by_key(|b| std::cmp::Reverse(b.0.len()));
        for (target, replacement) in replacements {
            redacted_line = redacted_line.replace(&target, &replacement);
        }

        output_lines.push(redacted_line);
    }

    output_lines.join("\n")
}

/// Redact a JSON support-bundle entry by key.
///
/// `HealthDebugJson` and `ConfigSnapshot` entries are parsed structurally so
/// telco-marker fields are redacted regardless of JSON value type (string,
/// number, boolean, null, array). Structural redaction reserializes via
/// `serde_json`, so object key order may be normalized. If the text is not
/// valid JSON, it falls back to the token-based [`redact_text`] path.
pub fn redact_json(input: &str, summary: &mut RedactionSummary) -> String {
    redact_json_with_policy(input, summary, RedactionPolicy::DEFAULT)
}

/// Redact a JSON support-bundle entry by key using the supplied
/// [`RedactionPolicy`].
pub fn redact_json_with_policy(
    input: &str,
    summary: &mut RedactionSummary,
    policy: RedactionPolicy,
) -> String {
    match serde_json::from_str::<serde_json::Value>(input) {
        Ok(mut value) => {
            redact_json_value(&mut value, summary, policy);
            value.to_string()
        }
        Err(_) => redact_text_with_policy(input, summary, policy),
    }
}

fn redact_json_value(
    value: &mut serde_json::Value,
    summary: &mut RedactionSummary,
    policy: RedactionPolicy,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if json_key_is_secret_marker(key) {
                    summary.secrets += 1;
                    *val = serde_json::Value::String("[REDACTED_SECURITY_SECRET]".to_string());
                } else if let Some(id_type) = identifier_type_for_json_key(key) {
                    let placeholder = record_telco_redaction_by_type(summary, id_type, policy);
                    *val = serde_json::Value::String(placeholder.to_string());
                } else {
                    redact_json_value(val, summary, policy);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr.iter_mut() {
                redact_json_value(val, summary, policy);
            }
        }
        ref scalar => {
            if let Some(redacted) = redact_json_scalar(scalar, summary, policy) {
                *value = redacted;
            }
        }
    }
}

fn redact_json_scalar(
    value: &serde_json::Value,
    summary: &mut RedactionSummary,
    policy: RedactionPolicy,
) -> Option<serde_json::Value> {
    match value {
        serde_json::Value::String(s) => {
            if let Some(redacted) = classify_token(s, summary, policy) {
                return Some(serde_json::Value::String(redacted));
            }
            // Prose-style JSON string values may embed identifiers (e.g. a note
            // such as "subscriber IMSI 208950000000001 called"), and compact
            // config-like strings may embed semicolon-delimited marker=value
            // pairs (e.g. "state=ok;li-id=target-42"). Fall back to the full
            // text scanner when the value contains whitespace or marker-like
            // delimiters and the bare token classifier did not match.
            if s.contains(char::is_whitespace) || s.contains([';', '=', ':']) {
                let redacted = redact_text_with_policy(s, summary, policy);
                if redacted != *s {
                    return Some(serde_json::Value::String(redacted));
                }
            }
            None
        }
        serde_json::Value::Number(n) => {
            // JSON numbers cannot carry a leading sign or hex prefix. Convert the
            // number to its textual form and run it through the same telco+legacy
            // classifier used for plain text. This catches IMSI/MSISDN-length digit
            // strings and, via the same heuristic, 32-bit numeric TEID/SPI values
            // that appear under non-canonical keys.
            classify_token(&n.to_string(), summary, policy).map(serde_json::Value::String)
        }
        _ => None,
    }
}

fn identifier_type_for_json_key(key: &str) -> Option<IdentifierType> {
    TELCO_MARKER_KEYS
        .iter()
        .find(|marker| key.eq_ignore_ascii_case(marker))
        .and_then(|marker| crate::telco::marker_to_identifier_type(marker))
}

/// Classify a single token and return the redacted placeholder, updating the
/// summary counters. Returns `None` when the token does not contain sensitive
/// data.
fn classify_token(
    token: &str,
    summary: &mut RedactionSummary,
    policy: RedactionPolicy,
) -> Option<String> {
    let mut trimmed = token.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Trim trailing punctuation to ensure correct matching.
    trimmed = trimmed.trim_end_matches(['.', ':', '!', '?']);
    if trimmed.is_empty() {
        return None;
    }

    // A. SPIFFE ID
    if trimmed.starts_with("spiffe://") {
        summary.spiffe_ids += 1;
        return Some("spiffe://[REDACTED_SPIFFE_ID]".to_string());
    }

    // B. IP Address (v4 or v6, with optional port)
    let ip_candidate = strip_port(trimmed);
    if looks_like_ipv4(ip_candidate) {
        summary.ip_addresses += 1;
        return Some(if ip_candidate == trimmed {
            "[REDACTED_IPV4]".to_string()
        } else {
            "[REDACTED_IPV4]:[REDACTED_PORT]".to_string()
        });
    }
    if looks_like_ipv6(ip_candidate) {
        summary.ip_addresses += 1;
        return Some(if ip_candidate == trimmed {
            "[REDACTED_IPV6]".to_string()
        } else {
            "[REDACTED_IPV6]:[REDACTED_PORT]".to_string()
        });
    }
    if let Some(redacted) = redact_embedded_ip_suffix(trimmed) {
        summary.ip_addresses += 1;
        return Some(redacted);
    }

    // C. Telco identifiers: IMSI/MSISDN/IMEI/NAI/SIP/APN/TEID/SPI/Diameter Session-Id/LI ID.
    // Checked before JWT because dotted telco values (APN, Diameter Session-Id)
    // can otherwise match the JWT heuristics.
    if !is_already_redacted(trimmed) {
        if let Some(id) = TelcoIdentifier::classify(trimmed) {
            // Diameter Session-Id values are only redacted when preceded by a
            // known marker (handled by the marker/value scanner or the
            // semicolon subfield scanner). This prevents non-telco keys such as
            // `session=operator.example.com;123;0` from being over-redacted.
            if id.id_type == IdentifierType::DiameterSessionId {
                return None;
            }
            let placeholder = record_telco_redaction(summary, &id, policy);
            return Some(placeholder.to_string());
        }
    }

    // D. JWT
    if is_jwt(trimmed) {
        summary.secrets += 1;
        return Some("[REDACTED_JWT]".to_string());
    }

    if looks_like_bare_secret(trimmed) {
        summary.secrets += 1;
        return Some("[REDACTED_SECURITY_SECRET]".to_string());
    }

    // E. Paths & DB files
    if trimmed.ends_with(".db") || trimmed.ends_with(".sqlite") {
        summary.paths_and_files += 1;
        return Some("[REDACTED_DB_FILE]".to_string());
    }
    if trimmed.starts_with('/') && trimmed.contains('/') && trimmed.len() > 2 {
        summary.paths_and_files += 1;
        return Some("[REDACTED_PATH]".to_string());
    }

    // F. Obvious secret-bearing tokens that do not match the stricter line-level
    // secret markers (e.g. dotted values such as `jwt.secret.token`).
    if !is_already_redacted(trimmed)
        && !trimmed.contains("REDACTED_")
        && trimmed.to_ascii_lowercase().contains("secret")
    {
        summary.secrets += 1;
        return Some("[REDACTED_SECURITY_SECRET]".to_string());
    }

    // G. Legacy subscriber identifier fallback for shapes the telco classifier missed.
    if looks_like_subscriber_identifier(trimmed) {
        summary.subscriber_identifiers += 1;
        return Some("[REDACTED_SUBSCRIBER_ID]".to_string());
    }

    None
}

fn looks_like_bare_secret(token: &str) -> bool {
    looks_like_sensitive_hex(token) || looks_like_sensitive_base64(token)
}

fn looks_like_sensitive_hex(token: &str) -> bool {
    matches!(token.len(), 8 | 16 | 32 | 40 | 64)
        && token.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn looks_like_sensitive_base64(token: &str) -> bool {
    if token.len() < 32 || !token.len().is_multiple_of(4) {
        return false;
    }
    if looks_like_lowercase_identifier_slug(token) {
        return false;
    }

    let bytes = token.as_bytes();
    let mut padding_started = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_standard_symbol = false;

    for &byte in bytes {
        match byte {
            b'A'..=b'Z' if !padding_started => has_upper = true,
            b'a'..=b'z' if !padding_started => has_lower = true,
            b'0'..=b'9' if !padding_started => has_digit = true,
            b'+' | b'/' if !padding_started => has_standard_symbol = true,
            b'-' | b'_' if !padding_started => {}
            b'=' => padding_started = true,
            _ => return false,
        }
    }

    let padding = bytes.iter().rev().take_while(|&&byte| byte == b'=').count();
    if padding > 2 {
        return false;
    }

    has_standard_symbol || (has_upper && has_lower && has_digit)
}

fn looks_like_lowercase_identifier_slug(token: &str) -> bool {
    let mut saw_separator = false;
    let mut previous_was_separator = false;
    let mut saw_word_char = false;

    for byte in token.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => {
                saw_word_char = true;
                previous_was_separator = false;
            }
            b'_' | b'-' => {
                if !saw_word_char || previous_was_separator {
                    return false;
                }
                saw_separator = true;
                previous_was_separator = true;
            }
            _ => return false,
        }
    }

    saw_separator && !previous_was_separator
}

/// Returns true when `token` begins with a known telco marker followed by an
/// accepted separator (`-`, `_`, `:`, `=`, `.`). This is used to decide whether
/// a `key=value` token whose value contains `;` should be deferred to the
/// semicolon subfield scanner. SIP/SIPS are included because their URI scheme
/// prefix identifies the whole token as a telco identifier.
fn starts_with_telco_marker(token: &str) -> bool {
    const EXTRA: &[&str] = &["sip", "sips"];
    TELCO_MARKER_KEYS.iter().chain(EXTRA.iter()).any(|marker| {
        token.len() > marker.len()
            && token.as_bytes()[..marker.len()].eq_ignore_ascii_case(marker.as_bytes())
            && matches!(
                token.as_bytes()[marker.len()],
                b'-' | b'_' | b':' | b'=' | b'.'
            )
    })
}

/// Redact telco marker values in JSON-like or config-like text, e.g.
/// `{"dnn":"internet"}`, `'li-warrant-id':'war-42'`, or `dnn: internet`. The
/// key must be a known telco marker, followed by optional whitespace, `:` or
/// `=`, optional whitespace, and a quoted or unquoted value. Unquoted config
/// forms such as `apn = internet.operator.com` are also supported.
fn redact_marker_value_pairs(
    input: &str,
    summary: &mut RedactionSummary,
    policy: RedactionPolicy,
) -> String {
    let mut output = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let mut matched = false;

        // Quoted key: "marker" or 'marker'.
        for &quote in b"\"'" {
            if bytes.get(i) != Some(&quote) {
                continue;
            }
            for marker in TELCO_MARKER_KEYS {
                let marker_bytes = marker.as_bytes();
                let key_end = i + 1 + marker_bytes.len();
                if key_end >= bytes.len() {
                    continue;
                }
                if bytes[i + 1..key_end].eq_ignore_ascii_case(marker_bytes)
                    && bytes.get(key_end) == Some(&quote)
                {
                    if let Some((value_start, value_end)) =
                        scan_marker_value(bytes, key_end + 1, quote)
                    {
                        if value_start >= value_end {
                            continue;
                        }
                        let value = &input[value_start..value_end];
                        if is_already_redacted(value) {
                            // Preserve the existing placeholder (including its
                            // surrounding quote/bracket) and continue after it.
                            output.push_str(&input[i..value_start]);
                            output.push_str(value);
                            i = value_end;
                            matched = true;
                            break;
                        }
                        let Some(id_type) = crate::telco::marker_to_identifier_type(marker) else {
                            // This branch is unreachable: every entry in
                            // TELCO_MARKER_KEYS is required to have a mapping by
                            // test_all_telco_markers_have_identifier_type_mapping.
                            // The fall-through is kept defensively so changes to
                            // the marker list cannot silently leak values.
                            continue;
                        };
                        let placeholder = record_telco_redaction_by_type(summary, id_type, policy);
                        output.push_str(&input[i..value_start]);
                        output.push_str(placeholder);
                        i = value_end;
                        matched = true;
                        break;
                    }
                }
            }
            if matched {
                break;
            }
        }

        // Unquoted key: marker at a word boundary, followed by optional
        // whitespace and then `:` or `=` (config-like `apn = internet` forms).
        if !matched {
            for marker in TELCO_MARKER_KEYS {
                let marker_bytes = marker.as_bytes();
                let key_end = i + marker_bytes.len();
                if key_end > bytes.len() {
                    continue;
                }
                let preceding_ok = i == 0
                    || bytes[i - 1].is_ascii_whitespace()
                    || matches!(bytes[i - 1], b'{' | b'[' | b',' | b':' | b';');
                if !preceding_ok || !bytes[i..key_end].eq_ignore_ascii_case(marker_bytes) {
                    continue;
                }
                let mut sep_pos = key_end;
                while sep_pos < bytes.len() && bytes[sep_pos].is_ascii_whitespace() {
                    sep_pos += 1;
                }
                if sep_pos >= bytes.len() || !matches!(bytes[sep_pos], b':' | b'=') {
                    continue;
                }
                let Some(id_type) = crate::telco::marker_to_identifier_type(marker) else {
                    // This branch is unreachable: every entry in
                    // TELCO_MARKER_KEYS is required to have a mapping by
                    // test_all_telco_markers_have_identifier_type_mapping.
                    // The fall-through is kept defensively so changes to the
                    // marker list cannot silently leak values.
                    continue;
                };
                let scanned = if id_type == IdentifierType::DiameterSessionId {
                    // Diameter Session-Id values contain ';' and cannot be
                    // handled by the generic value scanner.
                    scan_diameter_session_id_value(bytes, sep_pos)
                } else {
                    scan_marker_value(bytes, sep_pos, 0)
                };
                if let Some((value_start, value_end)) = scanned {
                    if value_start >= value_end {
                        continue;
                    }
                    let value = &input[value_start..value_end];
                    if is_already_redacted(value) {
                        // Preserve the existing placeholder (including its
                        // surrounding bracket) and continue after it.
                        output.push_str(&input[i..value_start]);
                        output.push_str(value);
                        i = value_end;
                        matched = true;
                        break;
                    }
                    let placeholder = record_telco_redaction_by_type(summary, id_type, policy);
                    output.push_str(&input[i..value_start]);
                    output.push_str(placeholder);
                    i = value_end;
                    matched = true;
                    break;
                }
            }
        }

        if !matched {
            let Some(ch) = input[i..].chars().next() else {
                break;
            };
            output.push(ch);
            i += ch.len_utf8();
        }
    }
    output
}

fn redact_labeled_spaced_subscriber_ids(
    input: &str,
    summary: &mut RedactionSummary,
    policy: RedactionPolicy,
) -> String {
    const MARKERS: &[(&str, IdentifierType)] = &[
        ("imsi", IdentifierType::Imsi),
        ("supi", IdentifierType::Imsi),
        ("msisdn", IdentifierType::Msisdn),
        ("imei", IdentifierType::Imei),
    ];

    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    let mut i = 0;

    while i < bytes.len() {
        let mut replacement = None;
        for &(marker, id_type) in MARKERS {
            if !marker_matches_at(bytes, i, marker) {
                continue;
            }
            let marker_end = i + marker.len();
            if let Some((value_start, value_end)) = scan_spaced_subscriber_value(bytes, marker_end)
            {
                replacement = Some((value_start, value_end, id_type));
                break;
            }
        }

        if let Some((value_start, value_end, id_type)) = replacement {
            let placeholder = record_telco_redaction_by_type(summary, id_type, policy);
            output.push_str(&input[cursor..value_start]);
            output.push_str(placeholder);
            cursor = value_end;
            i = value_end;
            continue;
        }

        let Some(ch) = input[i..].chars().next() else {
            break;
        };
        i += ch.len_utf8();
    }

    if cursor == 0 {
        return input.to_string();
    }

    output.push_str(&input[cursor..]);
    output
}

fn marker_matches_at(bytes: &[u8], pos: usize, marker: &str) -> bool {
    let marker_bytes = marker.as_bytes();
    let marker_end = pos + marker_bytes.len();
    if marker_end >= bytes.len() {
        return false;
    }
    let preceding_ok = pos == 0
        || !bytes[pos - 1].is_ascii_alphanumeric() && !matches!(bytes[pos - 1], b'_' | b'-' | b'.');
    if !preceding_ok || !bytes[pos..marker_end].eq_ignore_ascii_case(marker_bytes) {
        return false;
    }
    bytes[marker_end].is_ascii_whitespace() || matches!(bytes[marker_end], b':' | b'=')
}

fn scan_spaced_subscriber_value(bytes: &[u8], mut pos: usize) -> Option<(usize, usize)> {
    let mut saw_marker_separator = false;
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        saw_marker_separator = true;
        pos += 1;
    }
    if pos < bytes.len() && matches!(bytes[pos], b':' | b'=') {
        saw_marker_separator = true;
        pos += 1;
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
    }
    if !saw_marker_separator || pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
        return None;
    }

    let value_start = pos;
    let mut value_end = pos;
    let mut digits = 0usize;
    let mut saw_value_separator = false;

    while value_end < bytes.len() {
        if bytes[value_end].is_ascii_digit() {
            digits += 1;
            value_end += 1;
            continue;
        }

        if !matches!(bytes[value_end], b' ' | b'\t' | b'-') {
            break;
        }

        let separator_start = value_end;
        while value_end < bytes.len() && matches!(bytes[value_end], b' ' | b'\t' | b'-') {
            value_end += 1;
        }
        if value_end >= bytes.len() || !bytes[value_end].is_ascii_digit() {
            value_end = separator_start;
            break;
        }
        saw_value_separator = true;
    }

    if saw_value_separator && (8..=16).contains(&digits) {
        Some((value_start, value_end))
    } else {
        None
    }
}

/// Scan the bytes after a telco marker key for an optional-whitespace,
/// `:` or `=`, optional-whitespace, and a value. Returns the byte range of the
/// value itself (excluding any surrounding quotes). `quote` is the expected
/// quote character for quoted values; use 0 for unquoted values.
fn scan_marker_value(bytes: &[u8], mut pos: usize, quote: u8) -> Option<(usize, usize)> {
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    if !matches!(bytes.get(pos), Some(b':') | Some(b'=')) {
        return None;
    }
    pos += 1;
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    if pos >= bytes.len() {
        return None;
    }
    if quote != 0 && bytes.get(pos) == Some(&quote) {
        let value_start = pos + 1;
        // Walk the quoted value and honour backslash escapes so an escaped quote
        // (e.g. 'dnn':'intern\'et') does not prematurely terminate the value.
        let mut j = value_start;
        while j < bytes.len() {
            if bytes[j] == b'\\' {
                j += 2;
            } else if bytes[j] == quote {
                return Some((value_start, j));
            } else {
                j += 1;
            }
        }
        None
    } else {
        let value_start = pos;
        // If the value starts with another telco marker followed by ':' or '=',
        // the original key has an empty value; do not treat the following
        // key=value pair as the value of the original key.
        if is_marker_followed_by_separator(&bytes[value_start..]) {
            return None;
        }
        // For non-Diameter markers, treat ';' as a value terminator so the
        // semicolon-subfield scanner can handle later subfields independently.
        // Diameter Session-Id values use `scan_diameter_session_id_value` instead
        // of this path because their core value itself contains ';'.
        let value_end = bytes[value_start..]
            .iter()
            .position(|&b| {
                b.is_ascii_whitespace()
                    || b == b','
                    || b == b';'
                    || b == b'}'
                    || b == b']'
                    || b == b'\n'
                    || b == b'\r'
            })
            .map(|p| value_start + p)
            .unwrap_or(bytes.len());
        if value_start == value_end {
            return None;
        }
        Some((value_start, value_end))
    }
}

/// Scan a Diameter Session-Id value after its separator. Handles unquoted
/// config-like forms such as `diameter-session-id = op.example.com;123;0` and
/// quoted forms such as `diameter-session-id="op.example.com;123;0"`.
/// Returns the byte range of the value (excluding surrounding quotes). The
/// value is consumed through the required origin;high;low fields and stops
/// before a trailing `;key=value` subfield, whitespace, or the closing quote.
fn scan_diameter_session_id_value(bytes: &[u8], mut pos: usize) -> Option<(usize, usize)> {
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    if !matches!(bytes.get(pos), Some(b':') | Some(b'=')) {
        return None;
    }
    pos += 1;
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    if pos >= bytes.len() {
        return None;
    }

    let quote = if matches!(bytes.get(pos), Some(b'"') | Some(b'\'')) {
        Some(bytes[pos])
    } else {
        None
    };
    let value_start = if quote.is_some() { pos + 1 } else { pos };
    if value_start >= bytes.len() {
        return None;
    }

    // End of a semicolon-separated part. When inside a quoted value, also stop
    // at the matching closing quote.
    let part_end = |bytes: &[u8], mut p: usize| -> usize {
        while p < bytes.len() && bytes[p] != b';' && !bytes[p].is_ascii_whitespace() {
            if let Some(q) = quote {
                if bytes[p] == q {
                    break;
                }
            }
            p += 1;
        }
        p
    };

    // origin-host must contain a dot.
    let origin_end = part_end(bytes, value_start);
    if origin_end == value_start || !bytes[value_start..origin_end].contains(&b'.') {
        return None;
    }
    if origin_end >= bytes.len() || bytes[origin_end] != b';' {
        return None;
    }

    // high 32-bit field must be decimal digits.
    let high_start = origin_end + 1;
    let high_end = part_end(bytes, high_start);
    if high_end == high_start
        || !bytes[high_start..high_end]
            .iter()
            .all(|&b| b.is_ascii_digit())
    {
        return None;
    }
    if high_end >= bytes.len() || bytes[high_end] != b';' {
        return None;
    }

    // low 32-bit field must be decimal digits.
    let low_start = high_end + 1;
    let low_end = part_end(bytes, low_start);
    if low_end == low_start
        || !bytes[low_start..low_end]
            .iter()
            .all(|&b| b.is_ascii_digit())
    {
        return None;
    }

    // Consume optional trailing parts that do not contain '=' (e.g. extra AVPs),
    // but stop before a `;key=value` subfield or the closing quote.
    let mut value_end = low_end;
    loop {
        if value_end >= bytes.len() || bytes[value_end].is_ascii_whitespace() {
            break;
        }
        if let Some(q) = quote {
            if bytes[value_end] == q {
                break;
            }
        }
        if bytes[value_end] != b';' {
            break;
        }
        let trailing_start = value_end + 1;
        let trailing_end = part_end(bytes, trailing_start);
        if trailing_end == trailing_start || bytes[trailing_start..trailing_end].contains(&b'=') {
            break;
        }
        value_end = trailing_end;
    }

    Some((value_start, value_end))
}

/// Returns true if `bytes` starts with a known telco marker immediately
/// followed by `:` or `=`.
fn is_marker_followed_by_separator(bytes: &[u8]) -> bool {
    TELCO_MARKER_KEYS.iter().any(|marker| {
        let m = marker.as_bytes();
        bytes.len() > m.len()
            && bytes[..m.len()].eq_ignore_ascii_case(m)
            && matches!(bytes[m.len()], b':' | b'=')
    })
}

fn line_contains_secret_marker(lower_line: &str) -> bool {
    const MARKERS: [&str; 11] = [
        "password",
        "passwd",
        "client_secret",
        "private_key",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "authorization:",
        "bearer ",
        "token=",
    ];
    MARKERS.iter().any(|marker| lower_line.contains(marker))
}

/// Returns true when a JSON object key indicates that its value should be
/// treated as a secret (e.g. `password`, `client_secret`, `authorization`).
fn json_key_is_secret_marker(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let compact: String = lower
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let is_token_key = compact.ends_with("token");

    compact.contains("password")
        || compact.contains("passwd")
        || compact.contains("privatekey")
        || compact.contains("apikey")
        || compact.ends_with("authorization")
        || compact.ends_with("authorizationheader")
        || compact == "bearer"
        || compact.ends_with("credential")
        || compact.ends_with("credentials")
        || compact == "secret"
        || compact.ends_with("secret")
        || compact.ends_with("secretkey")
        || is_token_key
}

fn line_contains_sql_or_db_error(lower_line: &str) -> bool {
    lower_line.contains("sqlite error")
        || lower_line.contains("sqlite3")
        || lower_line.contains("database is locked")
        || lower_line.contains("database disk image")
        || lower_line.contains("sql error")
        || lower_line.contains("select ") && lower_line.contains(" from ")
        || lower_line.contains("insert into ")
        || lower_line.contains("delete from ")
        || lower_line.contains("update ") && lower_line.contains(" set ")
        || lower_line.contains("create table")
}

fn strip_port(token: &str) -> &str {
    let Some((host, port)) = token.rsplit_once(':') else {
        return token;
    };
    if host.contains(':') || !looks_like_port(port) {
        return token;
    }
    host
}

fn looks_like_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.chars().all(|c| c.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

fn redact_embedded_ip_suffix(token: &str) -> Option<String> {
    for (idx, delimiter) in token.char_indices().rev() {
        if !matches!(delimiter, '-' | '_' | '/' | '=') {
            continue;
        }
        let value_start = idx + delimiter.len_utf8();
        if value_start >= token.len() {
            continue;
        }
        let candidate = &token[value_start..];
        let ip_candidate = strip_port(candidate);
        let replacement = if looks_like_ipv4(ip_candidate) {
            if ip_candidate == candidate {
                "[REDACTED_IPV4]"
            } else {
                "[REDACTED_IPV4]:[REDACTED_PORT]"
            }
        } else if looks_like_ipv6(ip_candidate) {
            if ip_candidate == candidate {
                "[REDACTED_IPV6]"
            } else {
                "[REDACTED_IPV6]:[REDACTED_PORT]"
            }
        } else {
            continue;
        };

        let mut redacted = String::with_capacity(token.len());
        redacted.push_str(&token[..value_start]);
        redacted.push_str(replacement);
        return Some(redacted);
    }
    None
}

fn looks_like_ipv4(val: &str) -> bool {
    let mut parts = val.split('.');
    let Some(a) = parts.next() else {
        return false;
    };
    let Some(b) = parts.next() else {
        return false;
    };
    let Some(c) = parts.next() else {
        return false;
    };
    let Some(d) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [a, b, c, d].iter().all(|part| {
        !part.is_empty()
            && part.len() <= 3
            && part.chars().all(|c| c.is_ascii_digit())
            && part.parse::<u8>().is_ok()
    })
}

fn looks_like_ipv6(val: &str) -> bool {
    let colon_count = val.chars().filter(|&c| c == ':').count();
    if !(val.contains("::") || colon_count >= 3) {
        return false;
    }
    val.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

fn looks_like_subscriber_identifier(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    let normalized = lower
        .trim_start_matches("tel:")
        .trim_start_matches("urn:")
        .trim_matches(|c: char| {
            c == '+' || c == '"' || c == '\'' || c == ',' || c == ';' || c == '.' || c == ':'
        });

    if normalized.len() >= 8 && normalized.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    const MARKERS: [&str; 6] = ["supi", "gpsi", "imsi", "msisdn", "guti", "pei"];
    MARKERS.iter().any(|marker| {
        normalized
            .strip_prefix(marker)
            .is_some_and(|suffix| suffix.chars().any(|c| c.is_ascii_digit()))
    })
}

fn is_jwt(val: &str) -> bool {
    let parts: Vec<&str> = val.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    // Require realistic JWT dimensions to avoid redacting ordinary dotted
    // hostnames such as `operator.example.com` as secrets.
    val.len() >= 30
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() >= 4
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// Main entrypoint for redacting a list of diagnostic entries into a RedactedSupportBundle.
pub fn redact_support_bundle(
    entries: &[DiagnosticEntry],
    mode: BundleMode,
) -> Result<RedactedSupportBundle, RedactionError> {
    redact_support_bundle_with_policy(entries, mode, RedactionPolicy::DEFAULT)
}

/// Main entrypoint for redacting a list of diagnostic entries into a
/// RedactedSupportBundle using the supplied [`RedactionPolicy`].
pub fn redact_support_bundle_with_policy(
    entries: &[DiagnosticEntry],
    mode: BundleMode,
    policy: RedactionPolicy,
) -> Result<RedactedSupportBundle, RedactionError> {
    let mut redacted_entries = Vec::new();
    let mut summary = RedactionSummary::default();

    for entry in entries {
        match entry {
            DiagnosticEntry::ArbitraryDiagnosticAttachment {
                name,
                content,
                is_safe_metadata,
            } => {
                if mode == BundleMode::Production && !*is_safe_metadata {
                    return Err(RedactionError::ProductionSafetyViolation(name.clone()));
                }
                let text = match from_utf8(content) {
                    Ok(t) => redact_text_with_policy(t, &mut summary, policy),
                    Err(_) => {
                        summary.unknown_entries_rejected += 1;
                        if mode == BundleMode::Production {
                            return Err(RedactionError::ProductionSafetyViolation(name.clone()));
                        }
                        "[REDACTED_BINARY_OR_UNSAFE_ATTACHMENT]".to_string()
                    }
                };
                redacted_entries.push(RedactedEntry {
                    name: name.clone(),
                    entry_type: entry.entry_type().to_string(),
                    content: text,
                });
            }
            DiagnosticEntry::Unknown { name, .. } => {
                if mode == BundleMode::Production {
                    return Err(RedactionError::ProductionSafetyViolation(name.clone()));
                }
                summary.unknown_entries_rejected += 1;
                redacted_entries.push(RedactedEntry {
                    name: name.clone(),
                    entry_type: entry.entry_type().to_string(),
                    content: "[REDACTED_UNKNOWN_ENTRY_TYPE]".to_string(),
                });
            }
            _ => {
                let text = match entry {
                    DiagnosticEntry::Log(t) => t,
                    DiagnosticEntry::ConfigSnapshot(t) => t,
                    DiagnosticEntry::HealthDebugJson(t) => t,
                    DiagnosticEntry::AlarmSnapshot(t) => t,
                    DiagnosticEntry::MetricsText(t) => t,
                    DiagnosticEntry::RuntimeTaskState(t) => t,
                    DiagnosticEntry::PersistenceError(t) => t,
                    _ => unreachable!(),
                };
                let redacted_text = match entry {
                    DiagnosticEntry::ConfigSnapshot(_) | DiagnosticEntry::HealthDebugJson(_) => {
                        redact_json_with_policy(text, &mut summary, policy)
                    }
                    _ => redact_text_with_policy(text, &mut summary, policy),
                };
                redacted_entries.push(RedactedEntry {
                    name: entry.name().to_string(),
                    entry_type: entry.entry_type().to_string(),
                    content: redacted_text,
                });
            }
        }
    }

    Ok(RedactedSupportBundle {
        entries: redacted_entries,
        redaction_applied: summary.total_redactions() > 0,
        redaction_summary: summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_data_governance::TelcoIdentifierClass;

    #[test]
    fn test_redact_text_identifiers_and_secrets() {
        let mut summary = RedactionSummary::default();
        let log = "Subscriber 208950000000001 (IMSI) connected from 10.0.0.1 with SPIFFE ID spiffe://opc.local/ns/default/sa/amf. JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c. Database file /var/lib/opc/users.db is locked, see log at /var/log/opc.log.";
        let redacted = redact_text(log, &mut summary);

        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert!(redacted.contains("[REDACTED_IPV4]"));
        assert!(redacted.contains("spiffe://[REDACTED_SPIFFE_ID]"));
        assert!(redacted.contains("[REDACTED_JWT]"));
        assert!(redacted.contains("[REDACTED_PATH]"));
        assert!(redacted.contains("[REDACTED_DB_FILE]"));

        assert_eq!(summary.subscriber_identifiers, 1);
        assert_eq!(summary.ip_addresses, 1);
        assert_eq!(summary.spiffe_ids, 1);
        assert_eq!(summary.secrets, 1);
        assert_eq!(summary.paths_and_files, 2); // /var/lib/opc/users.db and users.db
    }

    #[test]
    fn test_redact_text_bare_high_entropy_secrets() {
        let mut summary = RedactionSummary::default();
        let log = concat!(
            "derived kek ",
            "3f2a111111111111111111111111111111111111111111111111111111111111",
            " and wrapped token q83KLcP0uVwF+7aTq83KLcP0uVwF+7aTq83KLcP0uVw="
        );

        let redacted = redact_text(log, &mut summary);

        assert!(
            !redacted.contains("3f2a111111111111111111111111111111111111111111111111111111111111")
        );
        assert!(!redacted.contains("q83KLcP0uVwF+7aTq83KLcP0uVwF+7aTq83KLcP0uVw="));
        assert_eq!(redacted.matches("[REDACTED_SECURITY_SECRET]").count(), 2);
        assert_eq!(summary.secrets, 2);
    }

    #[test]
    fn test_redact_text_preserves_snake_case_error_codes_that_resemble_base64url() {
        let error_code = "swu_ike_auth_child_sa_negotiation_failed";
        assert!(error_code.len() >= 32);
        assert!(error_code.len().is_multiple_of(4));

        let mut direct_summary = RedactionSummary::default();
        let direct_redacted = redact_text(error_code, &mut direct_summary);
        assert_eq!(direct_redacted, error_code);
        assert_eq!(direct_summary.secrets, 0);

        let mut summary = RedactionSummary::default();
        let log = concat!(
            "error_code=swu_ike_auth_child_sa_negotiation_failed ",
            "wrapped token q83KLcP0uVwF+7aTq83KLcP0uVwF+7aTq83KLcP0uVw="
        );

        let redacted = redact_text(log, &mut summary);

        assert!(redacted.contains("swu_ike_auth_child_sa_negotiation_failed"));
        assert!(!redacted.contains("q83KLcP0uVwF+7aTq83KLcP0uVwF+7aTq83KLcP0uVw="));
        assert_eq!(redacted.matches("[REDACTED_SECURITY_SECRET]").count(), 1);
        assert_eq!(summary.secrets, 1);
    }

    #[test]
    fn test_redact_support_bundle_bare_high_entropy_secret() {
        let entries = vec![DiagnosticEntry::Log(
            "derived kek 3f2a111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
        )];

        let bundle = redact_support_bundle(&entries, BundleMode::Production)
            .expect("support bundle redacts bare high-entropy secret");

        assert!(bundle.entries[0]
            .content
            .contains("[REDACTED_SECURITY_SECRET]"));
        assert_eq!(bundle.redaction_summary.secrets, 1);
    }

    #[test]
    fn test_redact_pem_and_sql() {
        let mut summary = RedactionSummary::default();
        let pem_log = format!(
            "Error loading key: -----BEGIN {}-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6...\n-----END {}-----",
            "PRIVATE KEY", "PRIVATE KEY"
        );
        let redacted_pem = redact_text(&pem_log, &mut summary);
        assert_eq!(redacted_pem, "[REDACTED_PEM_CERT_MATERIAL]");
        assert_eq!(summary.secrets, 1);

        let mut summary2 = RedactionSummary::default();
        let sql_log = "Executing query: SELECT * FROM subscribers WHERE imsi = '208950000000001'";
        let redacted_sql = redact_text(sql_log, &mut summary2);
        assert_eq!(redacted_sql, "[REDACTED_SQL_OR_DB_ERROR]");
        assert_eq!(summary2.sql_statements_or_errors, 1);
    }

    #[test]
    fn test_sql_redaction_does_not_match_status_update_prose() {
        let mut summary = RedactionSummary::default();
        let msg = "Stale status update rejected for cluster cluster-us-east: incoming resource version 4 is less than existing 5";
        let redacted = redact_text(msg, &mut summary);
        assert_eq!(redacted, msg);
        assert_eq!(summary.sql_statements_or_errors, 0);

        let mut summary = RedactionSummary::default();
        let sql = "Database transaction failed on UPDATE sessions SET state = 'down' WHERE id = 42";
        let redacted = redact_text(sql, &mut summary);
        assert_eq!(redacted, "[REDACTED_SQL_OR_DB_ERROR]");
        assert_eq!(summary.sql_statements_or_errors, 1);
    }

    #[test]
    fn test_unknown_fails_closed_in_production() {
        let entries = vec![
            DiagnosticEntry::Log("all clean".to_string()),
            DiagnosticEntry::Unknown {
                name: "mystery_blob".to_string(),
                content: vec![1, 2, 3],
            },
        ];

        let dev_res = redact_support_bundle(&entries, BundleMode::Development);
        assert!(dev_res.is_ok());
        let bundle = dev_res.unwrap();
        assert_eq!(bundle.redaction_summary.unknown_entries_rejected, 1);

        let prod_res = redact_support_bundle(&entries, BundleMode::Production);
        assert!(prod_res.is_err());
    }

    #[test]
    fn test_arbitrary_attachment_in_production() {
        let entries_safe = vec![DiagnosticEntry::ArbitraryDiagnosticAttachment {
            name: "safe_meta".to_string(),
            content: b"some text config".to_vec(),
            is_safe_metadata: true,
        }];
        let prod_res_safe = redact_support_bundle(&entries_safe, BundleMode::Production);
        assert!(prod_res_safe.is_ok());

        let entries_unsafe = vec![DiagnosticEntry::ArbitraryDiagnosticAttachment {
            name: "unsafe_meta".to_string(),
            content: b"some raw binary".to_vec(),
            is_safe_metadata: false,
        }];
        let prod_res_unsafe = redact_support_bundle(&entries_unsafe, BundleMode::Production);
        assert!(prod_res_unsafe.is_err());
    }

    #[test]
    fn test_marker_identifiers_ip_ports_and_secret_assignments() {
        let mut summary = RedactionSummary::default();
        let log = "imsi-208950000000001 msisdn:+15551234567 peer=192.168.1.10:443 token=abc";
        let redacted = redact_text(log, &mut summary);

        assert_eq!(redacted, "[REDACTED_LINE_CONTAINING_SECRET]");
        assert_eq!(summary.secrets, 1);

        let mut summary = RedactionSummary::default();
        let log = "imsi-208950000000001 msisdn:+15551234567 peer=192.168.1.10:443";
        let redacted = redact_text(log, &mut summary);

        assert!(!redacted.contains("208950000000001"));
        assert!(!redacted.contains("+15551234567"));
        assert!(!redacted.contains("192.168.1.10"));
        assert_eq!(summary.subscriber_identifiers, 2);
        assert_eq!(summary.ip_addresses, 1);

        let mut summary = RedactionSummary::default();
        let log = "started_at=12:34:56 peer=2001:db8::1";
        let redacted = redact_text(log, &mut summary);
        assert!(redacted.contains("12:34:56"));
        assert!(redacted.contains("[REDACTED_IPV6]"));
        assert_eq!(summary.ip_addresses, 1);

        let mut summary = RedactionSummary::default();
        let log = "principal=operator-192.168.1.100 peer=operator-2001:db8::1";
        let redacted = redact_text(log, &mut summary);
        assert!(redacted.contains("principal=operator-[REDACTED_IPV4]"));
        assert!(redacted.contains("peer=operator-[REDACTED_IPV6]"));
        assert_eq!(summary.ip_addresses, 2);
    }

    #[test]
    fn test_safe_binary_attachment_fails_closed_in_production() {
        let entries = vec![DiagnosticEntry::ArbitraryDiagnosticAttachment {
            name: "safe_but_binary".to_string(),
            content: vec![0xff, 0x00, 0x01],
            is_safe_metadata: true,
        }];

        assert!(redact_support_bundle(&entries, BundleMode::Production).is_err());
        assert!(redact_support_bundle(&entries, BundleMode::Development).is_ok());
    }

    #[test]
    fn test_clean_bundle_reports_no_redaction() {
        let entries = vec![DiagnosticEntry::Log("service ready".to_string())];
        let bundle = redact_support_bundle(&entries, BundleMode::Production).unwrap();
        assert!(!bundle.redaction_applied);
        assert_eq!(bundle.redaction_summary.total_redactions(), 0);
    }

    #[test]
    fn test_redact_text_telco_identifiers() {
        let mut summary = RedactionSummary::default();
        // Realistic ePDG diagnostic forms with '=' and ';' separators.
        let log = "nai=user@operator.com sip:+15551234567@operator.com apn=internet.operator.com dnn=internet teid=0x12345678 spi=0x9abcdef0 diameter-session-id=operator.example.com;123;0 li-id=target-42 li-warrant-id=war-42 li-correlation-id=corr-42 delivery-address=mdf";
        let redacted = redact_text(log, &mut summary);

        assert!(!redacted.contains("user@operator.com"));
        assert!(!redacted.contains("+15551234567"));
        assert!(!redacted.contains("internet.operator.com"));
        assert!(!redacted.contains("dnn=internet"));
        assert!(!redacted.contains("0x12345678"));
        assert!(!redacted.contains("0x9abcdef0"));
        assert!(!redacted.contains("operator.example.com;123;0"));
        assert!(!redacted.contains("target-42"));
        assert!(!redacted.contains("war-42"));
        assert!(!redacted.contains("corr-42"));
        assert!(!redacted.contains("delivery-address=mdf"));
        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert!(redacted.contains("[REDACTED_SECURITY_SECRET]"));
        assert!(redacted.contains("[REDACTED_SESSION_ENDPOINT]"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));

        // Exactly eleven distinct telco identifier values are redacted, counted
        // by their accurate data categories.
        assert_eq!(summary.subscriber_identifiers, 1); // nai
        assert_eq!(summary.network_sensitive_identifiers, 4); // sip, apn, dnn, diameter-session-id
        assert_eq!(summary.secrets, 1); // spi
        assert_eq!(summary.session_endpoints, 1); // teid
        assert_eq!(summary.lawful_intercept_identifiers, 4); // li-id, li-warrant-id, li-correlation-id, delivery-address
        assert_eq!(summary.total_redactions(), 11);
    }

    #[test]
    fn test_redact_text_telco_marker_values_do_not_leak() {
        // Regression test for marker=value forms that were previously split on
        // '=' and ';' before classification, leaking the value.
        let mut summary = RedactionSummary::default();
        let log = "nai=user@operator.com session=operator.example.com;123;0 li-id=target-42";
        let redacted = redact_text(log, &mut summary);

        assert!(!redacted.contains("user@operator.com"));
        // 'session' is not a telco marker, so its value is intentionally left
        // untouched by the telco marker/value scanner.
        assert!(redacted.contains("session=operator.example.com;123;0"));
        assert!(!redacted.contains("target-42"));
        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert_eq!(summary.subscriber_identifiers, 1);
        assert_eq!(summary.lawful_intercept_identifiers, 1);
    }

    #[test]
    fn test_redact_text_telco_marker_forms_exact_bypass_regression() {
        // Exact forms from the review feedback that previously leaked the
        // identifier value because the scanner split on '=' and ';'.
        let mut summary = RedactionSummary::default();
        let log =
            "apn=internet.operator.com diameter-session-id=op.example.com;123;0 li-id=target-42";
        let redacted = redact_text(log, &mut summary);

        assert!(!redacted.contains("internet.operator.com"));
        assert!(!redacted.contains("op.example.com;123;0"));
        assert!(!redacted.contains("target-42"));
        assert!(!redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert_eq!(summary.network_sensitive_identifiers, 2);
        assert_eq!(summary.lawful_intercept_identifiers, 1);
        assert_eq!(summary.subscriber_identifiers, 0);
    }

    #[test]
    fn test_redact_text_telco_diameter_session_id_whitespace_separator() {
        // Diameter Session-Id values contain ';', so the generic value scanner
        // rejects them; unquoted config forms with whitespace around ':'/'='
        // must still be redacted for all documented marker spellings.
        let cases = [
            "diameter-session-id = op.example.com;123;0",
            "diameter_session_id = op.example.com;123;0",
            "diameter.session.id : op.example.com;123;0",
            "diameterSessionId = op.example.com;123;0",
        ];

        for log in cases {
            let mut summary = RedactionSummary::default();
            let redacted = redact_text(log, &mut summary);
            assert!(
                !redacted.contains("op.example.com;123;0"),
                "value leaked for input: {}",
                log
            );
            assert!(
                redacted.contains("[REDACTED_NETWORK_SENSITIVE]"),
                "placeholder missing for input: {}",
                log
            );
            assert_eq!(
                summary.network_sensitive_identifiers, 1,
                "wrong counter for input: {}",
                log
            );
        }

        // A trailing `;key=value` subfield must not be swallowed.
        let mut summary = RedactionSummary::default();
        let log = "diameter-session-id = op.example.com;123;0;state=ok";
        let redacted = redact_text(log, &mut summary);
        assert!(!redacted.contains("op.example.com;123;0"));
        assert!(redacted.contains("state=ok"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert_eq!(summary.network_sensitive_identifiers, 1);
    }

    #[test]
    fn test_redact_text_telco_whitespace_marker_with_semicolon_terminator() {
        // Non-Diameter marker values terminated by ';' (or followed by a
        // ';key=value' subfield) must redact the value before the semicolon.
        let mut summary = RedactionSummary::default();
        let redacted = redact_text("li-id = target-42;", &mut summary);
        assert!(!redacted.contains("target-42"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert_eq!(summary.lawful_intercept_identifiers, 1);

        let mut summary = RedactionSummary::default();
        let redacted = redact_text("apn = internet.operator.com;", &mut summary);
        assert!(!redacted.contains("internet.operator.com"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert_eq!(summary.network_sensitive_identifiers, 1);

        let mut summary = RedactionSummary::default();
        let redacted = redact_text("li-id = target-42;imsi=208950000000001", &mut summary);
        assert!(!redacted.contains("target-42"));
        assert!(!redacted.contains("208950000000001"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert_eq!(summary.lawful_intercept_identifiers, 1);
        assert_eq!(summary.subscriber_identifiers, 1);
    }

    #[test]
    fn test_redact_text_telco_marker_separator_matrix() {
        // Comprehensive coverage: every supported marker spelling must redact
        // with no whitespace, whitespace around '=', and whitespace around ':'.
        #[allow(clippy::type_complexity)]
        let cases: &[(&str, &str, IdentifierType)] = &[
            ("imsi", "208950000000001", IdentifierType::Imsi),
            ("msisdn", "+15551234567", IdentifierType::Msisdn),
            ("imei", "490154203237518", IdentifierType::Imei),
            ("nai", "user@operator.com", IdentifierType::Nai),
            ("apn", "internet.operator.com", IdentifierType::Apn),
            ("dnn", "internet", IdentifierType::Dnn),
            ("teid", "0x12345678", IdentifierType::Teid),
            ("spi", "0x9abcdef0", IdentifierType::Spi),
            ("li-id", "target-42", IdentifierType::LiId),
            ("li-warrant-id", "war-42", IdentifierType::LiWarrantId),
            (
                "li-correlation-id",
                "corr-42",
                IdentifierType::LiCorrelationId,
            ),
            ("delivery-address", "mdf", IdentifierType::DeliveryAddress),
        ];
        let separators = ["=", " = ", ":", " : "];

        for (marker, value, id_type) in cases {
            for sep in separators {
                let log = format!("{}{}{}", marker, sep, value);
                let mut summary = RedactionSummary::default();
                let redacted = redact_text(&log, &mut summary);
                assert!(!redacted.contains(value), "value leaked for input: {}", log);
                assert!(
                    redacted.contains("[REDACTED_"),
                    "placeholder missing for input: {}",
                    log
                );
                assert!(
                    summary.total_redactions() >= 1,
                    "no redaction counted for input: {}",
                    log
                );

                // Sanity-check the counter bucket matches the identifier type.
                match id_type.telco_class() {
                    Some(TelcoIdentifierClass::Subscriber) => {
                        assert_eq!(
                            summary.subscriber_identifiers, 1,
                            "wrong bucket for input: {}",
                            log
                        );
                    }
                    Some(TelcoIdentifierClass::SessionEndpoint) => {
                        assert_eq!(
                            summary.session_endpoints, 1,
                            "wrong bucket for input: {}",
                            log
                        );
                    }
                    Some(TelcoIdentifierClass::SecurityAssociation) => {
                        assert_eq!(summary.secrets, 1, "wrong bucket for input: {}", log);
                    }
                    Some(TelcoIdentifierClass::Application) => {
                        assert_eq!(
                            summary.network_sensitive_identifiers, 1,
                            "wrong bucket for input: {}",
                            log
                        );
                    }
                    Some(TelcoIdentifierClass::LawfulIntercept) => {
                        assert_eq!(
                            summary.lawful_intercept_identifiers, 1,
                            "wrong bucket for input: {}",
                            log
                        );
                    }
                    None => {}
                    _ => {}
                }
            }
        }

        // Diameter Session-Id marker spellings (semicolon-bearing value).
        let diameter_markers = [
            "diameter-session-id",
            "diameter_session_id",
            "diameter.session.id",
            "diameterSessionId",
        ];
        for marker in diameter_markers {
            for sep in separators {
                let log = format!("{}{}op.example.com;123;0", marker, sep);
                let mut summary = RedactionSummary::default();
                let redacted = redact_text(&log, &mut summary);
                assert!(
                    !redacted.contains("op.example.com;123;0"),
                    "Diameter Session-Id leaked for input: {}",
                    log
                );
                assert!(
                    redacted.contains("[REDACTED_NETWORK_SENSITIVE]"),
                    "placeholder missing for input: {}",
                    log
                );
                assert_eq!(
                    summary.network_sensitive_identifiers, 1,
                    "wrong counter for input: {}",
                    log
                );
            }
        }
    }

    #[test]
    fn test_redact_text_telco_marker_idempotent() {
        // Re-redacting a line that already contains placeholders must not
        // double-count counters or corrupt the placeholder text.
        let mut summary = RedactionSummary::default();
        let log = "apn = internet.operator.com li-id = target-42";
        let once = redact_text(log, &mut summary);
        assert!(!once.contains("internet.operator.com"));
        assert!(!once.contains("target-42"));
        let first_total = summary.total_redactions();
        assert!(first_total > 0);

        let twice = redact_text(&once, &mut summary);
        assert_eq!(twice, once);
        assert_eq!(summary.total_redactions(), first_total);
    }

    #[test]
    fn test_redact_text_does_not_panic_on_hostile_utf8() {
        // Untrusted log text with multibyte tokens and a bare marker-looking
        // prefix must not abort redaction.
        let mut summary = RedactionSummary::default();
        let log = "日本 éaé sip 日本語=secret li-id=target-42";
        let redacted = redact_text(log, &mut summary);

        assert!(!redacted.contains("target-42"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert!(summary.lawful_intercept_identifiers > 0);
    }

    #[test]
    fn test_redact_text_embedded_telco_marker_in_semicolon_list() {
        // Embedded marker=value forms after ';' must be redacted without
        // splitting Diameter Session-Id values.
        let mut summary = RedactionSummary::default();
        let log = "state=ok;li-id=target-42";
        let redacted = redact_text(log, &mut summary);
        assert!(!redacted.contains("target-42"));
        assert!(redacted.contains("state=ok"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert_eq!(summary.lawful_intercept_identifiers, 1);

        let mut summary = RedactionSummary::default();
        let log = "state=ok;diameter-session-id=op.example.com;123;0";
        let redacted = redact_text(log, &mut summary);
        assert!(!redacted.contains("op.example.com;123;0"));
        assert!(redacted.contains("state=ok"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert_eq!(summary.network_sensitive_identifiers, 1);

        let mut summary = RedactionSummary::default();
        let log = "state=ok;diameter-session-id=op.example.com;123;0;li-id=target-42";
        let redacted = redact_text(log, &mut summary);
        assert!(!redacted.contains("op.example.com;123;0"));
        assert!(!redacted.contains("target-42"));
        assert!(redacted.contains("state=ok"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert_eq!(summary.network_sensitive_identifiers, 1);
        assert_eq!(summary.lawful_intercept_identifiers, 1);
    }

    #[test]
    fn test_redact_text_leading_marker_with_semicolon_subfields() {
        // A token that starts with a telco marker and also contains ';'-separated
        // subfields must be handled by the subfield scanner so each identifier is
        // counted and redacted independently.
        let mut summary = RedactionSummary::default();
        let log = "li-id=target-42;imsi=208950000000001";
        let redacted = redact_text(log, &mut summary);

        assert!(!redacted.contains("target-42"));
        assert!(!redacted.contains("208950000000001"));
        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        // Two distinct identifiers, not one over-redacted blob.
        assert_eq!(summary.lawful_intercept_identifiers, 1);
        assert_eq!(summary.subscriber_identifiers, 1);

        // Diameter Session-Id with trailing non-identifier parts still works.
        let mut summary = RedactionSummary::default();
        let log = "diameter-session-id=op.example.com;123;0;state=ok";
        let redacted = redact_text(log, &mut summary);
        assert!(!redacted.contains("op.example.com;123;0"));
        assert!(redacted.contains("state=ok"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert_eq!(summary.network_sensitive_identifiers, 1);
    }

    #[test]
    fn test_redact_text_labeled_spaced_subscriber_ids() {
        let mut summary = RedactionSummary::default();
        let log = "investigating IMSI 20895 00000 00001 after callback";
        let redacted = redact_text(log, &mut summary);

        assert!(!redacted.contains("20895 00000 00001"));
        assert!(redacted.contains("IMSI [REDACTED_SUBSCRIBER_ID]"));
        assert!(redacted.contains("after callback"));
        assert_eq!(summary.subscriber_identifiers, 1);

        let mut summary = RedactionSummary::default();
        let log = "supi: 20895-00000-00002";
        let redacted = redact_text(log, &mut summary);

        assert_eq!(redacted, "supi: [REDACTED_SUBSCRIBER_ID]");
        assert_eq!(summary.subscriber_identifiers, 1);
    }

    #[test]
    fn test_redact_text_telco_quoted_json_marker_values() {
        // JSON-style quoted key:value pairs with telco markers must be redacted
        // without relying on the token scanner, which splits on quote characters.
        let mut summary = RedactionSummary::default();
        let log =
            r#"{"dnn":"internet","li-warrant-id":"war-42","delivery-address":"mdf","count":123}"#;
        let redacted = redact_text(log, &mut summary);

        assert!(!redacted.contains("internet"));
        assert!(!redacted.contains("war-42"));
        assert!(!redacted.contains("mdf"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert!(redacted.contains("\"count\":123"));
        assert_eq!(summary.network_sensitive_identifiers, 1);
        assert_eq!(summary.lawful_intercept_identifiers, 2);

        // Single-quoted config-like variants and whitespace around ':'/'='.
        let mut summary = RedactionSummary::default();
        let log = "'apn' : 'internet.operator.com' 'imsi' = '208950000000001'";
        let redacted = redact_text(log, &mut summary);
        assert!(!redacted.contains("internet.operator.com"));
        assert!(!redacted.contains("208950000000001"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert_eq!(summary.network_sensitive_identifiers, 1);
        assert_eq!(summary.subscriber_identifiers, 1);

        // Escaped quote inside a single-quoted value must not truncate the value
        // and leave a suffix unredacted.
        let mut summary = RedactionSummary::default();
        let log = r#"'dnn':'intern\'et'"#;
        let redacted = redact_text(log, &mut summary);
        assert!(!redacted.contains("intern"));
        assert!(!redacted.contains("et"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert_eq!(summary.network_sensitive_identifiers, 1);
    }

    #[test]
    fn test_redact_text_telco_whitespace_around_separator() {
        // Unquoted config-style marker/value pairs with whitespace around the
        // separator must be redacted, not tokenized into separate words.
        let mut summary = RedactionSummary::default();
        let log = "apn = internet.operator.com li-id = target-42 dnn : internet";
        let redacted = redact_text(log, &mut summary);

        assert!(!redacted.contains("internet.operator.com"));
        assert!(!redacted.contains("target-42"));
        assert!(!redacted.contains("internet"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert_eq!(summary.network_sensitive_identifiers, 2);
        assert_eq!(summary.lawful_intercept_identifiers, 1);
    }

    #[test]
    fn test_redact_text_telco_sip_uri_with_parameters() {
        // SIP URIs with ';param=value' parameters must redact the subscriber
        // URI part, not just the parameter value after the first '='.
        let mut summary = RedactionSummary::default();
        let log = "sip:+15551234567@operator.com;transport=udp";
        let redacted = redact_text(log, &mut summary);

        assert!(!redacted.contains("+15551234567"));
        assert!(!redacted.contains("operator.com"));
        assert!(redacted.contains("transport=udp"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert_eq!(summary.network_sensitive_identifiers, 1);

        // SIPS variant.
        let mut summary = RedactionSummary::default();
        let log = "sips:+15551234567@operator.com;transport=tcp";
        let redacted = redact_text(log, &mut summary);
        assert!(!redacted.contains("+15551234567"));
        assert!(!redacted.contains("operator.com"));
        assert!(redacted.contains("transport=tcp"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert_eq!(summary.network_sensitive_identifiers, 1);
    }

    #[test]
    fn test_redact_text_empty_marker_value_does_not_corrupt_line() {
        // A marker with no value must not cause an empty-string replacement
        // that inserts placeholders between every character.
        let mut summary = RedactionSummary::default();
        let log = "apn= li-id= teid=0x12345678";
        let redacted = redact_text(log, &mut summary);
        assert!(!redacted.contains("0x12345678"));
        assert!(redacted.contains("apn="));
        assert!(redacted.contains("li-id="));
        assert!(!redacted.contains("[REDACTED_SUBSCRIBER_ID][REDACTED_SUBSCRIBER_ID]"));
        assert!(redacted.contains("[REDACTED_SESSION_ENDPOINT]"));
        assert_eq!(summary.session_endpoints, 1);
        assert_eq!(summary.secrets, 0);
        assert_eq!(summary.network_sensitive_identifiers, 0);
        assert_eq!(summary.lawful_intercept_identifiers, 0);
    }

    #[test]
    fn test_redact_json_support_bundle_entries() {
        // HealthDebugJson and ConfigSnapshot entries must be parsed structurally
        // so telco-marker fields are redacted regardless of JSON value type.
        let json = r#"{
            "teid": 305419896,
            "spi": 2596069104,
            "dnn": "internet",
            "apn": "internet.operator.com",
            "imsi": "208950000000001",
            "li_warrant_id": "war-42",
            "li_correlation_id": "corr-42",
            "delivery_address": "mdf",
            "nested": { "teid": 1234 },
            "subscriber": "208950000000001",
            "raw_imsi": 208950000000001,
            "ids": ["sip:+15551234567@operator.com"],
            "count": 123
        }"#;

        let mut summary = RedactionSummary::default();
        let redacted = redact_json(json, &mut summary);

        assert!(!redacted.contains("305419896"));
        assert!(!redacted.contains("2596069104"));
        assert!(!redacted.contains("internet"));
        assert!(!redacted.contains("internet.operator.com"));
        assert!(!redacted.contains("208950000000001"));
        assert!(!redacted.contains("+15551234567"));
        assert!(!redacted.contains("war-42"));
        assert!(!redacted.contains("corr-42"));
        assert!(!redacted.contains("mdf"));
        assert!(!redacted.contains("1234"));
        assert!(redacted.contains("\"count\":123"));

        assert!(redacted.contains("[REDACTED_SESSION_ENDPOINT]"));
        assert!(redacted.contains("[REDACTED_SECURITY_SECRET]"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));

        assert_eq!(summary.session_endpoints, 2); // top-level + nested teid
        assert_eq!(summary.secrets, 1); // spi
        assert_eq!(summary.network_sensitive_identifiers, 3); // dnn + apn + ids[0]
        assert_eq!(summary.subscriber_identifiers, 3); // imsi + subscriber + raw_imsi
        assert_eq!(summary.lawful_intercept_identifiers, 3); // li_warrant_id + li_correlation_id + delivery_address

        // Redacted output must still be valid JSON.
        let reparsed: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(reparsed["count"], 123);

        // Escaped quotes inside JSON string values must survive intact.
        let escaped = r#"{"dnn":"intern\"et","count":7}"#;
        let mut summary2 = RedactionSummary::default();
        let redacted_escaped = redact_json(escaped, &mut summary2);
        assert!(!redacted_escaped.contains("intern\"et"));
        assert!(redacted_escaped.contains("[REDACTED_NETWORK_SENSITIVE]"));
        let reparsed_escaped: serde_json::Value = serde_json::from_str(&redacted_escaped).unwrap();
        assert_eq!(reparsed_escaped["count"], 7);

        // The same redaction applies through redact_support_bundle for
        // HealthDebugJson and ConfigSnapshot entry types.
        let entries = vec![
            DiagnosticEntry::HealthDebugJson(json.to_string()),
            DiagnosticEntry::ConfigSnapshot(json.to_string()),
        ];
        let bundle = redact_support_bundle(&entries, BundleMode::Production).unwrap();
        assert!(bundle.redaction_applied);
        for entry in &bundle.entries {
            assert!(
                serde_json::from_str::<serde_json::Value>(&entry.content).is_ok(),
                "redacted {} must remain valid JSON: {}",
                entry.entry_type,
                entry.content
            );
        }

        // Even the generic text path must catch JSON objects with numeric
        // telco-marker values and leave valid JSON behind.
        let mut summary3 = RedactionSummary::default();
        let text_redacted = redact_text(json, &mut summary3);
        assert!(!text_redacted.contains("305419896"));
        assert!(!text_redacted.contains("2596069104"));
        assert!(serde_json::from_str::<serde_json::Value>(&text_redacted).is_ok());
        assert_eq!(summary3.session_endpoints, 2);
        assert_eq!(summary3.secrets, 1);
    }

    #[test]
    fn test_redact_json_telco_diameter_session_id_snake_case_key() {
        // Regression: JSON producers often emit snake_case or camelCase keys for
        // Diameter Session-Id. The value must be redacted even though bare
        // Diameter Session-Id values are intentionally not classified outside a
        // known marker context.
        let mut summary = RedactionSummary::default();
        let json = r#"{"diameter_session_id":"op.example.com;123;0"}"#;
        let redacted = redact_json(json, &mut summary);
        assert!(!redacted.contains("op.example.com;123;0"));
        assert!(redacted.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert_eq!(summary.network_sensitive_identifiers, 1);
        assert!(serde_json::from_str::<serde_json::Value>(&redacted).is_ok());

        let mut summary2 = RedactionSummary::default();
        let json2 = r#"{"diameterSessionId":"op.example.com;123;0"}"#;
        let redacted2 = redact_json(json2, &mut summary2);
        assert!(!redacted2.contains("op.example.com;123;0"));
        assert!(redacted2.contains("[REDACTED_NETWORK_SENSITIVE]"));
        assert_eq!(summary2.network_sensitive_identifiers, 1);
        assert!(serde_json::from_str::<serde_json::Value>(&redacted2).is_ok());
    }

    #[test]
    fn test_redact_json_telco_embedded_identifier_in_prose() {
        // JSON string values that contain prose with embedded telco identifiers
        // must be redacted, not left as cleartext because the scalar classifier
        // only looks at the whole value.
        let mut summary = RedactionSummary::default();
        let json = r#"{"note":"subscriber IMSI 208950000000001 called"}"#;
        let redacted = redact_json(json, &mut summary);
        assert!(!redacted.contains("208950000000001"));
        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert_eq!(summary.subscriber_identifiers, 1);
        assert!(serde_json::from_str::<serde_json::Value>(&redacted).is_ok());
    }

    #[test]
    fn test_redact_json_telco_secret_keys() {
        // JSON objects with secret-bearing keys must have their values replaced
        // with a security-secret placeholder, matching the fail-closed
        // line-level secret marker guard.
        let cases = [
            (r#"{"password":"abc123"}"#, "abc123"),
            (r#"{"client_secret":"s3"}"#, "s3"),
            (
                r#"{"private_key":"-----BEGIN RSA PRIVATE KEY-----"}"#,
                "-----BEGIN RSA PRIVATE KEY-----",
            ),
            (r#"{"api_key":"ak_live_12345"}"#, "ak_live_12345"),
            (r#"{"apikey":"hidden"}"#, "hidden"),
            (
                r#"{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}"#,
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            ),
            (r#"{"refresh_token":"rt_abc"}"#, "rt_abc"),
            (r#"{"auth_token":"tok_abc"}"#, "tok_abc"),
            (r#"{"token":"opaque-token-value"}"#, "opaque-token-value"),
            (r#"{"authToken":"tok_camel"}"#, "tok_camel"),
            (r#"{"accessToken":"access_camel"}"#, "access_camel"),
            (r#"{"refresh-token":"rt_hyphen"}"#, "rt_hyphen"),
            (r#"{"refresh.token":"rt_dot"}"#, "rt_dot"),
            (r#"{"authorization":"Basic abc123"}"#, "Basic abc123"),
            (
                r#"{"secret":"generic-secret-value"}"#,
                "generic-secret-value",
            ),
            (r#"{"secret_key":"secret-key-value"}"#, "secret-key-value"),
            (
                r#"{"credentials":"client-id:client-secret"}"#,
                "client-id:client-secret",
            ),
            // Case-insensitive key matching.
            (r#"{"CLIENT_SECRET":"s3"}"#, "s3"),
            (r#"{"ApiKey":"hidden-api-key"}"#, "hidden-api-key"),
            (
                r#"{"Authorization":"Basic dXNlcjpwYXNz"}"#,
                "Basic dXNlcjpwYXNz",
            ),
        ];

        for (json, secret) in cases {
            let mut summary = RedactionSummary::default();
            let redacted = redact_text(json, &mut summary);
            assert!(
                !redacted.contains(secret),
                "secret value leaked for {}: {}",
                json,
                redacted
            );
            assert!(
                redacted.contains("[REDACTED_SECURITY_SECRET]"),
                "placeholder missing for {}: {}",
                json,
                redacted
            );
            assert_eq!(summary.secrets, 1, "wrong counter for {}", json);
            assert!(serde_json::from_str::<serde_json::Value>(&redacted).is_ok());
        }

        // Nested secret keys and arrays must also be handled.
        let mut summary = RedactionSummary::default();
        let json = r#"{"outer":{"client_secret":"nested"},"items":[{"password":"arr"}]}"#;
        let redacted = redact_text(json, &mut summary);
        assert!(!redacted.contains("nested"));
        assert!(!redacted.contains("arr"));
        assert!(redacted.contains("[REDACTED_SECURITY_SECRET]"));
        assert_eq!(summary.secrets, 2);
        assert!(serde_json::from_str::<serde_json::Value>(&redacted).is_ok());
    }

    #[test]
    fn test_redact_json_telco_token_metadata_keys_are_not_secret_markers() {
        // Token-shaped metadata keys must not be treated as secret-bearing
        // fields just because they contain the substring "token".
        let json = r#"{"token_type":"Bearer","tokens":["public"],"token_count":2,"tokenizer":"wordpiece"}"#;
        let mut summary = RedactionSummary::default();
        let redacted = redact_text(json, &mut summary);

        assert!(redacted.contains("\"token_type\":\"Bearer\""));
        assert!(redacted.contains("\"tokens\":[\"public\"]"));
        assert!(redacted.contains("\"token_count\":2"));
        assert!(redacted.contains("\"tokenizer\":\"wordpiece\""));
        assert!(!redacted.contains("[REDACTED_SECURITY_SECRET]"));
        assert_eq!(summary.secrets, 0);
        assert!(serde_json::from_str::<serde_json::Value>(&redacted).is_ok());
    }

    #[test]
    fn test_redact_support_bundle_telco_secret_keys() {
        // Support-bundle JSON entry types (HealthDebugJson and ConfigSnapshot)
        // must redact values under secret-bearing keys.
        let json = r#"{"password":"super-secret-password","client_secret":"client-secret-value","api_key":"api-key-value","authorization":"Basic abc123","secret":"generic-secret-value","secret_key":"secret-key-value"}"#;
        let entries = vec![
            DiagnosticEntry::HealthDebugJson(json.to_string()),
            DiagnosticEntry::ConfigSnapshot(json.to_string()),
        ];
        let bundle = redact_support_bundle(&entries, BundleMode::Production).unwrap();
        assert!(!bundle.entries[0].content.contains("super-secret-password"));
        assert!(!bundle.entries[0].content.contains("client-secret-value"));
        assert!(!bundle.entries[0].content.contains("api-key-value"));
        assert!(!bundle.entries[0].content.contains("Basic abc123"));
        assert!(!bundle.entries[0].content.contains("generic-secret-value"));
        assert!(!bundle.entries[0].content.contains("secret-key-value"));
        assert!(bundle.entries[0]
            .content
            .contains("[REDACTED_SECURITY_SECRET]"));
        assert!(!bundle.entries[1].content.contains("super-secret-password"));
        assert!(!bundle.entries[1].content.contains("client-secret-value"));
        assert!(!bundle.entries[1].content.contains("api-key-value"));
        assert!(!bundle.entries[1].content.contains("Basic abc123"));
        assert!(!bundle.entries[1].content.contains("generic-secret-value"));
        assert!(!bundle.entries[1].content.contains("secret-key-value"));
        assert!(bundle.entries[1]
            .content
            .contains("[REDACTED_SECURITY_SECRET]"));
        assert_eq!(bundle.redaction_summary.secrets, 12);
        assert!(bundle.redaction_applied);
    }

    #[test]
    fn test_redact_support_bundle_telco_apn_dnn_policy() {
        // Default policy treats APN/DNN as network-sensitive; deployments that
        // consider them subscriber data can override the classification.
        let json = r#"{"apn":"internet.operator.com","dnn":"internet"}"#;
        let entries = vec![DiagnosticEntry::HealthDebugJson(json.to_string())];

        let bundle_default = redact_support_bundle(&entries, BundleMode::Production).unwrap();
        assert_eq!(
            bundle_default
                .redaction_summary
                .network_sensitive_identifiers,
            2
        );
        assert_eq!(bundle_default.redaction_summary.subscriber_identifiers, 0);
        assert!(!bundle_default.entries[0].content.contains("internet"));

        let policy = RedactionPolicy::with_apn_dnn_class(ApnDnnClass::SubscriberId);
        let bundle_subscriber =
            redact_support_bundle_with_policy(&entries, BundleMode::Production, policy).unwrap();
        assert_eq!(
            bundle_subscriber
                .redaction_summary
                .network_sensitive_identifiers,
            0
        );
        assert_eq!(
            bundle_subscriber.redaction_summary.subscriber_identifiers,
            2
        );
        assert!(!bundle_subscriber.entries[0].content.contains("internet"));
    }

    #[test]
    fn test_redaction_summary_deserializes_legacy_summary() {
        // Pre-change summaries used `secrets` and did not contain the new telco
        // counters. With `#[serde(default)]` and the `secrets` alias, such
        // output still deserializes and missing counters default to zero.
        let json = r#"{"subscriber_identifiers":1,"secrets":2,"ip_addresses":3,"spiffe_ids":0,"paths_and_files":4,"sql_statements_or_errors":0,"unknown_entries_rejected":0}"#;
        let summary: RedactionSummary = serde_json::from_str(json).unwrap();
        assert_eq!(summary.secrets, 2);
        assert_eq!(summary.subscriber_identifiers, 1);
        assert_eq!(summary.ip_addresses, 3);
        assert_eq!(summary.paths_and_files, 4);
        assert_eq!(summary.session_endpoints, 0);
        assert_eq!(summary.lawful_intercept_identifiers, 0);
        assert_eq!(summary.network_sensitive_identifiers, 0);
    }

    #[test]
    fn test_redaction_summary_secrets_wire_name_is_backward_compatible() {
        // Newly-produced summaries must serialize the secret counter as the
        // legacy `secrets` field so existing consumers keep working. The new
        // `security_secrets` name is still accepted during deserialization.
        let summary = RedactionSummary {
            subscriber_identifiers: 1,
            secrets: 2,
            ip_addresses: 3,
            ..RedactionSummary::default()
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"secrets\":2"));
        assert!(!json.contains("\"security_secrets\""));

        // Round-trip through the legacy wire name.
        let round: RedactionSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(round, summary);

        // Deserialization also accepts the new `security_secrets` name.
        let json_new = r#"{"subscriber_identifiers":1,"security_secrets":2,"ip_addresses":3}"#;
        let from_new: RedactionSummary = serde_json::from_str(json_new).unwrap();
        assert_eq!(from_new.secrets, 2);
    }

    #[test]
    fn test_all_telco_markers_have_identifier_type_mapping() {
        // Every marker advertised to the support-bundle scanner must map to a
        // canonical IdentifierType. This guards the fail-closed `continue` paths
        // in `redact_marker_value_pairs` from silently skipping redaction.
        for marker in crate::telco::TELCO_MARKER_KEYS {
            assert!(
                crate::telco::marker_to_identifier_type(marker).is_some(),
                "marker {:?} has no IdentifierType mapping",
                marker
            );
        }
    }

    #[test]
    fn test_redact_json_numeric_subscriber_identifiers_under_arbitrary_keys() {
        // Numeric values under non-canonical keys that look like subscriber
        // identifiers (8-15 digits) must still be redacted, while ordinary small
        // counters are left untouched. Without a hex prefix these values classify
        // as subscriber IDs rather than TEID/SPI.
        let json = r#"{"unknown_teid": 305419896, "unknown_spi": 2596069104, "count": 123}"#;
        let mut summary = RedactionSummary::default();
        let redacted = redact_json(json, &mut summary);

        assert!(!redacted.contains("305419896"));
        assert!(!redacted.contains("2596069104"));
        assert!(redacted.contains("\"count\":123"));
        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert_eq!(summary.subscriber_identifiers, 2);
        assert!(serde_json::from_str::<serde_json::Value>(&redacted).is_ok());
    }

    #[test]
    fn test_redact_text_telco_marker_value_form_matrix() {
        // Regression matrix covering marker spellings, separators, value forms
        // (plain, semicolon-terminated, `;key=value` suffix, quoted), and
        // idempotency. Each case must redact exactly once and preserve all
        // surrounding punctuation/structure.
        fn expected_placeholder(id_type: IdentifierType) -> &'static str {
            let data_class = RedactionPolicy::DEFAULT.data_class_for(id_type);
            placeholder_for_class(data_class)
        }

        #[derive(Debug, Clone, Copy)]
        struct Case {
            marker: &'static str,
            value: &'static str,
            id_type: IdentifierType,
        }

        let cases = [
            Case {
                marker: "imsi",
                value: "208950000000001",
                id_type: IdentifierType::Imsi,
            },
            Case {
                marker: "li-id",
                value: "target-42",
                id_type: IdentifierType::LiId,
            },
            Case {
                marker: "apn",
                value: "internet.operator.com",
                id_type: IdentifierType::Apn,
            },
            Case {
                marker: "diameter-session-id",
                value: "op.example.com;123;0",
                id_type: IdentifierType::DiameterSessionId,
            },
        ];
        let separators = ["=", " = ", ":", " : "];

        for case in cases {
            for sep in separators {
                let forms: Vec<(String, Vec<&str>)> =
                    if case.id_type == IdentifierType::DiameterSessionId {
                        vec![
                            (format!("{}{}{}", case.marker, sep, case.value), vec![]),
                            (format!("{}{}{};", case.marker, sep, case.value), vec![";"]),
                            (
                                format!("{}{}{};state=ok", case.marker, sep, case.value),
                                vec![";state=ok"],
                            ),
                            (
                                format!("{}{}\"{}\"", case.marker, sep, case.value),
                                vec!["\"", "\""],
                            ),
                            (
                                format!("{}{}\"{}\";state=ok", case.marker, sep, case.value),
                                vec!["\"", "\";state=ok"],
                            ),
                        ]
                    } else {
                        vec![
                            (format!("{}{}{}", case.marker, sep, case.value), vec![]),
                            (format!("{}{}{};", case.marker, sep, case.value), vec![";"]),
                            (
                                format!("{}{}{};state=ok", case.marker, sep, case.value),
                                vec![";state=ok"],
                            ),
                        ]
                    };

                for (log, preserved) in forms {
                    let mut summary = RedactionSummary::default();
                    let redacted = redact_text(&log, &mut summary);
                    assert!(
                        !redacted.contains(case.value),
                        "value leaked for input: {:?}",
                        log
                    );
                    let placeholder = expected_placeholder(case.id_type);
                    assert!(
                        redacted.contains(placeholder),
                        "placeholder missing for input: {:?}\ngot: {:?}",
                        log,
                        redacted
                    );
                    assert_eq!(
                        summary.total_redactions(),
                        1,
                        "wrong counter for input: {:?}",
                        log
                    );
                    for fragment in preserved {
                        assert!(
                            redacted.contains(fragment),
                            "preserved fragment {:?} missing for input: {:?}\ngot: {:?}",
                            fragment,
                            log,
                            redacted
                        );
                    }

                    // Idempotency: re-redacting the already-redacted line must be
                    // byte-for-byte identical and must not increment any counters.
                    let first_total = summary.total_redactions();
                    let twice = redact_text(&redacted, &mut summary);
                    assert_eq!(
                        twice, redacted,
                        "re-redaction changed output for input: {:?}\nfirst: {:?}\nsecond: {:?}",
                        log, redacted, twice
                    );
                    assert_eq!(
                        summary.total_redactions(),
                        first_total,
                        "re-redaction incremented counters for input: {:?}",
                        log
                    );
                }
            }
        }
    }

    #[test]
    fn test_redact_text_telco_marker_after_semicolon_with_whitespace() {
        // Embedded marker=value forms after ';' must be redacted even when the
        // marker uses whitespace around its separator (e.g. `li-id = target-42`).
        let mut summary = RedactionSummary::default();
        let redacted = redact_text("state=ok;li-id = target-42", &mut summary);
        assert!(!redacted.contains("target-42"));
        assert!(redacted.contains("state=ok"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert_eq!(summary.lawful_intercept_identifiers, 1);

        // Multiple embedded markers with whitespace separators.
        let mut summary = RedactionSummary::default();
        let redacted = redact_text(
            "state=ok;li-id = target-42;imsi : 208950000000001",
            &mut summary,
        );
        assert!(!redacted.contains("target-42"));
        assert!(!redacted.contains("208950000000001"));
        assert!(redacted.contains("state=ok"));
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert_eq!(summary.lawful_intercept_identifiers, 1);
        assert_eq!(summary.subscriber_identifiers, 1);
    }

    #[test]
    fn test_redact_json_telco_compact_semicolon_delimited_marker_string() {
        // Compact JSON strings containing semicolon-delimited marker=value
        // pairs (with no whitespace) must be redacted by the JSON scalar
        // fallback, not left unchanged.
        let mut summary = RedactionSummary::default();
        let json = r#"{"note":"state=ok;li-id=target-42"}"#;
        let redacted = redact_json(json, &mut summary);
        assert!(
            !redacted.contains("target-42"),
            "value leaked in JSON: {}",
            redacted
        );
        assert!(
            redacted.contains("state=ok"),
            "preserved state=ok: {}",
            redacted
        );
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert_eq!(summary.lawful_intercept_identifiers, 1);
        assert!(serde_json::from_str::<serde_json::Value>(&redacted).is_ok());

        // Mixed compact and prose forms inside JSON arrays.
        let mut summary = RedactionSummary::default();
        let json = r#"["state=ok;li-id=target-42","subscriber IMSI 208950000000001"]"#;
        let redacted = redact_json(json, &mut summary);
        assert!(!redacted.contains("target-42"), "LI leaked: {}", redacted);
        assert!(
            !redacted.contains("208950000000001"),
            "IMSI leaked: {}",
            redacted
        );
        assert!(redacted.contains("[REDACTED_LAWFUL_INTERCEPT_ID]"));
        assert!(redacted.contains("[REDACTED_SUBSCRIBER_ID]"));
        assert!(serde_json::from_str::<serde_json::Value>(&redacted).is_ok());
    }

    #[test]
    fn test_redact_text_telco_quoted_diameter_session_id_alternate_markers() {
        // Every supported Diameter Session-Id marker spelling must redact when
        // the value is quoted after an unquoted key.
        let markers = [
            "diameter-session-id",
            "diameter_session_id",
            "diameter.session.id",
            "diameterSessionId",
        ];
        let separators = ["=", " = ", ":", " : "];
        for marker in markers {
            for sep in separators {
                for quote in ["\"", "'"] {
                    let mut summary = RedactionSummary::default();
                    let log = format!("{}{}{}op.example.com;123;0{}", marker, sep, quote, quote);
                    let redacted = redact_text(&log, &mut summary);
                    assert!(
                        !redacted.contains("op.example.com;123;0"),
                        "value leaked for input: {:?}",
                        log
                    );
                    assert!(
                        redacted.contains("[REDACTED_NETWORK_SENSITIVE]"),
                        "placeholder missing for input: {:?}\ngot: {:?}",
                        log,
                        redacted
                    );
                    assert_eq!(
                        summary.network_sensitive_identifiers, 1,
                        "wrong counter for input: {:?}",
                        log
                    );
                }
            }
        }
    }
}
