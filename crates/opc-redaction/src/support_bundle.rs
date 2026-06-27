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
pub struct RedactionSummary {
    pub subscriber_identifiers: usize,
    pub secrets: usize,
    pub ip_addresses: usize,
    pub spiffe_ids: usize,
    pub paths_and_files: usize,
    pub sql_statements_or_errors: usize,
    pub unknown_entries_rejected: usize,
}

impl RedactionSummary {
    pub fn total_redactions(&self) -> usize {
        self.subscriber_identifiers
            + self.secrets
            + self.ip_addresses
            + self.spiffe_ids
            + self.paths_and_files
            + self.sql_statements_or_errors
            + self.unknown_entries_rejected
    }
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

        // 3. Token-based scanning for IPs, IDs, Paths, JWTs, Spiffe IDs
        // We'll split the line by characters that commonly bound sensitive terms
        let tokens: Vec<&str> = redacted_line
            .split(|c: char| {
                c == ' '
                    || c == '\t'
                    || c == ','
                    || c == ';'
                    || c == '='
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
            let mut trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Trim trailing punctuation to ensure correct matching
            trimmed = trimmed.trim_end_matches(['.', ':', '!', '?']);
            if trimmed.is_empty() {
                continue;
            }

            // A. SPIFFE ID
            if trimmed.starts_with("spiffe://") {
                summary.spiffe_ids += 1;
                replacements.push((
                    trimmed.to_string(),
                    "spiffe://[REDACTED_SPIFFE_ID]".to_string(),
                ));
                continue;
            }

            // B. IP Address (v4 or v6, with optional port)
            let ip_candidate = strip_port(trimmed);
            if looks_like_ipv4(ip_candidate) {
                summary.ip_addresses += 1;
                replacements.push((
                    trimmed.to_string(),
                    if ip_candidate == trimmed {
                        "[REDACTED_IPV4]".to_string()
                    } else {
                        "[REDACTED_IPV4]:[REDACTED_PORT]".to_string()
                    },
                ));
                continue;
            }
            if looks_like_ipv6(ip_candidate) {
                summary.ip_addresses += 1;
                replacements.push((
                    trimmed.to_string(),
                    if ip_candidate == trimmed {
                        "[REDACTED_IPV6]".to_string()
                    } else {
                        "[REDACTED_IPV6]:[REDACTED_PORT]".to_string()
                    },
                ));
                continue;
            }

            // C. JWT
            if is_jwt(trimmed) {
                summary.secrets += 1;
                replacements.push((trimmed.to_string(), "[REDACTED_JWT]".to_string()));
                continue;
            }

            // D. Paths & DB files
            if trimmed.ends_with(".db") || trimmed.ends_with(".sqlite") {
                summary.paths_and_files += 1;
                replacements.push((trimmed.to_string(), "[REDACTED_DB_FILE]".to_string()));
                continue;
            }
            if trimmed.starts_with('/') && trimmed.contains('/') && trimmed.len() > 2 {
                summary.paths_and_files += 1;
                replacements.push((trimmed.to_string(), "[REDACTED_PATH]".to_string()));
                continue;
            }

            // E. Subscriber identifiers: raw long digits or marker-shaped values.
            if looks_like_subscriber_identifier(trimmed) {
                summary.subscriber_identifiers += 1;
                replacements.push((trimmed.to_string(), "[REDACTED_SUBSCRIBER_ID]".to_string()));
                continue;
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
        normalized.starts_with(&format!("{marker}-"))
            || normalized.starts_with(&format!("{marker}_"))
            || normalized.starts_with(&format!("{marker}:"))
            || normalized.starts_with(&format!("{marker}="))
            || normalized
                .strip_prefix(marker)
                .is_some_and(|suffix| suffix.chars().any(|c| c.is_ascii_digit()))
    })
}

fn is_jwt(val: &str) -> bool {
    let parts: Vec<&str> = val.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    val.len() > 12
        && parts.iter().all(|part| {
            !part.is_empty()
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
                    Ok(t) => redact_text(t, &mut summary),
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
                let redacted_text = redact_text(text, &mut summary);
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

    #[test]
    fn test_redact_text_identifiers_and_secrets() {
        let mut summary = RedactionSummary::default();
        let log = "Subscriber 208950000000001 (IMSI) connected from 10.0.0.1 with SPIFFE ID spiffe://opc.local/ns/default/sa/amf. JWT token: aaaaa.bbbbb.ccccc. Database file /var/lib/opc/users.db is locked, see log at /var/log/opc.log.";
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
}
