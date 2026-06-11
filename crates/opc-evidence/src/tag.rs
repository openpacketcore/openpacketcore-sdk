use crate::EvidenceError;
use serde::{Deserialize, Serialize};

/// A parsed conformance tag extracted from a doc-comment block.
///
/// Supported keys per RFC 006 §5.2:
/// `spec`, `req`, `conformance`, `gap`, `security`, `performance`, `test`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceTag {
    pub key: String,
    pub value: String,
}

impl ConformanceTag {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Parses a block of doc-comment lines (or plain text) into [`ConformanceTag`]s.
///
/// Lines must start with `@` followed by a known key and a value:
/// ```text
/// @spec 3GPP TS 29.281 R18 5.1 Table 5.1-1
/// @req REQ-3GPP-TS29281-R18-5.1-001
/// @conformance partial
/// @gap GAP-000123
/// ```
///
/// Unknown keys produce an error when `strict` is `true`.
pub fn parse_tags(doc: &str, strict: bool) -> Result<Vec<ConformanceTag>, EvidenceError> {
    const KNOWN_KEYS: &[&str] = &[
        "spec",
        "req",
        "conformance",
        "gap",
        "security",
        "performance",
        "test",
    ];

    let mut tags = Vec::new();
    for line in doc.lines() {
        let trimmed = line.trim();
        // Support `/// @key value`, `// @key value`, or plain `@key value`.
        let body = trimmed
            .strip_prefix("/// ")
            .or_else(|| trimmed.strip_prefix("// "))
            .or_else(|| trimmed.strip_prefix("///"))
            .or_else(|| trimmed.strip_prefix("//"))
            .unwrap_or(trimmed)
            .trim_start();

        let Some(rest) = body.strip_prefix('@') else {
            continue;
        };

        let mut parts = rest.splitn(2, char::is_whitespace);
        let key = parts
            .next()
            .ok_or_else(|| EvidenceError::InvalidTag(trimmed.to_string()))?
            .trim()
            .to_lowercase();
        let value = parts.next().unwrap_or("").trim().to_string();

        if strict && value.is_empty() {
            return Err(EvidenceError::InvalidTag(format!(
                "tag '{key}' requires a value in '{trimmed}'"
            )));
        }

        if key.is_empty() {
            return Err(EvidenceError::InvalidTag(trimmed.to_string()));
        }

        if strict && !KNOWN_KEYS.contains(&key.as_str()) {
            return Err(EvidenceError::InvalidTag(format!(
                "unknown tag key '{key}' in '{trimmed}'"
            )));
        }

        tags.push(ConformanceTag::new(key, value));
    }

    Ok(tags)
}
