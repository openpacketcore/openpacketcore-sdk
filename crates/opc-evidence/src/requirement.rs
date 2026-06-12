use std::fmt;
use std::str::FromStr;

use crate::EvidenceError;

/// Stable requirement identifier: `REQ-<source>-<document>-<release>-<section>-<ordinal>`.
///
/// Example: `REQ-3GPP-TS29281-R18-5.1-001`
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequirementId {
    source: String,
    document: String,
    release: String,
    section: String,
    ordinal: u32,
}

impl RequirementId {
    /// Constructs a `RequirementId` from validated components.
    pub fn new(
        source: impl Into<String>,
        document: impl Into<String>,
        release: impl Into<String>,
        section: impl Into<String>,
        ordinal: u32,
    ) -> Result<Self, EvidenceError> {
        let source = source.into();
        let document = document.into();
        let release = release.into();
        let section = section.into();

        if source.is_empty()
            || source.contains('-')
            || document.is_empty()
            || document.contains('-')
            || release.is_empty()
            || release.contains('-')
            || section.is_empty()
            || section.contains('-')
        {
            return Err(EvidenceError::InvalidRequirementId(format!(
                "REQ-{source}-{document}-{release}-{section}-{ordinal:03}"
            )));
        }

        Ok(Self {
            source,
            document,
            release,
            section,
            ordinal,
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn document(&self) -> &str {
        &self.document
    }

    pub fn release(&self) -> &str {
        &self.release
    }

    pub fn section(&self) -> &str {
        &self.section
    }

    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }
}

impl fmt::Display for RequirementId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "REQ-{}-{}-{}-{}-{:03}",
            self.source, self.document, self.release, self.section, self.ordinal
        )
    }
}

impl FromStr for RequirementId {
    type Err = EvidenceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let rest = value
            .strip_prefix("REQ-")
            .ok_or_else(|| EvidenceError::InvalidRequirementId(value.to_string()))?;

        let parts: Vec<&str> = rest.split('-').collect();
        if parts.len() != 5 {
            return Err(EvidenceError::InvalidRequirementId(value.to_string()));
        }

        let source = parts[0].to_string();
        let document = parts[1].to_string();
        let release = parts[2].to_string();
        let section = parts[3].to_string();
        let ordinal = parts[4]
            .parse::<u32>()
            .map_err(|_| EvidenceError::InvalidRequirementId(value.to_string()))?;

        Self::new(source, document, release, section, ordinal)
            .map_err(|_| EvidenceError::InvalidRequirementId(value.to_string()))
    }
}

impl serde::Serialize for RequirementId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for RequirementId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}
