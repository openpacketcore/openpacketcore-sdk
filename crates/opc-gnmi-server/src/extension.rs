//! Fail-safe gNMI registered extension policy.

use std::collections::BTreeMap;

use crate::GnmiError;

/// Proto-free gNMI extension envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Registered extension ID.
    pub id: u32,
    /// Whether an unsupported extension is critical to request semantics.
    pub critical: bool,
    /// Opaque extension payload. This is never included in errors or metrics.
    pub payload: Vec<u8>,
}

impl Extension {
    /// Builds an extension envelope.
    pub fn new(id: u32, critical: bool, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            id,
            critical,
            payload: payload.into(),
        }
    }
}

/// Extension registration metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredExtension {
    id: u32,
    name: String,
    advertised: bool,
}

impl RegisteredExtension {
    /// Registers a known extension. Set `advertised` only after semantics are
    /// implemented end to end.
    pub fn new(id: u32, name: impl Into<String>, advertised: bool) -> Result<Self, GnmiError> {
        let name = name.into();
        if name.is_empty()
            || name.trim() != name
            || name.chars().any(char::is_control)
            || !name
                .chars()
                .all(|ch| matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.'))
        {
            return Err(GnmiError::invalid("invalid gNMI extension name"));
        }
        Ok(Self {
            id,
            name,
            advertised,
        })
    }

    /// Registered extension ID.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Low-cardinality extension name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether Capabilities should advertise this extension.
    pub const fn advertised(&self) -> bool {
        self.advertised
    }
}

/// Result of extension validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedExtension {
    /// Registered extension ID.
    pub id: u32,
    /// Registered extension name.
    pub name: String,
}

/// Per-extension validation disposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionDisposition {
    /// Known extension accepted.
    Accepted(AcceptedExtension),
    /// Unknown non-critical extension ignored.
    IgnoredUnknown { id: u32 },
}

/// Registry for extension handling and advertisement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtensionRegistry {
    registered: BTreeMap<u32, RegisteredExtension>,
}

impl ExtensionRegistry {
    /// Builds a registry.
    pub fn new(
        extensions: impl IntoIterator<Item = RegisteredExtension>,
    ) -> Result<Self, GnmiError> {
        let mut registered = BTreeMap::new();
        for ext in extensions {
            if registered.insert(ext.id(), ext).is_some() {
                return Err(GnmiError::invalid("duplicate gNMI extension id"));
            }
        }
        let registry = Self { registered };
        registry.validate()?;
        Ok(registry)
    }

    /// Validates registry consistency.
    pub fn validate(&self) -> Result<(), GnmiError> {
        for ext in self.registered.values() {
            if ext.advertised() {
                return Err(GnmiError::unimplemented(format!(
                    "gNMI extension {} is registered but not implemented end to end",
                    ext.name()
                )));
            }
        }
        Ok(())
    }

    /// IDs that should appear in Capabilities.
    pub fn advertised_ids(&self) -> Vec<u32> {
        self.registered
            .values()
            .filter(|ext| ext.advertised())
            .map(RegisteredExtension::id)
            .collect()
    }

    /// Validates a request's extension list.
    ///
    /// Unknown critical extensions fail closed. Unknown non-critical extensions
    /// are ignored, as required for extension forward compatibility.
    pub fn validate_request(
        &self,
        extensions: &[Extension],
    ) -> Result<Vec<ExtensionDisposition>, GnmiError> {
        let mut out = Vec::new();
        for ext in extensions {
            if let Some(registered) = self.registered.get(&ext.id) {
                out.push(ExtensionDisposition::Accepted(AcceptedExtension {
                    id: registered.id(),
                    name: registered.name().to_string(),
                }));
            } else if ext.critical {
                return Err(GnmiError::unimplemented(format!(
                    "unknown critical gNMI extension id {}",
                    ext.id
                )));
            } else {
                out.push(ExtensionDisposition::IgnoredUnknown { id: ext.id });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_critical_extensions_fail_closed() {
        let registry = ExtensionRegistry::default();
        let err = registry
            .validate_request(&[Extension::new(999, true, b"secret".to_vec())])
            .unwrap_err();
        assert_eq!(err.status().as_str(), "UNIMPLEMENTED");
        assert!(!err.to_string().contains("secret"));
    }

    #[test]
    fn unknown_non_critical_extensions_are_ignored() {
        let registry = ExtensionRegistry::default();
        let result = registry
            .validate_request(&[Extension::new(999, false, b"payload".to_vec())])
            .expect("ignored");
        assert_eq!(
            result,
            vec![ExtensionDisposition::IgnoredUnknown { id: 999 }]
        );
    }

    #[test]
    fn advertised_extensions_are_blocked_until_semantics_exist() {
        let advertised = RegisteredExtension::new(1, "commit-confirmed", true).expect("ext");
        assert!(ExtensionRegistry::new([advertised]).is_err());

        let hidden = RegisteredExtension::new(1, "commit-confirmed", false).expect("ext");
        let registry = ExtensionRegistry::new([hidden]).expect("registry");
        assert!(registry.advertised_ids().is_empty());
        assert!(matches!(
            registry
                .validate_request(&[Extension::new(1, true, Vec::new())])
                .expect("known")[0],
            ExtensionDisposition::Accepted(_)
        ));
    }
}
