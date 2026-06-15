//! Schema-backed gNMI Capabilities data.

use std::collections::BTreeSet;

use opc_mgmt_schema::SchemaRegistry;

use crate::{encoding::EncodingRegistry, error::GnmiError, extension::ExtensionRegistry, Encoding};

/// gNMI protocol version string advertised in Capabilities.
///
/// The future proto slice must derive this from the vendored OpenConfig proto
/// pin. Until then the embedding code must provide it explicitly; there is no
/// default value that could pretend a proto version has been selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnmiVersion(String);

impl GnmiVersion {
    /// Builds a validated version string.
    pub fn new(value: impl Into<String>) -> Result<Self, GnmiError> {
        let value = value.into();
        if value.is_empty()
            || value.trim() != value
            || value.chars().any(char::is_control)
            || value.chars().any(char::is_whitespace)
        {
            return Err(GnmiError::invalid("invalid gNMI version string"));
        }
        Ok(Self(value))
    }

    /// Returns the advertised version string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Capability inputs that are independent of a generated schema registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityProfile {
    version: GnmiVersion,
    encodings: EncodingRegistry,
}

impl CapabilityProfile {
    /// Builds a capability profile.
    pub fn new(version: GnmiVersion, encodings: EncodingRegistry) -> Self {
        Self { version, encodings }
    }

    /// Initial JSON-only profile for a known proto version.
    pub fn json_only(version: GnmiVersion) -> Self {
        Self::new(version, EncodingRegistry::json_only())
    }

    /// Validates profile consistency.
    pub fn validate(&self) -> Result<(), GnmiError> {
        self.encodings.validate().map_err(GnmiError::from)
    }

    /// Advertised gNMI version.
    pub const fn version(&self) -> &GnmiVersion {
        &self.version
    }

    /// Advertised encoding registry.
    pub const fn encodings(&self) -> &EncodingRegistry {
        &self.encodings
    }
}

/// One model row for a gNMI Capabilities response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnmiModelData {
    /// YANG module name.
    pub name: String,
    /// Optional organization. The current schema registry does not carry this,
    /// so generated capabilities leave it absent instead of fabricating one from
    /// namespace or prefix.
    pub organization: Option<String>,
    /// Module revision/version.
    pub version: String,
    /// Module XML namespace retained for future proto/render adapters.
    pub namespace: String,
    /// Module prefix retained for future proto/render adapters.
    pub prefix: String,
}

/// Protocol-neutral Capabilities response data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnmiCapabilities {
    /// Served YANG modules.
    pub models: Vec<GnmiModelData>,
    /// Supported encodings, in advertised order.
    pub encodings: Vec<Encoding>,
    /// Supported gNMI version.
    pub gnmi_version: String,
    /// Advertised registered extension IDs.
    pub extensions: Vec<u32>,
}

impl GnmiCapabilities {
    /// Builds Capabilities data from the generated schema registry and explicit
    /// profile. Models are sorted for deterministic output and duplicate module
    /// rows fail closed.
    pub fn from_registry(
        registry: &dyn SchemaRegistry,
        profile: &CapabilityProfile,
        extensions: &ExtensionRegistry,
    ) -> Self {
        let mut models: Vec<_> = registry
            .served_models()
            .iter()
            .map(|model| GnmiModelData {
                name: model.name.to_string(),
                organization: None,
                version: model.revision.to_string(),
                namespace: model.namespace.to_string(),
                prefix: model.prefix.to_string(),
            })
            .collect();
        models.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.version.cmp(&b.version))
                .then_with(|| a.namespace.cmp(&b.namespace))
        });

        Self {
            models,
            encodings: profile.encodings().encodings().to_vec(),
            gnmi_version: profile.version().as_str().to_string(),
            extensions: extensions.advertised_ids(),
        }
    }

    /// Validates that the capability model set has no duplicate name/version
    /// rows and that the encoding profile is non-empty.
    pub fn validate(&self) -> Result<(), GnmiError> {
        if self.encodings.is_empty() {
            return Err(GnmiError::invalid(
                "gNMI capabilities cannot advertise an empty encoding set",
            ));
        }
        let mut seen = BTreeSet::new();
        for model in &self.models {
            if !seen.insert((model.name.as_str(), model.version.as_str())) {
                return Err(GnmiError::schema(format!(
                    "duplicate gNMI model capability {}@{}",
                    model.name, model.version
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_mgmt_schema::{DataClass, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry};

    struct TestRegistry;

    static MODELS: &[ModelData] = &[
        ModelData {
            name: "z-module",
            revision: "2026-06-01",
            namespace: "urn:z",
            prefix: "z",
        },
        ModelData {
            name: "a-module",
            revision: "2026-06-02",
            namespace: "urn:a",
            prefix: "a",
        },
    ];

    static ORIGINS: &[OriginEntry] = &[OriginEntry {
        origin: "",
        modules: &["a-module", "z-module"],
    }];

    static NODES: &[NodeMeta] = &[NodeMeta {
        path: "/a:root",
        module: "a-module",
        kind: NodeKind::Container,
        config: true,
        leaf_type: None,
        key_leaves: &[],
        data_class: DataClass::Public,
        default: None,
        has_default: false,
        presence: false,
        child_paths: &[],
    }];

    impl SchemaRegistry for TestRegistry {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:test"
        }

        fn served_models(&self) -> &'static [ModelData] {
            MODELS
        }

        fn nodes(&self) -> &'static [NodeMeta] {
            NODES
        }

        fn origins(&self) -> &'static [OriginEntry] {
            ORIGINS
        }
    }

    #[test]
    fn capabilities_are_schema_backed_and_deterministic() {
        let profile = CapabilityProfile::json_only(GnmiVersion::new("0.10.0").expect("version"));
        let caps =
            GnmiCapabilities::from_registry(&TestRegistry, &profile, &ExtensionRegistry::default());

        assert_eq!(caps.gnmi_version, "0.10.0");
        assert_eq!(caps.encodings, vec![Encoding::JsonIetf, Encoding::Json]);
        assert_eq!(caps.models[0].name, "a-module");
        assert_eq!(caps.models[1].name, "z-module");
        assert_eq!(caps.models[0].organization, None);
        assert!(caps.extensions.is_empty());
        caps.validate().expect("valid capabilities");
    }

    #[test]
    fn version_is_explicit_and_bounded() {
        assert!(GnmiVersion::new("0.10.0").is_ok());
        assert!(GnmiVersion::new("").is_err());
        assert!(GnmiVersion::new("0.10.0 debug").is_err());
        assert!(GnmiVersion::new(" 0.10.0").is_err());
    }
}
