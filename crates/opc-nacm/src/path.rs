use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::NacmError;

const PATH_KIND: &str = "yang path";
const REGISTRY_KIND: &str = "module registry";

/// Canonical module/prefix registry used to normalize YANG path segments.
#[derive(Debug, Clone, Default)]
pub struct ModuleRegistry {
    prefix_to_modules: BTreeMap<String, BTreeSet<String>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a module/prefix pair.
    ///
    /// Re-registering the same pair is idempotent; registering the same prefix
    /// for multiple modules preserves the ambiguity so that path normalization
    /// can reject it deterministically. Module names, prefixes, and node names
    /// follow the RFC 7950 identifier shape: the first character must be an
    /// ASCII letter or `_`, and later characters may additionally include
    /// digits, `-`, and `.`.
    pub fn register_module(
        &mut self,
        module: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Result<(), NacmError> {
        let module = validate_symbol(REGISTRY_KIND, "module", &module.into())?;
        let prefix = validate_symbol(REGISTRY_KIND, "prefix", &prefix.into())?;

        self.prefix_to_modules
            .entry(prefix.clone())
            .or_default()
            .insert(module.clone());
        Ok(())
    }

    pub fn modules_for_prefix(&self, prefix: &str) -> Option<&BTreeSet<String>> {
        self.prefix_to_modules.get(prefix)
    }

    fn resolve_default_module<'a>(&self, module: &'a str) -> Result<&'a str, NacmError> {
        if self
            .prefix_to_modules
            .values()
            .any(|modules| modules.contains(module))
        {
            return Ok(module);
        }

        if self.prefix_to_modules.contains_key(module) {
            return Err(NacmError::new(
                PATH_KIND,
                format!("default module '{module}' must be a canonical module name, not a prefix"),
            ));
        }

        Err(NacmError::new(
            PATH_KIND,
            format!("unknown default module '{module}'"),
        ))
    }

    fn resolve_prefix(&self, prefix: &str) -> Result<&str, NacmError> {
        let modules = self.prefix_to_modules.get(prefix).ok_or_else(|| {
            NacmError::new(PATH_KIND, format!("unknown module prefix '{prefix}'"))
        })?;

        if modules.len() != 1 {
            let rendered = modules.iter().cloned().collect::<Vec<_>>().join(", ");
            return Err(NacmError::new(
                PATH_KIND,
                format!("ambiguous module prefix '{prefix}' resolves to [{rendered}]"),
            ));
        }

        Ok(modules
            .iter()
            .next()
            .expect("len checked above; single module must exist"))
    }
}

/// Canonical qualified YANG node name resolved to a module name rather than a
/// local prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QualifiedNodeName {
    module: String,
    name: String,
}

impl QualifiedNodeName {
    pub fn new(module: impl Into<String>, name: impl Into<String>) -> Result<Self, NacmError> {
        let module = validate_symbol(PATH_KIND, "module", &module.into())?;
        let name = validate_symbol(PATH_KIND, "node name", &name.into())?;
        Ok(Self { module, name })
    }

    pub fn module(&self) -> &str {
        &self.module
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for QualifiedNodeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.module, self.name)
    }
}

/// Normalized absolute YANG path with every segment resolved to a canonical
/// module name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct YangPath {
    segments: Vec<QualifiedNodeName>,
}

impl YangPath {
    pub fn parse(input: &str, registry: &ModuleRegistry) -> Result<Self, NacmError> {
        Self::parse_with_default_module(input, registry, None)
    }

    pub fn parse_with_default_module(
        input: &str,
        registry: &ModuleRegistry,
        default_module: Option<&str>,
    ) -> Result<Self, NacmError> {
        let segments = parse_segments(input, registry, default_module, false)?;
        if segments.is_empty() {
            return Err(NacmError::new(
                PATH_KIND,
                "absolute paths must contain at least one segment",
            ));
        }

        let exact = segments
            .into_iter()
            .map(|segment| match segment {
                ParsedPatternSegment::Exact(node) => Ok(node),
                ParsedPatternSegment::WildcardAny | ParsedPatternSegment::WildcardModule(_) => Err(
                    NacmError::new(PATH_KIND, "wildcards are only valid in NACM rule patterns"),
                ),
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { segments: exact })
    }

    pub fn segments(&self) -> &[QualifiedNodeName] {
        &self.segments
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

impl fmt::Display for YangPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.segments.is_empty() {
            return f.write_str("/");
        }

        for segment in &self.segments {
            write!(f, "/{segment}")?;
        }
        Ok(())
    }
}

/// One segment within a normalized NACM rule pattern.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum YangPathPatternSegment {
    Exact(QualifiedNodeName),
    WildcardAny,
    WildcardModule(String),
}

impl YangPathPatternSegment {
    pub fn exact_name(&self) -> Option<&QualifiedNodeName> {
        match self {
            Self::Exact(name) => Some(name),
            Self::WildcardAny | Self::WildcardModule(_) => None,
        }
    }
}

impl fmt::Display for YangPathPatternSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(name) => write!(f, "{name}"),
            Self::WildcardAny => f.write_str("*"),
            Self::WildcardModule(module) => write!(f, "{module}:*"),
        }
    }
}

/// Normalized NACM rule pattern. A trailing `/**` grants subtree matching,
/// while `*` or `module:*` segments match a single path segment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct YangPathPattern {
    segments: Vec<YangPathPatternSegment>,
    subtree: bool,
}

impl YangPathPattern {
    pub fn parse(input: &str, registry: &ModuleRegistry) -> Result<Self, NacmError> {
        Self::parse_with_default_module(input, registry, None)
    }

    pub fn parse_with_default_module(
        input: &str,
        registry: &ModuleRegistry,
        default_module: Option<&str>,
    ) -> Result<Self, NacmError> {
        let (base, subtree) = split_subtree_suffix(input)?;
        let segments: Vec<YangPathPatternSegment> =
            parse_segments(base, registry, default_module, true)?
                .into_iter()
                .map(ParsedPatternSegment::into_pattern_segment)
                .collect();

        if !subtree && segments.is_empty() {
            return Err(NacmError::new(
                PATH_KIND,
                "exact rule patterns must contain at least one segment",
            ));
        }

        Ok(Self { segments, subtree })
    }

    pub fn segments(&self) -> &[YangPathPatternSegment] {
        &self.segments
    }

    pub fn is_subtree(&self) -> bool {
        self.subtree
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn matches(&self, path: &YangPath) -> bool {
        if self.subtree {
            if self.segments.len() > path.len() {
                return false;
            }
        } else if self.segments.len() != path.len() {
            return false;
        }

        self.segments
            .iter()
            .zip(path.segments())
            .all(|(pattern, actual)| match pattern {
                YangPathPatternSegment::Exact(name) => name == actual,
                YangPathPatternSegment::WildcardAny => true,
                YangPathPatternSegment::WildcardModule(module) => module == actual.module(),
            })
    }
}

impl fmt::Display for YangPathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.segments.is_empty() {
            return f.write_str("/**");
        }

        for segment in &self.segments {
            write!(f, "/{segment}")?;
        }

        if self.subtree {
            f.write_str("/**")?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedPatternSegment {
    Exact(QualifiedNodeName),
    WildcardAny,
    WildcardModule(String),
}

impl ParsedPatternSegment {
    fn into_pattern_segment(self) -> YangPathPatternSegment {
        match self {
            Self::Exact(name) => YangPathPatternSegment::Exact(name),
            Self::WildcardAny => YangPathPatternSegment::WildcardAny,
            Self::WildcardModule(module) => YangPathPatternSegment::WildcardModule(module),
        }
    }
}

fn split_subtree_suffix(input: &str) -> Result<(&str, bool), NacmError> {
    if input == "/**" {
        return Ok(("/", true));
    }

    if let Some(base) = input.strip_suffix("/**") {
        return Ok((if base.is_empty() { "/" } else { base }, true));
    }

    Ok((input, false))
}

fn parse_segments(
    input: &str,
    registry: &ModuleRegistry,
    default_module: Option<&str>,
    allow_wildcards: bool,
) -> Result<Vec<ParsedPatternSegment>, NacmError> {
    if input.is_empty() {
        return Err(NacmError::new(PATH_KIND, "paths must not be empty"));
    }

    if input.trim() != input {
        return Err(NacmError::new(
            PATH_KIND,
            "paths must not contain leading or trailing whitespace",
        ));
    }

    if !input.starts_with('/') {
        return Err(NacmError::new(PATH_KIND, "paths must start with '/'"));
    }

    if input == "/" {
        return Ok(Vec::new());
    }

    if input.ends_with('/') {
        return Err(NacmError::new(PATH_KIND, "paths must not end with '/'"));
    }

    let mut current_module = match default_module {
        Some(module) => {
            let module = validate_symbol(PATH_KIND, "default module", module)?;
            Some(registry.resolve_default_module(&module)?.to_owned())
        }
        None => None,
    };
    let mut segments = Vec::new();

    for raw_segment in input[1..].split('/') {
        if raw_segment.is_empty() || raw_segment == "." || raw_segment == ".." {
            return Err(NacmError::new(
                PATH_KIND,
                format!("invalid path segment '{raw_segment}'"),
            ));
        }

        if allow_wildcards {
            if raw_segment == "*" {
                segments.push(ParsedPatternSegment::WildcardAny);
                continue;
            }

            if let Some(prefix) = raw_segment.strip_suffix(":*") {
                if prefix.is_empty() {
                    return Err(NacmError::new(
                        PATH_KIND,
                        "module-scoped wildcards must include a non-empty prefix",
                    ));
                }

                let module = registry.resolve_prefix(prefix)?.to_owned();
                current_module = Some(module.clone());
                segments.push(ParsedPatternSegment::WildcardModule(module));
                continue;
            }
        }

        if raw_segment.contains('*') {
            return Err(NacmError::new(
                PATH_KIND,
                format!("wildcards are not valid in segment '{raw_segment}'"),
            ));
        }

        let (module, name) = if let Some((prefix, name)) = raw_segment.split_once(':') {
            if prefix.is_empty() || name.is_empty() {
                return Err(NacmError::new(
                    PATH_KIND,
                    format!("qualified segment '{raw_segment}' must include both prefix and node"),
                ));
            }

            let module = registry.resolve_prefix(prefix)?.to_owned();
            let name = validate_symbol(PATH_KIND, "node name", name)?;
            current_module = Some(module.clone());
            (module, name)
        } else {
            let module = current_module.clone().ok_or_else(|| {
                NacmError::new(
                    PATH_KIND,
                    format!(
                        "segment '{raw_segment}' is missing a prefix and no module context is available"
                    ),
                )
            })?;
            let name = validate_symbol(PATH_KIND, "node name", raw_segment)?;
            (module, name)
        };

        segments.push(ParsedPatternSegment::Exact(QualifiedNodeName {
            module,
            name,
        }));
    }

    Ok(segments)
}

fn validate_symbol(
    kind: &'static str,
    label: &'static str,
    value: &str,
) -> Result<String, NacmError> {
    if value.is_empty() {
        return Err(NacmError::new(kind, format!("{label} cannot be empty")));
    }

    if value.trim() != value {
        return Err(NacmError::new(
            kind,
            format!("{label} must not contain leading or trailing whitespace"),
        ));
    }

    let mut chars = value.chars();
    let first = chars
        .next()
        .expect("empty strings are rejected above before first-character validation");
    if !matches!(first, 'a'..='z' | 'A'..='Z' | '_') {
        return Err(NacmError::new(
            kind,
            format!("{label} must start with an ASCII letter or '_'"),
        ));
    }

    for ch in chars {
        if !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.') {
            return Err(NacmError::new(
                kind,
                format!("{label} must contain only ASCII letters, digits, '-', '_', and '.'"),
            ));
        }
    }

    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ModuleRegistry {
        let mut registry = ModuleRegistry::new();
        registry
            .register_module("ietf-interfaces", "if")
            .expect("register interface module");
        registry
            .register_module("ietf-system", "sys")
            .expect("register system module");
        registry
    }

    #[test]
    fn parses_root_subtree_pattern() {
        let pattern = YangPathPattern::parse("/**", &registry()).expect("parse root subtree");
        assert!(pattern.is_subtree());
        assert!(pattern.segments().is_empty());
        assert_eq!(pattern.to_string(), "/**");
    }

    #[test]
    fn exact_root_pattern_is_rejected() {
        let err = YangPathPattern::parse("/", &registry()).expect_err("root exact is invalid");
        assert_eq!(err.kind(), PATH_KIND);
        assert!(err.message().contains("exact rule patterns"));
    }

    #[test]
    fn module_wildcard_matches_same_module_only() {
        let registry = registry();
        let pattern = YangPathPattern::parse("/if:interfaces/if:*", &registry)
            .expect("pattern with module wildcard");

        let allowed = YangPath::parse("/if:interfaces/if:interface", &registry).expect("path");
        let denied = YangPath::parse("/if:interfaces/sys:clock", &registry).expect("other path");

        assert!(pattern.matches(&allowed));
        assert!(!pattern.matches(&denied));
    }

    #[test]
    fn validate_symbol_rejects_digit_and_dot_led_identifiers() {
        let mut registry = ModuleRegistry::new();
        let prefix_err = registry
            .register_module("mod", "9if")
            .expect_err("digit-led prefix must be rejected");
        assert!(prefix_err
            .message()
            .contains("must start with an ASCII letter or '_'"));

        let dot_err =
            QualifiedNodeName::new(".bad", "node").expect_err("dot-led module must be rejected");
        assert!(dot_err
            .message()
            .contains("must start with an ASCII letter or '_'"));
    }

    #[test]
    fn validate_symbol_allows_trailing_hyphen_identifiers() {
        let mut registry = ModuleRegistry::new();
        registry
            .register_module("mod-", "if-")
            .expect("trailing hyphen identifiers are valid");

        let path = YangPath::parse("/if-:interfaces-/if-:leaf-", &registry)
            .expect("trailing hyphen path should parse");
        assert_eq!(path.to_string(), "/mod-:interfaces-/mod-:leaf-");
    }
}
