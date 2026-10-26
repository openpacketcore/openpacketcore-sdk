use crate::diagnostic::YangSourceLocation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModuleImport {
    pub name: String,
    pub revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LockedModule {
    pub name: String,
    pub revision: String,
    pub namespace: String,
    pub checksum: String,
    pub imports: Vec<ModuleImport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleLockfile {
    pub profile: String,
    pub modules: Vec<LockedModule>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SchemaModule {
    pub name: String,
    pub revision: String,
    pub namespace: String,
    pub prefix: String,
    pub source: YangSourceLocation,
    /// Raw YANG source text, if available for `<get-schema>` retrieval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_text: Option<String>,
    /// Modules imported by this module.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<ModuleImport>,
    /// Features advertised by this module.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Deviation module names applied to this module.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deviations: Vec<String>,
    /// Whether the module is implemented or import-only.
    #[serde(default)]
    pub conformance: ModuleConformance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ModuleConformance {
    #[default]
    Implement,
    Import,
}

impl Default for SchemaModule {
    fn default() -> Self {
        Self {
            name: String::new(),
            revision: String::new(),
            namespace: String::new(),
            prefix: String::new(),
            source: YangSourceLocation::default(),
            source_text: None,
            imports: Vec::new(),
            features: Vec::new(),
            deviations: Vec::new(),
            conformance: ModuleConformance::Implement,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SchemaNodeKind {
    Container,
    List,
    Leaf,
    LeafList,
    Choice,
    Case,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum TypeRef {
    Boolean,
    String,
    /// A string with retained YANG `length` and conjunctive XSD patterns.
    RestrictedString {
        /// Ordered, disjoint allowed character-count intervals.
        length: Vec<StringLengthInterval>,
        /// Every pattern must accept the value after applying its modifier.
        patterns: Vec<StringPattern>,
    },
    Enumeration {
        values: Vec<EnumValue>,
    },
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Int8,
    Int16,
    Int32,
    Int64,
    Decimal64 {
        /// Required YANG scale, in the inclusive range 1..=18.
        fraction_digits: u8,
    },
    Empty,
    IdentityRef {
        base: String,
    },
    LeafRef {
        target_path: String,
    },
    Custom {
        name: String,
    },
}

impl TypeRef {
    pub(crate) fn string_restrictions(
        &self,
    ) -> Option<(&[StringLengthInterval], &[StringPattern])> {
        match self {
            Self::RestrictedString { length, patterns } => Some((length, patterns)),
            _ => None,
        }
    }

    pub(crate) fn integer_bounds(&self) -> Option<(i128, i128)> {
        Some(match self {
            Self::Uint8 => (0, i128::from(u8::MAX)),
            Self::Uint16 => (0, i128::from(u16::MAX)),
            Self::Uint32 => (0, i128::from(u32::MAX)),
            Self::Uint64 => (0, i128::from(u64::MAX)),
            Self::Int8 => (i128::from(i8::MIN), i128::from(i8::MAX)),
            Self::Int16 => (i128::from(i16::MIN), i128::from(i16::MAX)),
            Self::Int32 => (i128::from(i32::MIN), i128::from(i32::MAX)),
            Self::Int64 => (i128::from(i64::MIN), i128::from(i64::MAX)),
            _ => return None,
        })
    }
}

/// One inclusive YANG string length interval, measured in Unicode characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StringLengthInterval {
    /// Inclusive lower character count.
    pub min: u64,
    /// Inclusive upper character count, including YANG `max` = `u64::MAX`.
    pub max: u64,
}

/// A YANG XSD pattern and its optional `invert-match` modifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StringPattern {
    /// The original XSD regular expression, preserved in the schema digest.
    pub expression: String,
    /// Whether a match must instead reject the value.
    #[serde(default)]
    pub invert_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EnumValue {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NumericRangeInterval {
    /// Inclusive bound; `i128` represents every YANG signed and unsigned integer.
    pub min: i128,
    /// Inclusive bound; `i128` represents every YANG signed and unsigned integer.
    pub max: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaNode {
    pub path: String,
    pub module: String,
    pub kind: SchemaNodeKind,
    pub config: bool,
    pub type_ref: Option<TypeRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub numeric_range: Vec<NumericRangeInterval>,
    /// Explicit YANG mandatory statement; omission is equivalent to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,
    /// Minimum list/leaf-list cardinality; omission means zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_elements: Option<u32>,
    /// Maximum list/leaf-list cardinality; omission means unbounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_elements: Option<u32>,
    pub key_leaves: Vec<String>,
    pub child_paths: Vec<String>,
    pub source: YangSourceLocation,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub presence: Option<String>,
    #[serde(default)]
    pub ordered_by: Option<String>,
    #[serde(default)]
    pub data_class: Option<String>,
    #[serde(default)]
    pub unique_constraints: Vec<Vec<String>>,
}

impl Default for SchemaNode {
    fn default() -> Self {
        Self {
            path: String::new(),
            module: String::new(),
            kind: SchemaNodeKind::Container,
            config: false,
            type_ref: None,
            numeric_range: Vec::new(),
            mandatory: None,
            min_elements: None,
            max_elements: None,
            key_leaves: Vec::new(),
            child_paths: Vec::new(),
            source: YangSourceLocation::default(),
            default: None,
            presence: None,
            ordered_by: None,
            data_class: None,
            unique_constraints: Vec::new(),
        }
    }
}

impl SchemaNode {
    pub(crate) fn validate_cardinality(&self) -> Result<(), &'static str> {
        if self.mandatory.is_some()
            && !matches!(self.kind, SchemaNodeKind::Leaf | SchemaNodeKind::Choice)
        {
            return Err("mandatory is only valid on a leaf or choice in this profile");
        }
        if self.mandatory == Some(true) && self.default.is_some() {
            return Err("a mandatory node cannot declare a default");
        }
        if (self.min_elements.is_some() || self.max_elements.is_some())
            && !matches!(self.kind, SchemaNodeKind::List | SchemaNodeKind::LeafList)
        {
            return Err("element bounds require a list or leaf-list");
        }
        if self
            .max_elements
            .is_some_and(|max| max == 0 || max < self.min_elements.unwrap_or(0))
        {
            return Err("max-elements must be positive and at least min-elements");
        }
        if self.kind == SchemaNodeKind::LeafList
            && self.min_elements.is_some_and(|min| min > 0)
            && self.default.is_some()
        {
            return Err("a leaf-list with positive min-elements cannot declare defaults");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathAnchor {
    Root,
    Current,
    Parent,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PathExpr {
    pub anchor: PathAnchor,
    pub segments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Literal {
    String(String),
    Number(i64),
    Bool(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FunctionName {
    Count,
    Current,
    Not,
    StartsWith,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: FunctionName,
    pub args: Vec<ConstraintExpr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompareOp {
    Eq,
    NotEq,
    Gte,
    Lte,
    Gt,
    Lt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BooleanOp {
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConstraintExpr {
    Path(PathExpr),
    Literal(Literal),
    Function(FunctionCall),
    Compare {
        op: CompareOp,
        left: Box<ConstraintExpr>,
        right: Box<ConstraintExpr>,
    },
    Boolean {
        op: BooleanOp,
        terms: Vec<ConstraintExpr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintBinding {
    pub target_path: String,
    pub expr: ConstraintExpr,
    pub source: YangSourceLocation,
    #[serde(default)]
    pub kind: Option<String>,
}

impl Default for ConstraintBinding {
    fn default() -> Self {
        Self {
            target_path: String::new(),
            expr: ConstraintExpr::Literal(Literal::Bool(true)),
            source: YangSourceLocation::default(),
            kind: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnsupportedFeatureKind {
    Deviation,
    Extension,
    IfFeature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedFeature {
    pub kind: UnsupportedFeatureKind,
    pub name: String,
    pub source: YangSourceLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackBudget {
    pub max_size_of_root: usize,
    pub max_size_of_any_struct: usize,
}

impl Default for StackBudget {
    fn default() -> Self {
        Self {
            max_size_of_root: 4096,
            max_size_of_any_struct: 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StackScope {
    Root,
    Nested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllocationStrategy {
    Inline,
    Boxed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StackShape {
    pub rust_type: String,
    pub yang_path: String,
    pub scope: StackScope,
    pub estimated_size: usize,
    pub allocation: AllocationStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaIr {
    pub modules: Vec<SchemaModule>,
    pub nodes: Vec<SchemaNode>,
    pub constraints: Vec<ConstraintBinding>,
    pub unsupported_features: Vec<UnsupportedFeature>,
    pub stack_budget: StackBudget,
    pub stack_shapes: Vec<StackShape>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawConstraintExpr {
    Path {
        anchor: String,
        segments: Vec<String>,
    },
    Literal(Literal),
    Function {
        name: String,
        args: Vec<RawConstraintExpr>,
    },
    Compare {
        op: String,
        left: Box<RawConstraintExpr>,
        right: Box<RawConstraintExpr>,
    },
    Boolean {
        op: String,
        terms: Vec<RawConstraintExpr>,
    },
}
