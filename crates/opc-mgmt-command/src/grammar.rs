use crate::{ArgumentName, ArgumentValue, CommandToken, HelpText, ModelError};

/// Minimum sensitivity a command argument requests.
///
/// Trusted schema/governance metadata may always raise sensitivity. Catalog
/// metadata cannot mark a value public and lower that trusted classification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ArgumentSensitivity {
    /// Inherit the trusted schema/governance classification.
    #[default]
    Inherit,
    /// Treat the value as sensitive even when schema metadata is less strict.
    Sensitive,
}

/// Typed argument value accepted by the local parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueSpec {
    /// Bounded free-form text.
    Text {
        /// Maximum UTF-8 bytes.
        max_bytes: usize,
    },
    /// `true` or `false`.
    Boolean,
    /// IPv4 or IPv6 address.
    IpAddress,
    /// IPv4 or IPv6 prefix.
    IpPrefix,
    /// Inclusive unsigned integer range.
    Unsigned {
        /// Minimum accepted value.
        min: u64,
        /// Maximum accepted value.
        max: u64,
    },
    /// Inclusive signed integer range.
    Signed {
        /// Minimum accepted value.
        min: i64,
        /// Maximum accepted value.
        max: i64,
    },
    /// Closed set of static values.
    Enumeration {
        /// Accepted values.
        values: Vec<ArgumentValue>,
    },
    /// Duration in milliseconds.
    DurationMillis {
        /// Minimum accepted duration.
        min: u64,
        /// Maximum accepted duration.
        max: u64,
    },
}

impl ValueSpec {
    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Text { max_bytes: 0 } => Err(ModelError::Zero {
                field: "text_argument_max_bytes",
            }),
            Self::Unsigned { min, max } if min > max => Err(ModelError::InvertedRange {
                field: "unsigned_argument",
            }),
            Self::Signed { min, max } if min > max => Err(ModelError::InvertedRange {
                field: "signed_argument",
            }),
            Self::DurationMillis { min, max } if min > max => Err(ModelError::InvertedRange {
                field: "duration_argument",
            }),
            Self::Enumeration { values } if values.is_empty() => Err(ModelError::Empty {
                field: "enumeration_values",
            }),
            _ => Ok(()),
        }
    }
}

/// Local/static completion declaration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CompletionSpec {
    /// No value completion.
    #[default]
    None,
    /// Offer a bounded static value set.
    Static(Vec<ArgumentValue>),
    /// Derive values from trusted generated enumeration metadata.
    SchemaEnumeration,
}

/// One node in a bounded command grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrammarNode {
    /// A visible keyword with optional interactive aliases.
    Literal {
        /// Canonical keyword.
        token: CommandToken,
        /// Additional exact aliases.
        aliases: Vec<CommandToken>,
        /// Contextual help.
        help: HelpText,
    },
    /// A typed value captured under `name`.
    Argument {
        /// Stable argument name.
        name: ArgumentName,
        /// Accepted value shape.
        value: ValueSpec,
        /// Catalog-requested minimum sensitivity.
        sensitivity: ArgumentSensitivity,
        /// Local completion declaration.
        completion: CompletionSpec,
    },
    /// An optional sequence.
    Optional(Vec<GrammarNode>),
    /// One of several alternative sequences.
    Choice(Vec<Vec<GrammarNode>>),
}

impl GrammarNode {
    /// Constructs a literal without aliases.
    #[must_use]
    pub fn literal(token: CommandToken, help: HelpText) -> Self {
        Self::Literal {
            token,
            aliases: Vec::new(),
            help,
        }
    }

    /// Constructs a literal with interactive aliases.
    #[must_use]
    pub fn literal_with_aliases(
        token: CommandToken,
        aliases: impl IntoIterator<Item = CommandToken>,
        help: HelpText,
    ) -> Self {
        Self::Literal {
            token,
            aliases: aliases.into_iter().collect(),
            help,
        }
    }

    /// Constructs a typed argument.
    #[must_use]
    pub fn argument(name: ArgumentName, value: ValueSpec) -> Self {
        Self::Argument {
            name,
            value,
            sensitivity: ArgumentSensitivity::Inherit,
            completion: CompletionSpec::None,
        }
    }

    /// Constructs a typed argument with sensitivity and completion metadata.
    #[must_use]
    pub fn argument_with(
        name: ArgumentName,
        value: ValueSpec,
        sensitivity: ArgumentSensitivity,
        completion: CompletionSpec,
    ) -> Self {
        Self::Argument {
            name,
            value,
            sensitivity,
            completion,
        }
    }

    /// Constructs an optional sequence.
    #[must_use]
    pub fn optional(nodes: impl IntoIterator<Item = GrammarNode>) -> Self {
        Self::Optional(nodes.into_iter().collect())
    }

    /// Constructs a choice from alternative sequences.
    #[must_use]
    pub fn choice<I, S>(arms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: IntoIterator<Item = GrammarNode>,
    {
        Self::Choice(
            arms.into_iter()
                .map(|arm| arm.into_iter().collect())
                .collect(),
        )
    }
}
