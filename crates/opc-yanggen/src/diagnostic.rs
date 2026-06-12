use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct YangSourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

impl YangSourceLocation {
    pub fn new(file: impl Into<String>, line: usize, column: usize) -> Self {
        Self {
            file: file.into(),
            line,
            column,
        }
    }
}

impl fmt::Display for YangSourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticCode {
    InvalidPathExpression,
    ConstraintDepthExceeded,
    #[serde(rename = "unsupported-xpath-function")]
    UnsupportedXPathFunction,
    UnsupportedYangFeature,
    /// Reserved for future XPath function arity validation once function
    /// lowering is enabled for the supported profile.
    ArityMismatch,
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPathExpression => write!(f, "invalid-path-expression"),
            Self::ConstraintDepthExceeded => write!(f, "constraint-depth-exceeded"),
            Self::UnsupportedXPathFunction => write!(f, "unsupported-xpath-function"),
            Self::UnsupportedYangFeature => write!(f, "unsupported-yang-feature"),
            Self::ArityMismatch => write!(f, "arity-mismatch"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub message: String,
    pub source: Option<YangSourceLocation>,
    pub help: Option<String>,
}

impl Diagnostic {
    pub fn new(
        code: DiagnosticCode,
        message: impl Into<String>,
        source: Option<YangSourceLocation>,
        help: Option<impl Into<String>>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source,
            help: help.map(Into::into),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "code: {}", self.code)?;
        writeln!(f, "message: {:?}", self.message)?;
        if let Some(ref src) = self.source {
            writeln!(f, "source: {:?}", src.to_string())?;
        }
        if let Some(ref h) = self.help {
            writeln!(f, "help: {h:?}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Diagnostic {}
