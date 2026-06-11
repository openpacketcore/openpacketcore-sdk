use crate::diagnostic::{Diagnostic, DiagnosticCode, YangSourceLocation};
use crate::ir::{BooleanOp, CompareOp, ConstraintExpr, PathAnchor, PathExpr, RawConstraintExpr};

/// Maximum depth allowed for constraint expression lowering.
/// This prevents stack overflow from deeply nested hostile input.
pub const MAX_CONSTRAINT_EXPR_DEPTH: u16 = 65;

/// Lower a raw constraint expression into a typed `ConstraintExpr` IR.
///
/// This function enforces:
/// - A maximum recursion depth (`MAX_CONSTRAINT_EXPR_DEPTH`).
/// - Rejection of XPath function calls until reference-engine differential
///   coverage exists for the supported profile.
/// - Rejection of unsupported XPath constructs in path segments.
pub fn lower_constraint(
    raw: &RawConstraintExpr,
    source: YangSourceLocation,
) -> Result<ConstraintExpr, Diagnostic> {
    lower_constraint_inner(raw, &source, 0)
}

fn lower_constraint_inner(
    raw: &RawConstraintExpr,
    source: &YangSourceLocation,
    depth: u16,
) -> Result<ConstraintExpr, Diagnostic> {
    if depth > MAX_CONSTRAINT_EXPR_DEPTH {
        return Err(Diagnostic::new(
            DiagnosticCode::ConstraintDepthExceeded,
            format!(
                "Constraint expression exceeds maximum depth of {}",
                MAX_CONSTRAINT_EXPR_DEPTH
            ),
            Some(source.clone()),
            Some("Simplify the expression or split it into multiple constraints"),
        ));
    }

    match raw {
        RawConstraintExpr::Literal(lit) => Ok(ConstraintExpr::Literal(lit.clone())),
        RawConstraintExpr::Path { anchor, segments } => {
            for seg in segments {
                if seg.is_empty() || seg == "/" || seg == "." || seg == ".." {
                    return Err(Diagnostic::new(
                        DiagnosticCode::InvalidPathExpression,
                        format!("Invalid path segment: '{}' (empty or invalid)", seg),
                        Some(source.clone()),
                        Some(
                            "Paths must be well-formed without empty, '.', '..', or '//' segments",
                        ),
                    ));
                }
                // Reject unsupported XPath constructs: predicates, axes,
                // attribute selectors, and wildcards. These are beyond the
                // skeleton-phase supported XPath profile per RFC-002 §9.2.
                if seg.contains(['[', ']', '@', '*']) || seg.contains("::") {
                    return Err(Diagnostic::new(
                        DiagnosticCode::InvalidPathExpression,
                        format!("Unsupported XPath construct in path segment: '{}'", seg),
                        Some(source.clone()),
                        Some(
                            "Predicates, axes, attribute selectors, and wildcards are not supported in the skeleton phase",
                        ),
                    ));
                }
            }

            let parsed_anchor = match anchor.as_str() {
                "/" => PathAnchor::Root,
                "current()" => PathAnchor::Current,
                ".." => PathAnchor::Parent,
                _ => {
                    return Err(Diagnostic::new(
                        DiagnosticCode::InvalidPathExpression,
                        format!("Unsupported or invalid path anchor: '{}'", anchor),
                        Some(source.clone()),
                        Some("Supported path anchors are: '/', 'current()', or '..'"),
                    ));
                }
            };

            if (parsed_anchor == PathAnchor::Parent || parsed_anchor == PathAnchor::Root)
                && segments.is_empty()
            {
                return Err(Diagnostic::new(
                    DiagnosticCode::InvalidPathExpression,
                    format!(
                        "Path with anchor '{}' must not have an empty segment list",
                        anchor
                    ),
                    Some(source.clone()),
                    Some("Parent and root anchors must be followed by a path segment"),
                ));
            }

            Ok(ConstraintExpr::Path(PathExpr {
                anchor: parsed_anchor,
                segments: segments.clone(),
            }))
        }
        RawConstraintExpr::Function { name, args } => {
            let _ = args;
            Err(Diagnostic::new(
                DiagnosticCode::UnsupportedXPathFunction,
                format!("Unsupported XPath function: '{}'", name),
                Some(source.clone()),
                Some(
                    "XPath function lowering is intentionally disabled in the skeleton phase until reference-engine differential tests are available",
                ),
            ))
        }
        RawConstraintExpr::Compare { op, left, right } => {
            let parsed_op = match op.as_str() {
                "==" | "=" => CompareOp::Eq,
                "!=" => CompareOp::NotEq,
                ">=" => CompareOp::Gte,
                "<=" => CompareOp::Lte,
                ">" => CompareOp::Gt,
                "<" => CompareOp::Lt,
                _ => {
                    return Err(Diagnostic::new(
                        DiagnosticCode::InvalidPathExpression,
                        format!("Unsupported comparison operator: '{}'", op),
                        Some(source.clone()),
                        None::<String>,
                    ));
                }
            };

            let lowered_left = Box::new(lower_constraint_inner(left, source, depth + 1)?);
            let lowered_right = Box::new(lower_constraint_inner(right, source, depth + 1)?);

            Ok(ConstraintExpr::Compare {
                op: parsed_op,
                left: lowered_left,
                right: lowered_right,
            })
        }
        RawConstraintExpr::Boolean { op, terms } => {
            let parsed_op = match op.as_str() {
                "and" => BooleanOp::And,
                "or" => BooleanOp::Or,
                _ => {
                    return Err(Diagnostic::new(
                        DiagnosticCode::InvalidPathExpression,
                        format!("Unsupported boolean operator: '{}'", op),
                        Some(source.clone()),
                        None::<String>,
                    ));
                }
            };

            let mut lowered_terms = Vec::new();
            for term in terms {
                lowered_terms.push(lower_constraint_inner(term, source, depth + 1)?);
            }

            Ok(ConstraintExpr::Boolean {
                op: parsed_op,
                terms: lowered_terms,
            })
        }
    }
}
