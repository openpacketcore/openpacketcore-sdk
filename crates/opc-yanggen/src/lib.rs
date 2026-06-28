//! OpenPacketCore YANG Projection and Codegen Engine.
//!
//! YANG-to-Rust type projection, RFC 7951 JSON serde, iterative semantic
//! constraint validation, and patch applicator.

pub mod diagnostic;
pub mod emit;
pub mod ir;
pub mod lower;
pub mod source;

pub use crate::diagnostic::{Diagnostic, DiagnosticCode, YangSourceLocation};
pub use crate::emit::{
    emit_fixture, emit_fixture_from_canonical, emit_stack_metadata, fnv1a64,
    format_constraint_expr, schema_digest, schema_digest_from_canonical, CanonicalInput,
    GenerationInput, PreScanResult, MAX_CANONICALIZATION_NODES,
};
pub use crate::ir::{
    AllocationStrategy, BooleanOp, CompareOp, ConstraintBinding, ConstraintExpr, FunctionCall,
    FunctionName, Literal, LockedModule, ModuleImport, ModuleLockfile, PathAnchor, PathExpr,
    RawConstraintExpr, SchemaIr, SchemaModule, SchemaNode, SchemaNodeKind, StackBudget, StackScope,
    StackShape, TypeRef, UnsupportedFeature, UnsupportedFeatureKind,
};
pub use crate::lower::{lower_constraint, MAX_CONSTRAINT_EXPR_DEPTH};
pub use crate::source::{
    generation_input_from_yang_sources, validate_generation_input_embedded_yang_sources,
    validate_generation_input_yang_sources, YangSource,
};

/// Flatten and validate operator input into the final [`SchemaIr`].
///
/// If any unsupported YANG features are encountered, this returns the first
/// diagnostic as an `Err`.
pub fn compile(input: &GenerationInput) -> Result<SchemaIr, Diagnostic> {
    compile_with_diagnostics(input).map_err(|errs| {
        errs.into_iter()
            .next()
            .expect("compile_with_diagnostics guarantees at least one diagnostic")
    })
}

/// Flatten and validate operator input into the final [`SchemaIr`], collecting all diagnostics.
///
/// Unlike [`compile`], which fails at the first unsupported feature, this function
/// collects and returns all unsupported feature diagnostics in a single `Vec`,
/// avoiding iterative fix-and-regenerate cycles.
pub fn compile_with_diagnostics(input: &GenerationInput) -> Result<SchemaIr, Vec<Diagnostic>> {
    if !input.unsupported_features.is_empty() {
        let mut diagnostics = Vec::with_capacity(input.unsupported_features.len());
        for feature in &input.unsupported_features {
            let kind_name = match feature.kind {
                UnsupportedFeatureKind::Deviation => "deviation",
                UnsupportedFeatureKind::Extension => "extension",
                UnsupportedFeatureKind::IfFeature => "if-feature",
            };
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::UnsupportedYangFeature,
                format!(
                    "unsupported YANG {} `{}` encountered during flattening",
                    kind_name, feature.name
                ),
                Some(feature.source.clone()),
                Some("remove the construct or add an explicit lowering strategy before generation"),
            ));
        }
        return Err(diagnostics);
    }

    Ok(SchemaIr {
        modules: input.schema_modules.clone(),
        nodes: input.nodes.clone(),
        constraints: input.constraints.clone(),
        unsupported_features: input.unsupported_features.clone(),
        stack_budget: input.stack_budget,
        stack_shapes: input.stack_shapes.clone(),
    })
}
pub mod rust;
