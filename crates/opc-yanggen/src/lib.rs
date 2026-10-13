//! OpenPacketCore YANG Projection and Codegen Engine.
//!
//! YANG-to-Rust type projection, RFC 7951 JSON serde, iterative semantic
//! constraint validation, and patch applicator.
//!
//! All eight YANG integer widths are supported, including exact ranges through
//! `u64::MAX`. Generated 64-bit integer wrappers use RFC 7951 JSON strings; smaller
//! integers use JSON numbers. Declared ranges are enforced by deserialization,
//! syntax validation, patches, gNMI Set, and NETCONF edits. Integer range metadata
//! has an additive `i128` table; existing generated `i64` tables remain valid.
//! The generator IR's [`NumericRangeInterval`] bounds are now `i128`.
//! Schema integer defaults decode decimal, octal, and hexadecimal notation
//! before range validation. Value-less list-entry patches assign and validate
//! their path keys in models using the extended scalar constructs.
//!
//! Colliding container/list type names are deterministically parent-qualified,
//! including their composite-key companions. Unique names remain unchanged.
//!
//! String `length` counts Unicode scalar values. All declared XSD `pattern`
//! restrictions apply to the whole value, including `invert-match`. Generated
//! code compiles each bounded pattern once through `opc-mgmt-schema` and checks
//! deserialization, syntax validation, patches, gNMI Set, and NETCONF edits.
//! Source quoting preserves literal strings, restricts double-quoted escapes,
//! trims physical double-quoted lines, and concatenates only quoted strings.
//!
//! Generated patch errors and leafref leaf-list validation errors omit input
//! keys and values from their messages, `Display`, and `Debug` output.

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
    AllocationStrategy, BooleanOp, CompareOp, ConstraintBinding, ConstraintExpr, EnumValue,
    FunctionCall, FunctionName, Literal, LockedModule, ModuleImport, ModuleLockfile,
    NumericRangeInterval, PathAnchor, PathExpr, RawConstraintExpr, SchemaIr, SchemaModule,
    SchemaNode, SchemaNodeKind, StackBudget, StackScope, StackShape, StringLengthInterval,
    StringPattern, TypeRef, UnsupportedFeature, UnsupportedFeatureKind,
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
