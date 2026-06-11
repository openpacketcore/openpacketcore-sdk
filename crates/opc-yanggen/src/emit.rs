use crate::ir::{
    AllocationStrategy, BooleanOp, CompareOp, ConstraintBinding, ConstraintExpr, FunctionName,
    Literal, ModuleLockfile, PathAnchor, SchemaModule, SchemaNode, SchemaNodeKind, StackBudget,
    StackScope, StackShape, TypeRef, UnsupportedFeature,
};
use crate::lower::MAX_CONSTRAINT_EXPR_DEPTH;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationInput {
    pub profile: String,
    pub lockfile: ModuleLockfile,
    pub schema_modules: Vec<SchemaModule>,
    pub nodes: Vec<SchemaNode>,
    pub constraints: Vec<ConstraintBinding>,
    pub stack_budget: StackBudget,
    pub stack_shapes: Vec<StackShape>,
    pub unsupported_features: Vec<UnsupportedFeature>,
}

/// Pre-sorted, profile-resolved collections derived from a [`GenerationInput`].
///
/// Computing the canonical form once lets both internal helpers and external
/// callers share the same clone-and-sort pass (via the public `_from_canonical`
/// entry points) when a single operation needs both digest and rendered output.
///
/// `canonicalization_skipped` is set to `true` when one or more constraint
/// expressions exceeded [`MAX_CANONICALIZATION_NODES`] during the pre-scan and
/// were returned uncanonicalized (terms not sorted). Callers can inspect this
/// field to detect the condition programmatically rather than relying on a
/// [`tracing`] subscriber.
#[derive(Debug, Clone)]
pub struct CanonicalInput {
    pub profile: CanonicalProfile,
    pub locked_modules: Vec<crate::ir::LockedModule>,
    pub schema_modules: Vec<SchemaModule>,
    pub nodes: Vec<SchemaNode>,
    pub constraints: Vec<ConstraintBinding>,
    pub stack_shapes: Vec<StackShape>,
    pub stack_budget: StackBudget,
    /// `true` if any constraint expression's canonicalization was skipped
    /// because it exceeded [`MAX_CANONICALIZATION_NODES`].
    pub canonicalization_skipped: bool,
    /// Peak pre-scan queue depth observed when `canonicalization_skipped` is `true`.
    /// When the `scan_stack.len()` budget term is present, this is bounded at
    /// O(MAX_CANONICALIZATION_NODES); without it the queue can grow to O(MAX²).
    /// `None` when all expressions were successfully canonicalized.
    #[doc(hidden)]
    pub max_canonical_scan_stack_len: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct CanonicalProfile {
    pub generation: String,
    pub lockfile_mismatch: Option<String>,
}

impl GenerationInput {
    /// Sort all collections into a deterministic canonical order.
    pub fn to_canonical(&self) -> CanonicalInput {
        let mut locked_modules = self.lockfile.modules.clone();
        locked_modules.sort_by(|a, b| {
            (&a.name, &a.revision, &a.namespace).cmp(&(&b.name, &b.revision, &b.namespace))
        });
        for m in &mut locked_modules {
            m.imports
                .sort_by(|a, b| (&a.name, &a.revision).cmp(&(&b.name, &b.revision)));
        }

        let mut schema_modules = self.schema_modules.clone();
        schema_modules.sort_by(|a, b| {
            (&a.name, &a.revision, &a.namespace).cmp(&(&b.name, &b.revision, &b.namespace))
        });

        let mut nodes = self.nodes.clone();
        for node in &mut nodes {
            node.child_paths.sort();
        }
        nodes.sort_by(|a, b| a.path.cmp(&b.path));

        let mut constraints = self.constraints.clone();
        let mut any_canonicalization_skipped = false;
        let mut max_scan_stack_len = 0;
        for constraint in &mut constraints {
            let (skipped, constraint_max_stack) =
                canonicalize_constraint_expr(&mut constraint.expr);
            if skipped {
                any_canonicalization_skipped = true;
                if constraint_max_stack > max_scan_stack_len {
                    max_scan_stack_len = constraint_max_stack;
                }
            }
        }
        // Sort constraints by semantic keys first, then source location as a
        // deterministic tiebreaker for identical must expressions. Digest
        // calculation remains source-independent because schema_digest omits
        // source locations from the hashed payload.
        constraints.sort_by(|left, right| {
            (&left.target_path, &left.expr, &left.source).cmp(&(
                &right.target_path,
                &right.expr,
                &right.source,
            ))
        });

        let mut stack_shapes = self.stack_shapes.clone();
        sort_stack_shapes(&mut stack_shapes);

        CanonicalInput {
            profile: canonical_profile(self),
            locked_modules,
            schema_modules,
            nodes,
            constraints,
            stack_shapes,
            stack_budget: self.stack_budget,
            canonicalization_skipped: any_canonicalization_skipped,
            max_canonical_scan_stack_len: if any_canonicalization_skipped {
                Some(max_scan_stack_len)
            } else {
                None
            },
        }
    }
}

fn canonical_profile(input: &GenerationInput) -> CanonicalProfile {
    if input.profile == input.lockfile.profile {
        CanonicalProfile {
            generation: input.profile.clone(),
            lockfile_mismatch: None,
        }
    } else {
        CanonicalProfile {
            generation: input.profile.clone(),
            lockfile_mismatch: Some(input.lockfile.profile.clone()),
        }
    }
}

pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3_u64);
    }
    hash
}

/// Compute a stable schema digest from flat operator input.
///
/// The digest excludes source locations and other diagnostic-only metadata so
/// that comment/whitespace changes in YANG source do not force false schema
/// migrations.
pub fn schema_digest(input: &GenerationInput) -> String {
    let canonical = input.to_canonical();
    schema_digest_from_canonical(&canonical)
}

/// Compute a stable schema digest from a pre-sorted [`CanonicalInput`].
///
/// Use this instead of [`schema_digest`] to avoid redundant clone-and-sort overhead
/// when sequencing both a digest calculation and fixture generation.
pub fn schema_digest_from_canonical(canonical: &CanonicalInput) -> String {
    let profile_json = match &canonical.profile.lockfile_mismatch {
        Some(lockfile_profile) => serde_json::json!({
            "generation": canonical.profile.generation,
            "lockfile": lockfile_profile,
        }),
        None => serde_json::json!(canonical.profile.generation),
    };

    let locked_modules_json: Vec<_> = canonical
        .locked_modules
        .iter()
        .map(|m| {
            serde_json::json!({
                "name": m.name,
                "revision": m.revision,
                "namespace": m.namespace,
                "checksum": m.checksum,
                "imports": m.imports,
            })
        })
        .collect();

    let schema_modules_json: Vec<_> = canonical
        .schema_modules
        .iter()
        .map(|m| {
            serde_json::json!({
                "name": m.name,
                "revision": m.revision,
                "namespace": m.namespace,
                "prefix": m.prefix,
            })
        })
        .collect();

    let nodes_json: Vec<_> = canonical
        .nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "path": n.path,
                "module": n.module,
                "kind": n.kind,
                "config": n.config,
                "type_ref": n.type_ref,
                "key_leaves": n.key_leaves,
                "child_paths": n.child_paths,
                "default": n.default,
                "presence": n.presence,
                "ordered_by": n.ordered_by,
                "data_class": n.data_class,
                "unique_constraints": n.unique_constraints,
            })
        })
        .collect();

    let constraints_json: Vec<_> = canonical
        .constraints
        .iter()
        .map(|c| {
            serde_json::json!({
                "target_path": c.target_path,
                "expr": c.expr,
            })
        })
        .collect();

    let canonical_json = serde_json::json!({
        "profile": profile_json,
        "locked_modules": locked_modules_json,
        "schema_modules": schema_modules_json,
        "nodes": nodes_json,
        "constraints": constraints_json,
    });

    let canonical_str = serde_json::to_string(&canonical_json)
        .expect("canonical JSON serialization of plain data types");
    let hash = fnv1a64(canonical_str.as_bytes());
    format!("fnv1a64:{:016x}", hash)
}

fn format_constraint_expr_inner(expr: &ConstraintExpr, depth: u16) -> String {
    if depth > MAX_CONSTRAINT_EXPR_DEPTH {
        return "<depth-exceeded>".to_string();
    }
    match expr {
        ConstraintExpr::Literal(lit) => match lit {
            Literal::String(s) => format!("'{}'", s),
            Literal::Number(n) => n.to_string(),
            Literal::Bool(b) => b.to_string(),
        },
        ConstraintExpr::Path(path) => {
            let anchor_str = match path.anchor {
                PathAnchor::Root => "/",
                PathAnchor::Current => "current()",
                PathAnchor::Parent => "..",
            };
            if path.segments.is_empty() {
                anchor_str.to_string()
            } else if anchor_str == "/" {
                format!("/{}", path.segments.join("/"))
            } else {
                format!("{}/{}", anchor_str, path.segments.join("/"))
            }
        }
        ConstraintExpr::Function(func) => {
            let name_str = match func.name {
                FunctionName::Count => "count",
                FunctionName::Current => "current",
                FunctionName::Not => "not",
                FunctionName::StartsWith => "starts-with",
            };
            let args_str: Vec<String> = func
                .args
                .iter()
                .map(|a| format_constraint_expr_inner(a, depth + 1))
                .collect();
            format!("{}({})", name_str, args_str.join(", "))
        }
        ConstraintExpr::Compare { op, left, right } => {
            let op_str = match op {
                CompareOp::Eq => "=",
                CompareOp::NotEq => "!=",
                CompareOp::Gte => ">=",
                CompareOp::Lte => "<=",
                CompareOp::Gt => ">",
                CompareOp::Lt => "<",
            };
            format!(
                "{} {} {}",
                format_constraint_expr_inner(left, depth + 1),
                op_str,
                format_constraint_expr_inner(right, depth + 1)
            )
        }
        ConstraintExpr::Boolean { op, terms } => {
            let op_str = match op {
                BooleanOp::And => "and",
                BooleanOp::Or => "or",
            };
            let terms_str: Vec<String> = terms
                .iter()
                .map(|t| format_constraint_expr_inner(t, depth + 1))
                .collect();
            format!("boolean({}, {})", op_str, terms_str.join(", "))
        }
    }
}

pub fn format_constraint_expr(expr: &ConstraintExpr) -> String {
    format_constraint_expr_inner(expr, 0)
}

/// Result of the canonicalization pre-scan pass.
///
/// Returned by `canonicalize_constraint_expr_owned` so callers can inspect
/// how the pre-scan behaved (e.g. which budget check fired, how large the
/// work queue grew) without depending on a [`tracing`] subscriber.
#[derive(Debug, Clone)]
pub struct PreScanResult {
    /// The constraint expression (canonicalized if budget was not exceeded,
    /// otherwise the original input expression).
    pub expr: ConstraintExpr,
    /// `true` if the pre-scan budget was exceeded and canonicalization was skipped.
    pub skipped: bool,
    /// Maximum number of items present in the pre-scan work queue at any point.
    /// Useful for regression testing: the `scan_stack.len()` budget term in
    /// `Boolean`/`Function`/`Compare` pre-checks is what keeps this bounded at
    /// O(MAX_CANONICALIZATION_NODES) rather than growing to O(MAX²).
    pub max_scan_stack_len: usize,
}

/// Maximum number of constraint-expression nodes the canonicalization pre-scan will accept.
/// Derived from MAX_CONSTRAINT_EXPR_DEPTH (65) × conservative fanout (~15), providing
/// headroom for wide Boolean/Function nodes while bounding heap usage.
///
/// Expressions exceeding this limit are returned uncanonicalized (terms unsorted) with a
/// [`tracing::warn!`] log rather than producing an error. Callers can detect this condition
/// by inspecting [`CanonicalInput::canonicalization_skipped`], which is set to `true` whenever
/// any constraint expression is returned uncanonicalized due to this limit.
pub const MAX_CANONICALIZATION_NODES: usize = 1000;

/// Canonicalize a constraint expression in-place, returning `(skipped, max_scan_stack_len)`.
/// `skipped` is `true` if the pre-scan budget was exceeded and the expression was returned
/// uncanonicalized. `max_scan_stack_len` is the peak pre-scan queue depth observed.
fn canonicalize_constraint_expr(expr: &mut ConstraintExpr) -> (bool, usize) {
    let dummy = ConstraintExpr::Literal(Literal::Bool(false));
    let owned = std::mem::replace(expr, dummy);
    let result = canonicalize_constraint_expr_owned(owned);
    *expr = result.expr;
    (result.skipped, result.max_scan_stack_len)
}

fn canonicalize_constraint_expr_owned(expr: ConstraintExpr) -> PreScanResult {
    enum Frame {
        Visit(ConstraintExpr),
        RebuildFunction {
            name: FunctionName,
            arg_count: usize,
        },
        RebuildCompare {
            op: CompareOp,
        },
        RebuildBoolean {
            op: BooleanOp,
            term_count: usize,
        },
    }

    // 1. Iterative borrowed pre-scan to check the node budget without cloning or stack overflow risk.
    // Checks include scan_stack.len() (already-queued items) so the work stack itself is bounded at O(MAX).
    let mut scan_stack = vec![&expr];
    let mut node_count = 0;
    let mut max_scan_stack_len = 0;
    macro_rules! budget_exceeded {
        () => {{
            tracing::warn!(
                "Canonicalization budget of {} nodes exceeded. Returning uncanonicalized expression.",
                MAX_CANONICALIZATION_NODES
            );
            return PreScanResult {
                expr,
                skipped: true,
                max_scan_stack_len,
            };
        }};
    }
    while let Some(current) = scan_stack.pop() {
        // Track peak queue depth for regression testing.
        if scan_stack.len() > max_scan_stack_len {
            max_scan_stack_len = scan_stack.len();
        }
        node_count += 1;
        if node_count > MAX_CANONICALIZATION_NODES {
            budget_exceeded!();
        }
        match current {
            ConstraintExpr::Path(_) | ConstraintExpr::Literal(_) => {}
            ConstraintExpr::Function(func) => {
                // Check: already-counted + already-queued + about-to-enqueue <= MAX
                if node_count + scan_stack.len() + func.args.len() > MAX_CANONICALIZATION_NODES {
                    budget_exceeded!();
                }
                for arg in &func.args {
                    scan_stack.push(arg);
                }
            }
            ConstraintExpr::Compare { left, right, .. } => {
                if node_count + scan_stack.len() + 2 > MAX_CANONICALIZATION_NODES {
                    budget_exceeded!();
                }
                scan_stack.push(left);
                scan_stack.push(right);
            }
            ConstraintExpr::Boolean { terms, .. } => {
                if node_count + scan_stack.len() + terms.len() > MAX_CANONICALIZATION_NODES {
                    budget_exceeded!();
                }
                for term in terms {
                    scan_stack.push(term);
                }
            }
        }
    }

    // 2. Since the pre-scan succeeded and the expression is guaranteed to be small (<= 1000 nodes),
    // we can proceed with the iterative canonicalization safely without pre-cloning or transient spikes.
    let mut frames = vec![Frame::Visit(expr)];
    let mut values = Vec::new();

    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Visit(ConstraintExpr::Path(path)) => values.push(ConstraintExpr::Path(path)),
            Frame::Visit(ConstraintExpr::Literal(lit)) => {
                values.push(ConstraintExpr::Literal(lit));
            }
            Frame::Visit(ConstraintExpr::Function(func)) => {
                let arg_count = func.args.len();
                frames.push(Frame::RebuildFunction {
                    name: func.name,
                    arg_count,
                });
                for arg in func.args.into_iter().rev() {
                    frames.push(Frame::Visit(arg));
                }
            }
            Frame::Visit(ConstraintExpr::Compare { op, left, right }) => {
                frames.push(Frame::RebuildCompare { op });
                frames.push(Frame::Visit(*right));
                frames.push(Frame::Visit(*left));
            }
            Frame::Visit(ConstraintExpr::Boolean { op, terms }) => {
                let term_count = terms.len();
                frames.push(Frame::RebuildBoolean { op, term_count });
                for term in terms.into_iter().rev() {
                    frames.push(Frame::Visit(term));
                }
            }
            Frame::RebuildFunction { name, arg_count } => {
                let split = values.len() - arg_count;
                let args = values.split_off(split);
                values.push(ConstraintExpr::Function(crate::ir::FunctionCall {
                    name,
                    args,
                }));
            }
            Frame::RebuildCompare { op } => {
                let split = values.len() - 2;
                let mut operands = values.split_off(split).into_iter();
                let left = operands
                    .next()
                    .expect("left operand must exist after compare traversal");
                let right = operands
                    .next()
                    .expect("right operand must exist after compare traversal");
                values.push(ConstraintExpr::Compare {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                });
            }
            Frame::RebuildBoolean { op, term_count } => {
                let split = values.len() - term_count;
                let mut terms = values.split_off(split);
                terms.sort();
                values.push(ConstraintExpr::Boolean { op, terms });
            }
        }
    }

    PreScanResult {
        expr: values
            .pop()
            .expect("constraint expression canonicalization must yield one value"),
        skipped: false,
        max_scan_stack_len,
    }
}

fn sort_stack_shapes(shapes: &mut [StackShape]) {
    shapes.sort();
}

fn format_stack_shape_line(shape: &StackShape, budget: &StackBudget) -> String {
    let (scope_str, budget_val) = match shape.scope {
        StackScope::Root => ("root", budget.max_size_of_root),
        StackScope::Nested => ("nested", budget.max_size_of_any_struct),
    };

    let alloc_str = match shape.allocation {
        AllocationStrategy::Inline => "inline",
        AllocationStrategy::Boxed => "boxed",
    };

    let status_str = match (
        shape.scope,
        shape.allocation,
        shape.estimated_size > budget_val,
    ) {
        (StackScope::Root, _, true) => "exceeding-budget",
        (StackScope::Root, _, false) => "within-budget",
        (StackScope::Nested, AllocationStrategy::Boxed, _) => "boxed-to-fit",
        (StackScope::Nested, AllocationStrategy::Inline, true) => "exceeding-budget",
        (StackScope::Nested, AllocationStrategy::Inline, false) => "within-budget",
    };

    format!(
        "  {} {} path={} estimated={} budget={} allocation={} status={}\n",
        scope_str,
        shape.rust_type,
        shape.yang_path,
        shape.estimated_size,
        budget_val,
        alloc_str,
        status_str
    )
}

pub fn emit_stack_metadata(shapes: &[StackShape], budget: &StackBudget) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "stack-budget root={} nested={}\n",
        budget.max_size_of_root, budget.max_size_of_any_struct
    ));

    let mut sorted_shapes = shapes.to_vec();
    sort_stack_shapes(&mut sorted_shapes);

    for shape in sorted_shapes {
        out.push_str(&format_stack_shape_line(&shape, budget));
    }
    out
}

/// Emit a deterministic schema fixture string from flat operator input.
pub fn emit_fixture(input: &GenerationInput) -> String {
    let canonical = input.to_canonical();
    emit_fixture_from_canonical(&canonical)
}

/// Emit a deterministic schema fixture string from a pre-sorted [`CanonicalInput`].
///
/// Use this instead of [`emit_fixture`] to avoid redundant clone-and-sort overhead
/// when sequencing both a digest calculation and fixture generation.
pub fn emit_fixture_from_canonical(canonical: &CanonicalInput) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "generator-version {}\n",
        env!("CARGO_PKG_VERSION")
    ));
    out.push_str(&format!("profile {}", canonical.profile.generation));
    if let Some(lockfile_profile) = &canonical.profile.lockfile_mismatch {
        out.push_str(&format!(
            " lockfile-profile={} mismatch=true",
            lockfile_profile
        ));
    }
    out.push('\n');
    out.push_str(&format!(
        "schema-digest {}\n",
        schema_digest_from_canonical(canonical)
    ));
    out.push_str("lockfile\n");

    for m in &canonical.locked_modules {
        let imports_str: Vec<String> = m
            .imports
            .iter()
            .map(|imp| format!("{}@{}", imp.name, imp.revision))
            .collect();
        out.push_str(&format!(
            "  module {}@{} namespace={} checksum={} imports=[{}]\n",
            m.name,
            m.revision,
            m.namespace,
            m.checksum,
            imports_str.join(", ")
        ));
    }

    out.push_str("schema-modules\n");
    for m in &canonical.schema_modules {
        out.push_str(&format!(
            "  module {} prefix={} revision={} namespace={} source={}\n",
            m.name, m.prefix, m.revision, m.namespace, m.source
        ));
    }

    out.push_str("schema-nodes\n");
    for node in &canonical.nodes {
        let kind_str = match node.kind {
            SchemaNodeKind::Container => "container",
            SchemaNodeKind::List => "list",
            SchemaNodeKind::Leaf => "leaf",
            SchemaNodeKind::LeafList => "leaflist",
            SchemaNodeKind::Choice => "choice",
            SchemaNodeKind::Case => "case",
        };

        let type_str = match &node.type_ref {
            None => "none".to_string(),
            Some(TypeRef::Boolean) => "boolean".to_string(),
            Some(TypeRef::String) => "string".to_string(),
            Some(TypeRef::Uint16) => "uint16".to_string(),
            Some(TypeRef::Uint32) => "uint32".to_string(),
            Some(TypeRef::Int64) => "int64".to_string(),
            Some(TypeRef::Decimal64) => "decimal64".to_string(),
            Some(TypeRef::Empty) => "empty".to_string(),
            Some(TypeRef::IdentityRef { base }) => format!("identityref(base={})", base),
            Some(TypeRef::LeafRef { target_path }) => format!("leafref(target={})", target_path),
            Some(TypeRef::Custom { name }) => format!("custom(name={})", name),
        };

        let mut extra = String::new();
        if let Some(ref d) = node.default {
            extra.push_str(&format!(" default={}", d));
        }
        if let Some(ref p) = node.presence {
            extra.push_str(&format!(" presence={}", p));
        }
        if let Some(ref o) = node.ordered_by {
            extra.push_str(&format!(" ordered-by={}", o));
        }
        if let Some(ref dc) = node.data_class {
            extra.push_str(&format!(" data-class={}", dc));
        }
        if !node.unique_constraints.is_empty() {
            let unique_strs: Vec<String> = node
                .unique_constraints
                .iter()
                .map(|u| format!("[{}]", u.join(", ")))
                .collect();
            extra.push_str(&format!(" unique=[{}]", unique_strs.join(", ")));
        }

        out.push_str(&format!(
            "  node path={} module={} kind={} config={} type={} keys=[{}] children=[{}]{} source={}\n",
            node.path,
            node.module,
            kind_str,
            node.config,
            type_str,
            node.key_leaves.join(", "),
            node.child_paths.join(", "),
            extra,
            node.source
        ));
    }

    out.push_str("constraints\n");
    for c in &canonical.constraints {
        out.push_str(&format!(
            "  must target={} source={} expr={}\n",
            c.target_path,
            c.source,
            format_constraint_expr(&c.expr)
        ));
    }

    out.push_str("stack-shapes\n");
    for shape in &canonical.stack_shapes {
        out.push_str(&format_stack_shape_line(shape, &canonical.stack_budget));
    }

    out
}
