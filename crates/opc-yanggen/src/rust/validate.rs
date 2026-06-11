use super::{clean_segment, last_segment, to_pascal_case, to_snake_case, RustGenerationError};
use crate::emit::{format_constraint_expr, CanonicalInput};
use crate::ir::{
    BooleanOp, CompareOp, ConstraintBinding, ConstraintExpr, FunctionName, Literal, PathAnchor,
    PathExpr, SchemaNode, SchemaNodeKind, TypeRef,
};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let root = input
        .nodes
        .iter()
        .find(|node| {
            let trimmed = node.path.trim_start_matches('/');
            !trimmed.is_empty() && !trimmed.contains('/')
        })
        .expect("Rust generation validates one root node before emitting validation");
    let root_name = clean_segment(last_segment(&root.path));
    let root_type = format_ident!("{}", to_pascal_case(root_name));

    let mut validation_checks = TokenStream::new();

    // 1. Generate must/when constraints
    for constraint in &input.constraints {
        let block = generate_constraint_check(constraint, input)?;
        validation_checks.extend(block);
    }

    // 2. Generate unique constraints
    for node in &input.nodes {
        if node.kind == SchemaNodeKind::List && !node.unique_constraints.is_empty() {
            let block = generate_unique_check(node, input)?;
            validation_checks.extend(block);
        }
    }

    // 3. Generate leafref constraints
    for node in &input.nodes {
        if let Some(TypeRef::LeafRef { target_path }) = &node.type_ref {
            let block = generate_leafref_check(node, target_path, input)?;
            validation_checks.extend(block);
        }
    }

    let tokens = quote! {
        use opc_config_model::{ValidationError, ValidationContext};
        use super::types::*;

        pub fn validate_syntax(_root: &#root_type) -> Result<(), ValidationError> {
            Ok(())
        }

        pub fn validate_semantics(
            _root: &#root_type,
            _ctx: &ValidationContext<#root_type>,
        ) -> Result<(), ValidationError> {
            #validation_checks
            Ok(())
        }
    };

    Ok(tokens.to_string())
}

fn generate_path_access(
    resolved_node: &SchemaNode,
    context_path: &str,
    input: &CanonicalInput,
) -> TokenStream {
    if resolved_node.path.starts_with(context_path) && resolved_node.path != context_path {
        let suffix = &resolved_node.path[context_path.len()..];
        let segments: Vec<&str> = suffix.split('/').filter(|s| !s.is_empty()).collect();
        let mut access = quote! { current_ctx };
        let mut cur_path = context_path.to_string();
        for seg in segments {
            cur_path.push('/');
            cur_path.push_str(seg);
            let seg_node = input.nodes.iter().find(|n| n.path == cur_path).unwrap();
            let field_ident = format_ident!("{}", to_snake_case(clean_segment(seg)));
            let is_sensitive = super::types::is_sensitive_node(seg_node);
            if is_sensitive {
                access = quote! { #access.#field_ident.get() };
            } else {
                access = quote! { #access.#field_ident };
            }
            if seg_node.kind == SchemaNodeKind::Container {
                access = quote! { #access.as_ref().unwrap() };
            }
        }
        access
    } else if resolved_node.path == context_path {
        quote! { current_ctx }
    } else {
        let root = input
            .nodes
            .iter()
            .find(|n| {
                let trimmed = n.path.trim_start_matches('/');
                !trimmed.is_empty() && !trimmed.contains('/')
            })
            .unwrap();
        let root_path = &root.path;
        if resolved_node.path == *root_path {
            quote! { _root }
        } else if resolved_node.path.starts_with(root_path) {
            let suffix = &resolved_node.path[root_path.len()..];
            let segments: Vec<&str> = suffix.split('/').filter(|s| !s.is_empty()).collect();
            let mut access = quote! { _root };
            let mut cur_path = root_path.clone();
            for seg in segments {
                cur_path.push('/');
                cur_path.push_str(seg);
                let seg_node = input.nodes.iter().find(|n| n.path == cur_path).unwrap();
                let field_ident = format_ident!("{}", to_snake_case(clean_segment(seg)));
                let is_sensitive = super::types::is_sensitive_node(seg_node);
                if is_sensitive {
                    access = quote! { #access.#field_ident.get() };
                } else {
                    access = quote! { #access.#field_ident };
                }
                if seg_node.kind == SchemaNodeKind::Container {
                    access = quote! { #access.as_ref().unwrap() };
                }
            }
            access
        } else {
            quote! { _root }
        }
    }
}

fn generate_constraint_check(
    constraint: &ConstraintBinding,
    input: &CanonicalInput,
) -> Result<TokenStream, RustGenerationError> {
    let target_node = input
        .nodes
        .iter()
        .find(|n| n.path == constraint.target_path)
        .ok_or_else(|| {
            RustGenerationError::new(format!(
                "constraint target node '{}' not found",
                constraint.target_path
            ))
        })?;

    let context_path = match target_node.kind {
        SchemaNodeKind::Leaf | SchemaNodeKind::LeafList => constraint
            .target_path
            .rsplit_once('/')
            .map(|(p, _)| p)
            .unwrap_or("")
            .to_string(),
        _ => constraint.target_path.clone(),
    };

    let expr_ts = evaluate_expr(
        &constraint.expr,
        "current_ctx",
        &constraint.target_path,
        &context_path,
        input,
        0,
    )?;
    let expr_str = format_constraint_expr(&constraint.expr);

    let is_when = constraint.kind.as_deref() == Some("when");
    let target_field_name = clean_segment(last_segment(&target_node.path));
    let target_field_ident = format_ident!("{}", to_snake_case(target_field_name));
    let is_sensitive = super::types::is_sensitive_node(target_node);
    let field_access = if is_sensitive {
        quote! { current_ctx.#target_field_ident.get() }
    } else {
        quote! { current_ctx.#target_field_ident }
    };
    let field_is_present = match target_node.kind {
        SchemaNodeKind::Leaf => {
            if target_node.config {
                quote! { #field_access.as_option().is_some() }
            } else {
                quote! { #field_access.is_some() }
            }
        }
        SchemaNodeKind::Container | SchemaNodeKind::List | SchemaNodeKind::LeafList => {
            quote! { true }
        }
        _ => quote! { false },
    };

    let check_body_logic = if is_when {
        quote! {
            if !(#expr_ts) {
                if #field_is_present {
                    return Err(ValidationError::semantics(
                        format!("Field must be absent when condition is unsatisfied: {}", #expr_str),
                    ));
                }
            }
        }
    } else {
        quote! {
            if #field_is_present {
                if !(#expr_ts) {
                    return Err(ValidationError::semantics(
                        format!("Constraint failed: {}", #expr_str),
                    ));
                }
            }
        }
    };

    // Build traversal loops
    let mut check_body = check_body_logic;

    let ancestors = get_ancestors_along_path(&context_path, input)?;
    let mut current_var = "_root".to_string();
    let mut wrap_closures = Vec::new();

    for ancestor in ancestors {
        let field_name = clean_segment(last_segment(&ancestor.path));
        let field_ident = format_ident!("{}", to_snake_case(field_name));
        let next_var = to_snake_case(field_name);
        let current_ident = format_ident!("{}", current_var);
        let next_ident = format_ident!("{}", next_var);

        match ancestor.kind {
            SchemaNodeKind::Container => {
                wrap_closures.push(Box::new(move |body: TokenStream| {
                    quote! {
                        if let Some(ref #next_ident) = #current_ident.#field_ident {
                            #body
                        }
                    }
                })
                    as Box<dyn FnOnce(TokenStream) -> TokenStream>);
                current_var = next_var;
            }
            SchemaNodeKind::List => {
                wrap_closures.push(Box::new(move |body: TokenStream| {
                    if ancestor.key_leaves.is_empty() {
                        quote! {
                            for #next_ident in &#current_ident.#field_ident {
                                #body
                            }
                        }
                    } else {
                        quote! {
                            for (_, #next_ident) in &#current_ident.#field_ident {
                                #body
                            }
                        }
                    }
                })
                    as Box<dyn FnOnce(TokenStream) -> TokenStream>);
                current_var = next_var;
            }
            _ => {}
        }
    }

    // Assign current_ctx
    let current_ident = format_ident!("{}", current_var);
    check_body = quote! {
        #[allow(unused_variables)]
        let current_ctx = &#current_ident;
        #check_body
    };

    // Nest the checks
    for wrap in wrap_closures.into_iter().rev() {
        check_body = wrap(check_body);
    }

    Ok(check_body)
}

fn generate_unique_check(
    list_node: &SchemaNode,
    input: &CanonicalInput,
) -> Result<TokenStream, RustGenerationError> {
    let mut checks = TokenStream::new();
    let parent_path = list_node
        .path
        .rsplit_once('/')
        .map(|(p, _)| p)
        .unwrap_or("")
        .to_string();
    let ancestors = get_ancestors_along_path(&parent_path, input)?;

    for (idx, unique_leaves) in list_node.unique_constraints.iter().enumerate() {
        let set_ident = format_ident!("unique_set_{}", idx);
        let mut tuple_exprs = Vec::new();
        let mut presence_checks = Vec::new();

        for unique_leaf in unique_leaves {
            let cleaned = clean_segment(unique_leaf);
            let field_ident = format_ident!("{}", to_snake_case(cleaned));
            let mut unique_node = None;
            for child_path in &list_node.child_paths {
                if let Some(child) = input.nodes.iter().find(|n| &n.path == child_path) {
                    if clean_segment(last_segment(&child.path)) == cleaned {
                        unique_node = Some(child);
                        break;
                    }
                }
            }
            let child = unique_node.ok_or_else(|| {
                RustGenerationError::new(format!(
                    "unique field '{}' not found in child paths",
                    cleaned
                ))
            })?;

            let is_sensitive = super::types::is_sensitive_node(child);
            let access = if is_sensitive {
                quote! { entry.#field_ident.get() }
            } else {
                quote! { entry.#field_ident }
            };

            if child.config {
                presence_checks.push(quote! { #access.as_option().is_some() });
                tuple_exprs.push(quote! { #access.as_option().cloned() });
            } else {
                presence_checks.push(quote! { #access.is_some() });
                tuple_exprs.push(quote! { #access.clone() });
            }
        }

        let loop_body = quote! {
            if #(#presence_checks)&&* {
                let key = ( #(#tuple_exprs),* , );
                if !#set_ident.insert(key) {
                    return Err(ValidationError::semantics("duplicate entry found in list unique constraint"));
                }
            }
        };

        // Traverse to list
        let list_field = clean_segment(last_segment(&list_node.path));
        let list_ident = format_ident!("{}", to_snake_case(list_field));

        let mut current_var = "_root".to_string();
        let mut wrap_closures = Vec::new();

        for ancestor in ancestors.iter() {
            let field_name = clean_segment(last_segment(&ancestor.path));
            let field_ident = format_ident!("{}", to_snake_case(field_name));
            let next_var = to_snake_case(field_name);
            let current_ident = format_ident!("{}", current_var);
            let next_ident = format_ident!("{}", next_var);

            match ancestor.kind {
                SchemaNodeKind::Container => {
                    wrap_closures.push(Box::new(move |body: TokenStream| {
                        quote! {
                            if let Some(ref #next_ident) = #current_ident.#field_ident {
                                #body
                            }
                        }
                    })
                        as Box<dyn FnOnce(TokenStream) -> TokenStream>);
                    current_var = next_var;
                }
                SchemaNodeKind::List => {
                    wrap_closures.push(Box::new(move |body: TokenStream| {
                        if ancestor.key_leaves.is_empty() {
                            quote! {
                                for #next_ident in &#current_ident.#field_ident {
                                    #body
                                }
                            }
                        } else {
                            quote! {
                                for (_, #next_ident) in &#current_ident.#field_ident {
                                    #body
                                }
                            }
                        }
                    })
                        as Box<dyn FnOnce(TokenStream) -> TokenStream>);
                    current_var = next_var;
                }
                _ => {}
            }
        }

        let current_ident = format_ident!("{}", current_var);
        let list_loop = if list_node.key_leaves.is_empty() {
            quote! {
                let mut #set_ident = std::collections::HashSet::new();
                for entry in &#current_ident.#list_ident {
                    #loop_body
                }
            }
        } else {
            quote! {
                let mut #set_ident = std::collections::HashSet::new();
                for (_, entry) in &#current_ident.#list_ident {
                    #loop_body
                }
            }
        };

        let mut block = list_loop;
        for wrap in wrap_closures.into_iter().rev() {
            block = wrap(block);
        }
        checks.extend(block);
    }

    Ok(checks)
}

fn generate_leafref_check(
    leaf_node: &SchemaNode,
    target_path: &str,
    input: &CanonicalInput,
) -> Result<TokenStream, RustGenerationError> {
    // Collect target values into set
    let target_parent_path = target_path
        .rsplit_once('/')
        .map(|(p, _)| p)
        .unwrap_or("")
        .to_string();
    let target_ancestors = get_ancestors_along_path(&target_parent_path, input)?;
    let target_field = clean_segment(last_segment(target_path));
    let target_field_ident = format_ident!("{}", to_snake_case(target_field));

    let set_ident = format_ident!(
        "leafref_set_{}",
        to_snake_case(clean_segment(last_segment(&leaf_node.path)))
    );

    // Check if target_node config determines whether it is LeafPresence or Option
    let target_node = input
        .nodes
        .iter()
        .find(|n| n.path == target_path)
        .ok_or_else(|| {
            RustGenerationError::new(format!("leafref target node '{}' not found", target_path))
        })?;

    let is_target_sensitive = super::types::is_sensitive_node(target_node);
    let target_access = if is_target_sensitive {
        quote! { entry.#target_field_ident.get() }
    } else {
        quote! { entry.#target_field_ident }
    };

    let insert_expr = if target_node.config {
        quote! {
            if let Some(ref v) = #target_access.as_option() {
                #set_ident.insert((*v).clone());
            }
        }
    } else {
        quote! {
            if let Some(ref v) = #target_access {
                #set_ident.insert(v.clone());
            }
        }
    };

    let mut current_var = "_root".to_string();
    let mut wrap_closures = Vec::new();

    for ancestor in target_ancestors {
        let field_name = clean_segment(last_segment(&ancestor.path));
        let field_ident = format_ident!("{}", to_snake_case(field_name));
        let next_var = format!("t_{}", to_snake_case(field_name));
        let current_ident = format_ident!("{}", current_var);
        let next_ident = format_ident!("{}", next_var);

        match ancestor.kind {
            SchemaNodeKind::Container => {
                wrap_closures.push(Box::new(move |body: TokenStream| {
                    quote! {
                        if let Some(ref #next_ident) = #current_ident.#field_ident {
                            #body
                        }
                    }
                })
                    as Box<dyn FnOnce(TokenStream) -> TokenStream>);
                current_var = next_var;
            }
            SchemaNodeKind::List => {
                wrap_closures.push(Box::new(move |body: TokenStream| {
                    if ancestor.key_leaves.is_empty() {
                        quote! {
                            for #next_ident in &#current_ident.#field_ident {
                                #body
                            }
                        }
                    } else {
                        quote! {
                            for (_, #next_ident) in &#current_ident.#field_ident {
                                #body
                            }
                        }
                    }
                })
                    as Box<dyn FnOnce(TokenStream) -> TokenStream>);
                current_var = next_var;
            }
            _ => {}
        }
    }

    let current_ident = format_ident!("{}", current_var);
    let mut collect_body = quote! {
        let entry = &#current_ident;
        #insert_expr
    };
    for wrap in wrap_closures.into_iter().rev() {
        collect_body = wrap(collect_body);
    }

    // Now validate the current leaf node value exists in the set
    let leaf_parent_path = leaf_node
        .path
        .rsplit_once('/')
        .map(|(p, _)| p)
        .unwrap_or("")
        .to_string();
    let leaf_ancestors = get_ancestors_along_path(&leaf_parent_path, input)?;
    let leaf_field = clean_segment(last_segment(&leaf_node.path));
    let leaf_field_ident = format_ident!("{}", to_snake_case(leaf_field));

    let is_leaf_sensitive = super::types::is_sensitive_node(leaf_node);
    let leaf_access = if is_leaf_sensitive {
        quote! { entry.#leaf_field_ident.get() }
    } else {
        quote! { entry.#leaf_field_ident }
    };

    let validate_expr = if leaf_node.config {
        quote! {
            if let Some(ref v) = #leaf_access.as_option() {
                if !#set_ident.contains(*v) {
                    return Err(ValidationError::semantics(format!("Value not found in target path {}", #target_path)));
                }
            }
        }
    } else {
        quote! {
            if let Some(ref v) = #leaf_access {
                if !#set_ident.contains(v) {
                    return Err(ValidationError::semantics(format!("Value not found in target path {}", #target_path)));
                }
            }
        }
    };

    let mut current_var_val = "_root".to_string();
    let mut wrap_closures_val = Vec::new();

    for ancestor in leaf_ancestors {
        let field_name = clean_segment(last_segment(&ancestor.path));
        let field_ident = format_ident!("{}", to_snake_case(field_name));
        let next_var = format!("v_{}", to_snake_case(field_name));
        let current_ident = format_ident!("{}", current_var_val);
        let next_ident = format_ident!("{}", next_var);

        match ancestor.kind {
            SchemaNodeKind::Container => {
                wrap_closures_val.push(Box::new(move |body: TokenStream| {
                    quote! {
                        if let Some(ref #next_ident) = #current_ident.#field_ident {
                            #body
                        }
                    }
                })
                    as Box<dyn FnOnce(TokenStream) -> TokenStream>);
                current_var_val = next_var;
            }
            SchemaNodeKind::List => {
                wrap_closures_val.push(Box::new(move |body: TokenStream| {
                    if ancestor.key_leaves.is_empty() {
                        quote! {
                            for #next_ident in &#current_ident.#field_ident {
                                #body
                            }
                        }
                    } else {
                        quote! {
                            for (_, #next_ident) in &#current_ident.#field_ident {
                                #body
                            }
                        }
                    }
                })
                    as Box<dyn FnOnce(TokenStream) -> TokenStream>);
                current_var_val = next_var;
            }
            _ => {}
        }
    }

    let current_ident_val = format_ident!("{}", current_var_val);
    let mut check_body = quote! {
        let entry = &#current_ident_val;
        #validate_expr
    };
    for wrap in wrap_closures_val.into_iter().rev() {
        check_body = wrap(check_body);
    }

    Ok(quote! {
        let mut #set_ident = std::collections::HashSet::new();
        #collect_body
        #check_body
    })
}

fn get_ancestors_along_path(
    path: &str,
    input: &CanonicalInput,
) -> Result<Vec<SchemaNode>, RustGenerationError> {
    let mut ancestors = Vec::new();
    let mut current_path = String::new();
    for seg in path.split('/') {
        if seg.is_empty() {
            continue;
        }
        current_path.push('/');
        current_path.push_str(seg);
        if let Some(node) = input.nodes.iter().find(|n| n.path == current_path) {
            if !is_root_path(&node.path) {
                ancestors.push(node.clone());
            }
        }
    }
    Ok(ancestors)
}

fn is_root_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    !trimmed.is_empty() && !trimmed.contains('/')
}

fn find_node_by_path_segments(
    start_node: &SchemaNode,
    segments: &[String],
    nodes: &[SchemaNode],
) -> Result<SchemaNode, String> {
    let mut current = start_node.clone();
    for seg in segments {
        let cleaned_seg = clean_segment(seg);
        let mut found = None;
        for child_path in &current.child_paths {
            if let Some(child) = nodes.iter().find(|n| &n.path == child_path) {
                let child_name = clean_segment(last_segment(&child.path));
                if child_name == cleaned_seg {
                    found = Some(child.clone());
                    break;
                }
            }
        }
        if let Some(f) = found {
            current = f;
        } else {
            return Err(format!(
                "child segment '{}' not found under '{}'",
                cleaned_seg, current.path
            ));
        }
    }
    Ok(current)
}

fn resolve_path_node(
    target_path: &str,
    path: &PathExpr,
    nodes: &[SchemaNode],
) -> Result<SchemaNode, String> {
    let target_node = nodes
        .iter()
        .find(|n| n.path == target_path)
        .ok_or_else(|| format!("target node '{}' not found", target_path))?;
    match path.anchor {
        PathAnchor::Current => find_node_by_path_segments(target_node, &path.segments, nodes),
        PathAnchor::Root => {
            let root_node = nodes
                .iter()
                .find(|n| {
                    let trimmed = n.path.trim_start_matches('/');
                    !trimmed.is_empty() && !trimmed.contains('/')
                })
                .ok_or_else(|| "root node not found".to_string())?;

            if !path.segments.is_empty()
                && clean_segment(&path.segments[0]) == clean_segment(last_segment(&root_node.path))
            {
                find_node_by_path_segments(root_node, &path.segments[1..], nodes)
            } else {
                find_node_by_path_segments(root_node, &path.segments, nodes)
            }
        }
        PathAnchor::Parent => {
            let parent_path = target_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            let parent_node = nodes
                .iter()
                .find(|n| n.path == parent_path)
                .ok_or_else(|| format!("parent of '{}' not found", target_path))?;
            find_node_by_path_segments(parent_node, &path.segments, nodes)
        }
    }
}

fn get_path_expr_type(
    target_path: &str,
    path: &PathExpr,
    input: &CanonicalInput,
) -> Option<TokenStream> {
    let resolved_node = resolve_path_node(target_path, path, &input.nodes).ok()?;
    let mut resolved_type = resolved_node.type_ref.as_ref();
    if let Some(TypeRef::LeafRef {
        target_path: t_path,
    }) = resolved_type
    {
        if let Some(target_node) = input.nodes.iter().find(|n| &n.path == t_path) {
            resolved_type = target_node.type_ref.as_ref();
        }
    }
    match resolved_type {
        Some(TypeRef::Boolean) => Some(quote! { bool }),
        Some(TypeRef::Uint16) => Some(quote! { u16 }),
        Some(TypeRef::Uint32) => Some(quote! { u32 }),
        Some(TypeRef::Int64) => Some(quote! { i64 }),
        Some(TypeRef::Decimal64) => Some(quote! { f64 }),
        _ => Some(quote! { String }),
    }
}

fn evaluate_expr(
    expr: &ConstraintExpr,
    context_var: &str,
    target_path: &str,
    context_path: &str,
    input: &CanonicalInput,
    depth: usize,
) -> Result<TokenStream, RustGenerationError> {
    if depth > 64 {
        return Err(RustGenerationError::new(
            "must/when constraints depth limit exceeded",
        ));
    }
    match expr {
        ConstraintExpr::Literal(lit) => match lit {
            crate::ir::Literal::Bool(b) => Ok(quote! { #b }),
            crate::ir::Literal::Number(n) => Ok(quote! { #n }),
            crate::ir::Literal::String(s) => Ok(quote! { #s }),
        },
        ConstraintExpr::Path(path) => {
            let resolved_node =
                resolve_path_node(target_path, path, &input.nodes).map_err(|e| {
                    RustGenerationError::new(format!(
                        "must/when constraints path resolution error: {}",
                        e
                    ))
                })?;
            let access = generate_path_access(&resolved_node, context_path, input);
            let is_custom_wrapper = matches!(
                resolved_node.type_ref,
                Some(TypeRef::Int64) | Some(TypeRef::Decimal64)
            );

            if resolved_node.kind == SchemaNodeKind::Leaf && resolved_node.config {
                if is_custom_wrapper {
                    Ok(quote! { #access.as_option().map(|x| x.0) })
                } else {
                    Ok(quote! { #access.as_option() })
                }
            } else {
                if is_custom_wrapper {
                    Ok(quote! { #access.as_ref().map(|x| x.0) })
                } else {
                    Ok(quote! { #access.as_ref() })
                }
            }
        }
        ConstraintExpr::Compare { op, left, right } => {
            let op_token = match op {
                CompareOp::Eq => quote! { == },
                CompareOp::NotEq => quote! { != },
                CompareOp::Gt => quote! { > },
                CompareOp::Lt => quote! { < },
                CompareOp::Gte => quote! { >= },
                CompareOp::Lte => quote! { <= },
            };

            let path_type = if let ConstraintExpr::Path(path) = &**left {
                get_path_expr_type(target_path, path, input)
            } else if let ConstraintExpr::Path(path) = &**right {
                get_path_expr_type(target_path, path, input)
            } else {
                None
            };

            let left_val = if let (ConstraintExpr::Literal(Literal::Number(n)), Some(ref ty)) =
                (&**left, &path_type)
            {
                quote! { (#n as #ty) }
            } else {
                evaluate_expr(
                    left,
                    context_var,
                    target_path,
                    context_path,
                    input,
                    depth + 1,
                )?
            };

            let right_val = if let (ConstraintExpr::Literal(Literal::Number(n)), Some(ref ty)) =
                (&**right, &path_type)
            {
                quote! { (#n as #ty) }
            } else {
                evaluate_expr(
                    right,
                    context_var,
                    target_path,
                    context_path,
                    input,
                    depth + 1,
                )?
            };

            let left_is_option = match &**left {
                ConstraintExpr::Path(_) => true,
                ConstraintExpr::Function(f) if f.name == FunctionName::Current => true,
                _ => false,
            };
            let right_is_option = match &**right {
                ConstraintExpr::Path(_) => true,
                ConstraintExpr::Function(f) if f.name == FunctionName::Current => true,
                _ => false,
            };

            match (left_is_option, right_is_option) {
                (true, true) => Ok(quote! { #left_val #op_token #right_val }),
                (true, false) => match op {
                    CompareOp::Eq | CompareOp::NotEq => {
                        Ok(quote! { #left_val #op_token Some(&#right_val) })
                    }
                    _ => Ok(quote! {
                        match #left_val {
                            Some(v) => *v #op_token #right_val,
                            None => false,
                        }
                    }),
                },
                (false, true) => match op {
                    CompareOp::Eq | CompareOp::NotEq => {
                        Ok(quote! { Some(&#left_val) #op_token #right_val })
                    }
                    _ => Ok(quote! {
                        match #right_val {
                            Some(v) => #left_val #op_token *v,
                            None => false,
                        }
                    }),
                },
                (false, false) => Ok(quote! { #left_val #op_token #right_val }),
            }
        }
        ConstraintExpr::Boolean { op, terms } => {
            let op_token = match op {
                BooleanOp::And => quote! { && },
                BooleanOp::Or => quote! { || },
            };
            let mut evaluated_terms = Vec::new();
            for term in terms {
                evaluated_terms.push(evaluate_expr(
                    term,
                    context_var,
                    target_path,
                    context_path,
                    input,
                    depth + 1,
                )?);
            }
            let mut iter = evaluated_terms.into_iter();
            if let Some(first) = iter.next() {
                let mut ts = first;
                for term in iter {
                    ts = quote! { #ts #op_token #term };
                }
                Ok(quote! { ( #ts ) })
            } else {
                Ok(quote! { true })
            }
        }
        ConstraintExpr::Function(func) => match func.name {
            FunctionName::Not => {
                if func.args.len() != 1 {
                    return Err(RustGenerationError::new("not() expects exactly 1 argument"));
                }
                let arg_val = evaluate_expr(
                    &func.args[0],
                    context_var,
                    target_path,
                    context_path,
                    input,
                    depth + 1,
                )?;
                let is_boolean_expr = match &func.args[0] {
                    ConstraintExpr::Compare { .. } | ConstraintExpr::Boolean { .. } => true,
                    ConstraintExpr::Function(f) if f.name == FunctionName::Not => true,
                    _ => false,
                };
                if is_boolean_expr {
                    Ok(quote! { !( #arg_val ) })
                } else {
                    Ok(quote! { #arg_val.is_none() })
                }
            }
            FunctionName::Count => {
                if func.args.len() != 1 {
                    return Err(RustGenerationError::new(
                        "count() expects exactly 1 argument",
                    ));
                }
                if let ConstraintExpr::Path(path) = &func.args[0] {
                    let resolved_node = resolve_path_node(target_path, path, &input.nodes)
                        .map_err(|e| {
                            RustGenerationError::new(format!(
                                "count() path resolution error: {}",
                                e
                            ))
                        })?;
                    let field_name = clean_segment(last_segment(&resolved_node.path));
                    let field_ident = format_ident!("{}", to_snake_case(field_name));
                    let context_ident = format_ident!("{}", context_var);
                    match resolved_node.kind {
                        SchemaNodeKind::List | SchemaNodeKind::LeafList => {
                            Ok(quote! { #context_ident.#field_ident.len() })
                        }
                        SchemaNodeKind::Container => {
                            Ok(quote! { if #context_ident.#field_ident.is_some() { 1 } else { 0 } })
                        }
                        SchemaNodeKind::Leaf => {
                            if resolved_node.config {
                                Ok(
                                    quote! { if #context_ident.#field_ident.as_option().is_some() { 1 } else { 0 } },
                                )
                            } else {
                                Ok(
                                    quote! { if #context_ident.#field_ident.is_some() { 1 } else { 0 } },
                                )
                            }
                        }
                        _ => Ok(quote! { 0 }),
                    }
                } else {
                    Err(RustGenerationError::new("count() expects a path argument"))
                }
            }
            FunctionName::Current => {
                if !func.args.is_empty() {
                    return Err(RustGenerationError::new("current() expects no arguments"));
                }
                let resolved_node = input
                    .nodes
                    .iter()
                    .find(|n| n.path == target_path)
                    .ok_or_else(|| {
                        RustGenerationError::new(format!("target node '{}' not found", target_path))
                    })?;
                let access = generate_path_access(resolved_node, context_path, input);
                let is_custom_wrapper = matches!(
                    resolved_node.type_ref,
                    Some(TypeRef::Int64) | Some(TypeRef::Decimal64)
                );
                if resolved_node.kind == SchemaNodeKind::Leaf && resolved_node.config {
                    if is_custom_wrapper {
                        Ok(quote! { #access.as_option().map(|x| x.0) })
                    } else {
                        Ok(quote! { #access.as_option() })
                    }
                } else {
                    if is_custom_wrapper {
                        Ok(quote! { #access.as_ref().map(|x| x.0) })
                    } else {
                        Ok(quote! { #access.as_ref() })
                    }
                }
            }
            _ => Err(RustGenerationError::new(format!(
                "unsupported must/when constraints: xpath function {:?}",
                func.name
            ))),
        },
    }
}
