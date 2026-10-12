use super::{NodeIndex, RustGenerationError};
use crate::{CanonicalInput, TypeRef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub(super) fn has_constraints(input: &CanonicalInput) -> bool {
    input
        .nodes
        .iter()
        .any(|n| matches!(n.type_ref, Some(TypeRef::RestrictedString { .. })))
}

pub(super) fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let nodes = NodeIndex::new(&input.nodes);
    let mut patterns = TokenStream::new();
    let mut arms = TokenStream::new();
    for node in &input.nodes {
        let scalar = nodes.scalar_node(node);
        let Some((length, restrictions)) = scalar
            .type_ref
            .as_ref()
            .and_then(TypeRef::string_restrictions)
        else {
            continue;
        };
        let path = &node.path;
        let length_check = if length.is_empty() {
            quote! { true }
        } else {
            let intervals = length.iter().map(|range| {
                let min = range.min;
                let max = range.max;
                quote! { (#min..=#max).contains(&length) }
            });
            quote! { { let length = value.chars().count() as u64; #(#intervals)||* } }
        };
        let checks = restrictions.iter().enumerate().map(|(i, pattern)| {
            let name = format_ident!("PATTERN_{}_{}", nodes.helper_name(&scalar.path).to_uppercase(), i);
            let expression = &pattern.expression;
            let inverted = pattern.invert_match;
            if scalar.path == node.path {
                patterns.extend(quote! {
                    static #name: std::sync::OnceLock<Result<opc_mgmt_schema::string_constraints::CompiledYangPattern, opc_mgmt_schema::string_constraints::PatternError>> = std::sync::OnceLock::new();
                });
            }
            quote! {
                #name.get_or_init(|| opc_mgmt_schema::string_constraints::CompiledYangPattern::compile(#expression))
                    .as_ref().is_ok_and(|pattern| pattern.is_match(value) != #inverted)
            }
        }).collect::<Vec<_>>();
        let check = if checks.is_empty() {
            length_check
        } else if length.is_empty() {
            quote! { #(#checks)&&* }
        } else {
            quote! { { let valid_length = #length_check; valid_length #(&& #checks)* } }
        };
        arms.extend(quote! { #path => #check, });
    }
    Ok(quote! {
        #patterns
        /// Validate retained string restrictions without exposing a value.
        pub fn valid(path: &str, value: &str) -> bool {
            match path { #arms _ => true }
        }
    }
    .to_string())
}

pub(super) fn validate_schema(input: &CanonicalInput) -> Result<(), RustGenerationError> {
    use opc_mgmt_schema::string_constraints::CompiledYangPattern;
    let nodes = NodeIndex::new(&input.nodes);
    for node in &input.nodes {
        let scalar = nodes.scalar_node(node);
        let Some((length, patterns)) = scalar
            .type_ref
            .as_ref()
            .and_then(TypeRef::string_restrictions)
        else {
            continue;
        };
        if length.iter().any(|range| range.min > range.max)
            || length.windows(2).any(|pair| pair[0].max >= pair[1].min)
            || patterns.len() > 64
        {
            return Err(RustGenerationError::new(
                "invalid or excessive string restrictions",
            ));
        }
        let compiled = patterns
            .iter()
            .map(|p| {
                CompiledYangPattern::compile(&p.expression)
                    .map_err(|error| RustGenerationError::new(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(value) = &node.default {
            let count = value.chars().count() as u64;
            if (!length.is_empty()
                && !length
                    .iter()
                    .any(|range| (range.min..=range.max).contains(&count)))
                || patterns
                    .iter()
                    .zip(&compiled)
                    .any(|(source, compiled)| compiled.is_match(value) == source.invert_match)
            {
                return Err(RustGenerationError::new(
                    "string default violates YANG constraints",
                ));
            }
        }
    }
    Ok(())
}
