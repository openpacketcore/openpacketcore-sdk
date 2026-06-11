use super::{clean_segment, last_segment, to_pascal_case, to_snake_case, RustGenerationError};
use crate::emit::CanonicalInput;
use crate::ir::SchemaNodeKind;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;

pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let mut impls = TokenStream::new();
    let mut nodes_by_path = HashMap::new();
    for node in &input.nodes {
        nodes_by_path.insert(node.path.clone(), node);
    }

    for node in &input.nodes {
        if node.kind == SchemaNodeKind::Container || node.kind == SchemaNodeKind::List {
            let name = clean_segment(last_segment(&node.path));
            let struct_name = format_ident!("{}", to_pascal_case(name));
            let mut redactions = TokenStream::new();

            for child_path in &node.child_paths {
                if let Some(child) = nodes_by_path.get(child_path) {
                    let child_name = clean_segment(last_segment(&child.path));
                    let field_ident = format_ident!("{}", to_snake_case(child_name));
                    let is_sensitive = super::types::is_sensitive_node(child);

                    if is_sensitive {
                        let is_key = node.kind == SchemaNodeKind::List
                            && node.key_leaves.iter().any(|k| k == child_name);
                        if is_key {
                            if child.config {
                                redactions.extend(quote! {
                                    if let Some(val) = self.#field_ident.get().as_option() {
                                        let hashed = val.deterministic_hash();
                                        self.#field_ident = SecretLeaf::new(LeafPresence::Explicit(hashed));
                                    }
                                });
                            } else {
                                redactions.extend(quote! {
                                    if let Some(val) = self.#field_ident.get().as_ref() {
                                        let hashed = val.deterministic_hash();
                                        self.#field_ident = SecretLeaf::new(Some(hashed));
                                    }
                                });
                            }
                        } else {
                            let redact_val = if child.config {
                                quote! { LeafPresence::Absent }
                            } else {
                                quote! { None }
                            };
                            redactions.extend(quote! {
                                self.#field_ident = SecretLeaf::new(#redact_val);
                            });
                        }
                    } else {
                        match child.kind {
                            SchemaNodeKind::Container => {
                                redactions.extend(quote! {
                                    if let Some(ref mut c) = self.#field_ident {
                                        c.redact_sensitive_depth(depth + 1);
                                    }
                                });
                            }
                            SchemaNodeKind::List => {
                                if child.key_leaves.is_empty() {
                                    redactions.extend(quote! {
                                        for val in &mut self.#field_ident {
                                            val.redact_sensitive_depth(depth + 1);
                                        }
                                    });
                                } else {
                                    let mut key_redact = TokenStream::new();
                                    if child.key_leaves.len() == 1 {
                                        let key_leaf = &child.key_leaves[0];
                                        let mut find_key_leaf_node = None;
                                        for key_child_path in &child.child_paths {
                                            if let Some(key_child) =
                                                nodes_by_path.get(key_child_path)
                                            {
                                                if clean_segment(last_segment(&key_child.path))
                                                    == key_leaf
                                                {
                                                    find_key_leaf_node = Some(key_child);
                                                    break;
                                                }
                                            }
                                        }
                                        if let Some(kn) = find_key_leaf_node {
                                            if super::types::is_sensitive_node(kn) {
                                                key_redact = quote! { k = k.deterministic_hash(); };
                                            }
                                        }
                                    } else {
                                        for key_leaf in &child.key_leaves {
                                            let mut find_key_leaf_node = None;
                                            for key_child_path in &child.child_paths {
                                                if let Some(key_child) =
                                                    nodes_by_path.get(key_child_path)
                                                {
                                                    if clean_segment(last_segment(&key_child.path))
                                                        == key_leaf
                                                    {
                                                        find_key_leaf_node = Some(key_child);
                                                        break;
                                                    }
                                                }
                                            }
                                            if let Some(kn) = find_key_leaf_node {
                                                if super::types::is_sensitive_node(kn) {
                                                    let field_ident = format_ident!(
                                                        "{}",
                                                        to_snake_case(key_leaf)
                                                    );
                                                    key_redact.extend(quote! {
                                                        k.#field_ident = k.#field_ident.deterministic_hash();
                                                    });
                                                }
                                            }
                                        }
                                    }

                                    redactions.extend(quote! {
                                        let mut new_map = std::collections::BTreeMap::new();
                                        #[allow(unused_mut)]
                                        for (mut k, mut val) in std::mem::take(&mut self.#field_ident) {
                                            #key_redact
                                            val.redact_sensitive_depth(depth + 1);
                                            new_map.insert(k, val);
                                        }
                                        self.#field_ident = new_map;
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            impls.extend(quote! {
                impl Redactable for #struct_name {
                    fn redact_sensitive(&mut self) {
                        self.redact_sensitive_depth(0);
                    }
                    fn redact_sensitive_depth(&mut self, depth: usize) {
                        if depth > 64 {
                            return;
                        }
                        #redactions
                    }
                }
            });
        }
    }

    let tokens = quote! {
        use super::types::*;

        pub trait Redactable {
            fn redact_sensitive(&mut self);
            fn redact_sensitive_depth(&mut self, depth: usize);
        }

        pub trait DeterministicHash {
            fn deterministic_hash(&self) -> Self;
        }

        impl DeterministicHash for String {
            fn deterministic_hash(&self) -> Self {
                let mut hash: u64 = 0xcbf29ce484222325;
                for &byte in self.as_bytes() {
                    hash ^= byte as u64;
                    hash = hash.wrapping_mul(0x100000001b3);
                }
                format!("{:016x}", hash)
            }
        }

        impl DeterministicHash for bool {
            fn deterministic_hash(&self) -> Self {
                *self
            }
        }

        impl DeterministicHash for YangEmpty {
            fn deterministic_hash(&self) -> Self {
                *self
            }
        }

        macro_rules! impl_deterministic_hash_int {
            ($($t:ty),*) => {
                $(
                    impl DeterministicHash for $t {
                        fn deterministic_hash(&self) -> Self {
                            let mut hash: u64 = 0xcbf29ce484222325;
                            for &byte in &self.to_be_bytes() {
                                hash ^= byte as u64;
                                hash = hash.wrapping_mul(0x100000001b3);
                            }
                            hash as Self
                        }
                    }
                )*
            };
        }

        impl_deterministic_hash_int!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

        impl DeterministicHash for YangInt64 {
            fn deterministic_hash(&self) -> Self {
                YangInt64(self.0.deterministic_hash())
            }
        }

        impl DeterministicHash for YangDecimal64 {
            fn deterministic_hash(&self) -> Self {
                let bits = self.0.to_bits();
                let mut hash: u64 = 0xcbf29ce484222325;
                for &byte in &bits.to_be_bytes() {
                    hash ^= byte as u64;
                    hash = hash.wrapping_mul(0x100000001b3);
                }
                YangDecimal64(f64::from_bits(hash))
            }
        }

        #impls
    };

    Ok(tokens.to_string())
}
