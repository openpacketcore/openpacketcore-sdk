use super::{
    clean_segment, is_sensitive_name, last_segment, to_pascal_case, to_snake_case,
    RustGenerationError,
};
use crate::emit::CanonicalInput;
use crate::ir::{AllocationStrategy, SchemaNode, SchemaNodeKind, TypeRef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;

pub fn is_sensitive_node(node: &SchemaNode) -> bool {
    if let Some(ref dc) = node.data_class {
        dc != "public" && dc != "operational"
    } else {
        is_sensitive_name(clean_segment(last_segment(&node.path)))
    }
}

fn get_raw_type(node: &SchemaNode, nodes_by_path: &HashMap<String, &SchemaNode>) -> TokenStream {
    get_raw_type_internal(node, nodes_by_path, &mut std::collections::HashSet::new())
}

fn get_raw_type_internal(
    node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
    visited: &mut std::collections::HashSet<String>,
) -> TokenStream {
    if visited.contains(&node.path) {
        return quote! { String };
    }
    visited.insert(node.path.clone());
    match &node.type_ref {
        Some(TypeRef::Boolean) => quote! { bool },
        Some(TypeRef::String) | Some(TypeRef::Enumeration { .. }) => quote! { String },
        Some(TypeRef::Uint16) => quote! { u16 },
        Some(TypeRef::Uint32) => quote! { u32 },
        Some(TypeRef::Int64) => quote! { YangInt64 },
        Some(TypeRef::Decimal64) => quote! { YangDecimal64 },
        Some(TypeRef::Empty) => quote! { YangEmpty },
        Some(TypeRef::IdentityRef { .. }) => quote! { String },
        Some(TypeRef::LeafRef { target_path }) => {
            if let Some(target_node) = nodes_by_path.get(target_path) {
                get_raw_type_internal(target_node, nodes_by_path, visited)
            } else {
                quote! { String }
            }
        }
        Some(TypeRef::Custom { name }) => {
            let custom_name = format_ident!("{}", to_pascal_case(name));
            quote! { #custom_name }
        }
        None => quote! { () },
    }
}

fn get_key_type(
    list_node: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> TokenStream {
    if list_node.key_leaves.len() == 1 {
        let key_name = &list_node.key_leaves[0];
        let mut key_ty = quote! { String };
        for child_path in &list_node.child_paths {
            if let Some(child) = nodes_by_path.get(child_path) {
                let child_name = clean_segment(last_segment(&child.path));
                if child_name == key_name {
                    key_ty = get_raw_type(child, nodes_by_path);
                    break;
                }
            }
        }
        key_ty
    } else {
        let name = clean_segment(last_segment(&list_node.path));
        let struct_name = format_ident!("{}Key", to_pascal_case(name));
        quote! { #struct_name }
    }
}

fn is_root_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    !trimmed.is_empty() && !trimmed.contains('/')
}

pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let mut tokens = TokenStream::new();
    let mut nodes_by_path = HashMap::new();
    for node in &input.nodes {
        nodes_by_path.insert(node.path.clone(), node);
    }

    // Emit helper types
    tokens.extend(quote! {
        use serde::{Serialize, Deserialize};

        #[derive(Clone, PartialEq, Default)]
        pub struct SecretLeaf<T> {
            inner: T,
        }
        impl<T: std::fmt::Debug> std::fmt::Debug for SecretLeaf<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "<REDACTED>")
            }
        }
        impl<T: Serialize> Serialize for SecretLeaf<T> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.inner.serialize(serializer)
            }
        }
        impl<'de, T: Deserialize<'de>> Deserialize<'de> for SecretLeaf<T> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let inner = T::deserialize(deserializer)?;
                Ok(SecretLeaf { inner })
            }
        }
        impl<T> SecretLeaf<T> {
            pub fn new(inner: T) -> Self {
                Self { inner }
            }
            pub fn into_inner(self) -> T {
                self.inner
            }
            pub fn get(&self) -> &T {
                &self.inner
            }
            pub fn get_mut(&mut self) -> &mut T {
                &mut self.inner
            }
            pub fn is_empty(&self) -> bool
            where
                for<'a> &'a T: IntoIterator,
            {
                self.inner.into_iter().next().is_none()
            }
        }
        impl<U> SecretLeaf<LeafPresence<U>> {
            pub fn is_absent(&self) -> bool {
                self.inner.is_absent()
            }
        }
        impl<U> SecretLeaf<Option<U>> {
            pub fn is_none(&self) -> bool {
                self.inner.is_none()
            }
        }

        #[derive(Clone, PartialEq)]
        pub enum LeafPresence<T> {
            Absent,
            Defaulted(T),
            Explicit(T),
        }
        impl<T: std::fmt::Debug> std::fmt::Debug for LeafPresence<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Absent => write!(f, "Absent"),
                    Self::Defaulted(v) => write!(f, "Defaulted({:?})", v),
                    Self::Explicit(v) => write!(f, "Explicit({:?})", v),
                }
            }
        }
        impl<T> LeafPresence<T> {
            pub fn as_option(&self) -> Option<&T> {
                match self {
                    Self::Absent => None,
                    Self::Defaulted(v) => Some(v),
                    Self::Explicit(v) => Some(v),
                }
            }
            pub fn into_option(self) -> Option<T> {
                match self {
                    Self::Absent => None,
                    Self::Defaulted(v) => Some(v),
                    Self::Explicit(v) => Some(v),
                }
            }
            pub fn is_absent(&self) -> bool {
                matches!(self, Self::Absent)
            }
        }
        impl<T: Default> Default for LeafPresence<T> {
            fn default() -> Self {
                Self::Absent
            }
        }
        impl<T: Serialize> Serialize for LeafPresence<T> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                match self {
                    Self::Absent => serializer.serialize_none(),
                    Self::Defaulted(v) | Self::Explicit(v) => v.serialize(serializer),
                }
            }
        }
        impl<'de, T: Deserialize<'de>> Deserialize<'de> for LeafPresence<T> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let opt = Option::<T>::deserialize(deserializer)?;
                match opt {
                    Some(v) => Ok(Self::Explicit(v)),
                    None => Ok(Self::Absent),
                }
            }
        }

        #[derive(Clone, Copy, Debug, PartialEq, Default)]
        pub struct YangInt64(pub i64);
        impl Serialize for YangInt64 {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.0.to_string())
            }
        }
        impl<'de> Deserialize<'de> for YangInt64 {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                let val = s.parse::<i64>().map_err(serde::de::Error::custom)?;
                Ok(YangInt64(val))
            }
        }

        #[derive(Clone, Copy, Debug, PartialEq, Default)]
        pub struct YangDecimal64(pub f64);
        impl Serialize for YangDecimal64 {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.0.to_string())
            }
        }
        impl<'de> Deserialize<'de> for YangDecimal64 {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                let val = s.parse::<f64>().map_err(serde::de::Error::custom)?;
                Ok(YangDecimal64(val))
            }
        }

        #[derive(Clone, Copy, Debug, PartialEq, Default, Eq)]
        pub struct YangEmpty;
        impl Serialize for YangEmpty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(1))?;
                seq.serialize_element(&())?;
                seq.end()
            }
        }
        impl<'de> Deserialize<'de> for YangEmpty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct Visitor;
                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = YangEmpty;
                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("a sequence containing null")
                    }
                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: serde::de::SeqAccess<'de>,
                    {
                        let elem: Option<()> = seq.next_element()?;
                        if elem.is_some() {
                            Ok(YangEmpty)
                        } else {
                            Err(serde::de::Error::custom("expected null in empty type sequence"))
                        }
                    }
                }
                deserializer.deserialize_seq(Visitor)
            }
        }
    });

    for node in &input.nodes {
        if node.kind == SchemaNodeKind::Container || node.kind == SchemaNodeKind::List {
            let name = clean_segment(last_segment(&node.path));
            let struct_name = format_ident!("{}", to_pascal_case(name));

            let mut fields = TokenStream::new();
            let mut default_fields = Vec::new();
            let mut has_defaults = false;

            for child_path in &node.child_paths {
                if let Some(child) = nodes_by_path.get(child_path) {
                    let child_name = clean_segment(last_segment(&child.path));
                    let field_ident = format_ident!("{}", to_snake_case(child_name));

                    let mut field_type = match child.kind {
                        SchemaNodeKind::Leaf => {
                            let ty = get_raw_type(child, &nodes_by_path);
                            if child.config {
                                quote! { LeafPresence<#ty> }
                            } else {
                                quote! { Option<#ty> }
                            }
                        }
                        SchemaNodeKind::Container => {
                            let ty_name = format_ident!("{}", to_pascal_case(child_name));
                            let mut is_boxed = false;
                            for shape in &input.stack_shapes {
                                if shape.yang_path == child.path
                                    && shape.allocation == AllocationStrategy::Boxed
                                {
                                    is_boxed = true;
                                }
                            }
                            if is_boxed {
                                quote! { Option<Box<#ty_name>> }
                            } else {
                                quote! { Option<#ty_name> }
                            }
                        }
                        SchemaNodeKind::List => {
                            let ty_name = format_ident!("{}", to_pascal_case(child_name));
                            if child.key_leaves.is_empty() {
                                quote! { Vec<#ty_name> }
                            } else {
                                let key_ty = get_key_type(child, &nodes_by_path);
                                quote! { std::collections::BTreeMap<#key_ty, #ty_name> }
                            }
                        }
                        SchemaNodeKind::LeafList => {
                            let mut resolved_elem_ty = child.type_ref.as_ref();
                            if let Some(TypeRef::LeafRef { target_path }) = resolved_elem_ty {
                                if let Some(target_node) = nodes_by_path.get(target_path) {
                                    resolved_elem_ty = target_node.type_ref.as_ref();
                                }
                            }
                            let elem_ty = match resolved_elem_ty {
                                Some(TypeRef::Boolean) => quote! { bool },
                                Some(TypeRef::String) | Some(TypeRef::Enumeration { .. }) => {
                                    quote! { String }
                                }
                                Some(TypeRef::Uint16) => quote! { u16 },
                                Some(TypeRef::Uint32) => quote! { u32 },
                                Some(TypeRef::Int64) => quote! { YangInt64 },
                                Some(TypeRef::Decimal64) => quote! { YangDecimal64 },
                                Some(TypeRef::Empty) => quote! { YangEmpty },
                                Some(TypeRef::IdentityRef { .. }) => quote! { String },
                                Some(TypeRef::Custom { name }) => {
                                    let custom_name = format_ident!("{}", to_pascal_case(name));
                                    quote! { #custom_name }
                                }
                                _ => quote! { String },
                            };
                            quote! { Vec<#elem_ty> }
                        }
                        _ => quote! { () },
                    };

                    if is_sensitive_node(child) {
                        field_type = quote! { SecretLeaf<#field_type> };
                    }

                    let is_sensitive = is_sensitive_node(child);

                    // Namespace-qualified field name logic (RFC 7951)
                    let is_qualified_needed =
                        is_root_path(&node.path) || child.module != node.module;
                    let field_name_str = if is_qualified_needed {
                        format!("{}:{}", child.module, child_name)
                    } else {
                        child_name.to_string()
                    };
                    let alias_1 = child_name;
                    let alias_2 = format!("{}:{}", child.module, child_name);

                    // Determine skip_serializing_if condition
                    let is_option = match child.kind {
                        SchemaNodeKind::Container => true,
                        SchemaNodeKind::Leaf => !child.config,
                        _ => false,
                    };
                    let is_sequence =
                        matches!(child.kind, SchemaNodeKind::List | SchemaNodeKind::LeafList);

                    let skip_if = if is_option {
                        if is_sensitive {
                            "SecretLeaf::is_none"
                        } else {
                            "Option::is_none"
                        }
                    } else if is_sequence {
                        if is_sensitive {
                            "SecretLeaf::is_empty"
                        } else {
                            "super::serde::is_sequence_empty"
                        }
                    } else {
                        // LeafPresence
                        if is_sensitive {
                            "SecretLeaf::is_absent"
                        } else {
                            "LeafPresence::is_absent"
                        }
                    };

                    let serde_helper_attr = if child.kind == SchemaNodeKind::List
                        && !child.key_leaves.is_empty()
                    {
                        quote! {
                            #[serde(serialize_with = "super::serde::serialize_list", deserialize_with = "super::serde::deserialize_list")]
                        }
                    } else {
                        quote! {}
                    };

                    fields.extend(quote! {
                        #serde_helper_attr
                        #[serde(rename = #field_name_str, alias = #alias_1, alias = #alias_2, skip_serializing_if = #skip_if, default)]
                        pub #field_ident: #field_type,
                    });

                    // Build default expression
                    let def_expr = get_field_default_expr(child, &nodes_by_path);
                    if child.default.is_some() {
                        has_defaults = true;
                    }
                    default_fields.push(quote! {
                        #field_ident: #def_expr
                    });
                }
            }

            if has_defaults {
                tokens.extend(quote! {
                    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
                    pub struct #struct_name {
                        #fields
                    }
                    impl Default for #struct_name {
                        fn default() -> Self {
                            Self {
                                #(#default_fields),*
                            }
                        }
                    }
                });
            } else {
                tokens.extend(quote! {
                    #[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
                    pub struct #struct_name {
                        #fields
                    }
                });
            }

            // Generate key struct if it's a multi-key list
            if node.kind == SchemaNodeKind::List && node.key_leaves.len() > 1 {
                let key_struct_ident = format_ident!("{}Key", to_pascal_case(name));
                let mut key_fields = TokenStream::new();
                for key_name in &node.key_leaves {
                    let mut key_ty = quote! { String };
                    for child_path in &node.child_paths {
                        if let Some(child) = nodes_by_path.get(child_path) {
                            let child_name = clean_segment(last_segment(&child.path));
                            if child_name == key_name {
                                key_ty = get_raw_type(child, &nodes_by_path);
                                break;
                            }
                        }
                    }
                    let field_ident = format_ident!("{}", to_snake_case(key_name));
                    key_fields.extend(quote! {
                        pub #field_ident: #key_ty,
                    });
                }
                tokens.extend(quote! {
                    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
                    pub struct #key_struct_ident {
                        #key_fields
                    }
                });
            }

            // Generate ExtractKey trait implementation for list value struct
            if node.kind == SchemaNodeKind::List && !node.key_leaves.is_empty() {
                let key_ty = get_key_type(node, &nodes_by_path);
                let extract_body = if node.key_leaves.len() == 1 {
                    let key_field = &node.key_leaves[0];
                    let field_ident = format_ident!("{}", to_snake_case(key_field));
                    let mut child_node = None;
                    for child_path in &node.child_paths {
                        if let Some(child) = nodes_by_path.get(child_path) {
                            if clean_segment(last_segment(&child.path)) == key_field {
                                child_node = Some(child);
                                break;
                            }
                        }
                    }
                    let child = child_node.unwrap();
                    let is_sensitive = is_sensitive_node(child);
                    if is_sensitive {
                        quote! { self.#field_ident.get().as_option().cloned().unwrap_or_default() }
                    } else {
                        quote! { self.#field_ident.as_option().cloned().unwrap_or_default() }
                    }
                } else {
                    let key_struct_ident = format_ident!("{}Key", to_pascal_case(name));
                    let mut key_constructors = TokenStream::new();
                    for key_field in &node.key_leaves {
                        let mut child_node = None;
                        for child_path in &node.child_paths {
                            if let Some(child) = nodes_by_path.get(child_path) {
                                if clean_segment(last_segment(&child.path)) == key_field {
                                    child_node = Some(child);
                                    break;
                                }
                            }
                        }
                        let child = child_node.unwrap();
                        let is_sensitive = is_sensitive_node(child);
                        let field_ident = format_ident!("{}", to_snake_case(key_field));
                        let val_expr = if is_sensitive {
                            quote! { self.#field_ident.get().as_option().cloned().unwrap_or_default() }
                        } else {
                            quote! { self.#field_ident.as_option().cloned().unwrap_or_default() }
                        };
                        key_constructors.extend(quote! {
                            #field_ident: #val_expr,
                        });
                    }
                    quote! {
                        #key_struct_ident {
                            #key_constructors
                        }
                    }
                };

                tokens.extend(quote! {
                    impl super::serde::ExtractKey<#key_ty> for #struct_name {
                        fn extract_key(&self) -> #key_ty {
                            #extract_body
                        }
                    }
                });
            }
        }
    }

    Ok(tokens.to_string())
}

fn get_field_default_expr(
    child: &SchemaNode,
    nodes_by_path: &HashMap<String, &SchemaNode>,
) -> TokenStream {
    if let Some(ref def_str) = child.default {
        let mut resolved_type = child.type_ref.as_ref();
        if let Some(TypeRef::LeafRef { target_path }) = resolved_type {
            if let Some(target_node) = nodes_by_path.get(target_path) {
                resolved_type = target_node.type_ref.as_ref();
            }
        }
        let val_expr = match resolved_type {
            Some(TypeRef::Boolean) => {
                let b = def_str == "true";
                quote! { #b }
            }
            Some(TypeRef::Uint16) => {
                let val = def_str.parse::<u16>().unwrap_or(0);
                quote! { #val }
            }
            Some(TypeRef::Uint32) => {
                let val = def_str.parse::<u32>().unwrap_or(0);
                quote! { #val }
            }
            Some(TypeRef::Int64) => {
                let val = def_str.parse::<i64>().unwrap_or(0);
                quote! { YangInt64(#val) }
            }
            Some(TypeRef::Decimal64) => {
                let val = def_str.parse::<f64>().unwrap_or(0.0);
                quote! { YangDecimal64(#val) }
            }
            Some(TypeRef::Empty) => {
                quote! { YangEmpty }
            }
            _ => {
                quote! { #def_str.to_string() }
            }
        };
        if is_sensitive_node(child) {
            quote! { SecretLeaf::new(LeafPresence::Defaulted(#val_expr)) }
        } else {
            quote! { LeafPresence::Defaulted(#val_expr) }
        }
    } else {
        let is_sensitive = is_sensitive_node(child);
        match child.kind {
            SchemaNodeKind::Leaf => {
                if child.config {
                    if is_sensitive {
                        quote! { SecretLeaf::new(LeafPresence::Absent) }
                    } else {
                        quote! { LeafPresence::Absent }
                    }
                } else if is_sensitive {
                    quote! { SecretLeaf::new(None) }
                } else {
                    quote! { None }
                }
            }
            _ => {
                quote! { Default::default() }
            }
        }
    }
}
