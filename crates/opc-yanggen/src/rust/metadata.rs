use super::{clean_segment, last_segment, RustGenerationError};
use crate::emit::CanonicalInput;
use proc_macro2::TokenStream;
use quote::quote;

fn map_data_class(dc_str: &str) -> TokenStream {
    match dc_str {
        "public" => quote! { DataClass::Public },
        "operational" => quote! { DataClass::Operational },
        "network-sensitive" => quote! { DataClass::NetworkSensitive },
        "subscriber-id" => quote! { DataClass::SubscriberId },
        "subscriber-session" => quote! { DataClass::SubscriberSession },
        "security-secret" => quote! { DataClass::SecuritySecret },
        "charging-record" => quote! { DataClass::ChargingRecord },
        "lawful-intercept" => quote! { DataClass::LawfulIntercept },
        "analytics-sensitive" => quote! { DataClass::AnalyticsSensitive },
        "audit-regulated" => quote! { DataClass::AuditRegulated },
        _ => quote! { DataClass::Public },
    }
}

pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let mut map_inserts = TokenStream::new();
    for node in &input.nodes {
        let path_str = &node.path;
        let data_class = if let Some(ref dc) = node.data_class {
            map_data_class(dc)
        } else {
            // fallback name-based for compatibility if no data_class is present
            let name = clean_segment(last_segment(&node.path));
            if super::is_sensitive_name(name) {
                quote! { DataClass::SecuritySecret }
            } else {
                quote! { DataClass::Public }
            }
        };
        map_inserts.extend(quote! {
            map.insert(
                YangPath::new(#path_str).expect("opc-yanggen emitted an invalid YANG path"),
                #data_class,
            );
        });
    }

    let tokens = quote! {
        use std::collections::HashMap;
        use opc_config_model::YangPath;
        use opc_data_governance::DataClass;

        pub fn get_data_classes() -> HashMap<YangPath, DataClass> {
            let mut map = HashMap::new();
            #map_inserts
            map
        }

        pub fn get_data_class_for_path(path: &YangPath) -> Option<DataClass> {
            let cleaned = strip_brackets(path.as_str());
            let schema_path = YangPath::new(cleaned).ok()?;
            get_data_classes().get(&schema_path).cloned()
        }

        fn strip_brackets(path: &str) -> String {
            let mut out = String::new();
            let mut in_brackets = false;
            for c in path.chars() {
                if c == '[' {
                    in_brackets = true;
                } else if c == ']' {
                    in_brackets = false;
                } else if !in_brackets {
                    out.push(c);
                }
            }
            out
        }
    };
    Ok(tokens.to_string())
}
