use super::RustGenerationError;
use crate::emit::CanonicalInput;
use quote::quote;

pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let mut valid_paths = Vec::new();
    let mut config_paths = Vec::new();
    let mut state_paths = Vec::new();

    for node in &input.nodes {
        let path_str = &node.path;
        valid_paths.push(path_str);
        if node.config {
            config_paths.push(path_str);
        } else {
            state_paths.push(path_str);
        }
    }

    // Sort to be deterministic
    valid_paths.sort();
    config_paths.sort();
    state_paths.sort();

    let tokens = quote! {
        pub const VALID_PATHS: &[&str] = &[
            #(#valid_paths),*
        ];

        pub const CONFIG_PATHS: &[&str] = &[
            #(#config_paths),*
        ];

        pub const STATE_PATHS: &[&str] = &[
            #(#state_paths),*
        ];

        pub fn is_valid_path(path: &str) -> bool {
            let normalized_input = normalize_path(path);
            VALID_PATHS.iter().any(|p| normalize_path(p) == normalized_input)
        }

        pub fn is_config_path(path: &str) -> bool {
            let normalized_input = normalize_path(path);
            CONFIG_PATHS.iter().any(|p| normalize_path(p) == normalized_input)
        }

        pub fn normalize_path(path: &str) -> String {
            let stripped = strip_brackets(path);
            let segments: Vec<&str> = stripped.split('/').map(|seg| {
                if let Some(idx) = seg.find(':') {
                    &seg[idx + 1..]
                } else {
                    seg
                }
            }).collect();
            segments.join("/")
        }

        pub fn strip_brackets(path: &str) -> String {
            let mut out = String::new();
            let mut in_brackets = false;
            let mut quote_char = None;
            let mut chars = path.chars().peekable();
            while let Some(c) = chars.next() {
                if quote_char.is_some() {
                    if c == '\\' {
                        let next_c = chars.next();
                        if !in_brackets {
                            out.push(c);
                            if let Some(nc) = next_c {
                                out.push(nc);
                            }
                        }
                    } else if Some(c) == quote_char {
                        quote_char = None;
                        if !in_brackets {
                            out.push(c);
                        }
                    } else if !in_brackets {
                        out.push(c);
                    }
                } else {
                    if c == '\\' {
                        let next_c = chars.next();
                        if !in_brackets {
                            out.push(c);
                            if let Some(nc) = next_c {
                                out.push(nc);
                            }
                        }
                    } else if c == '\'' || c == '"' {
                        quote_char = Some(c);
                        if !in_brackets {
                            out.push(c);
                        }
                    } else if c == '[' {
                        in_brackets = true;
                    } else if c == ']' {
                        in_brackets = false;
                    } else if !in_brackets {
                        out.push(c);
                    }
                }
            }
            out
        }
    };

    Ok(tokens.to_string())
}
