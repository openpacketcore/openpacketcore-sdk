//! Literal canonical paths shared by management read adapters.

use std::{collections::BTreeSet, fmt};

use crate::{parse_qualified_name, PathSegment, RequestPath};

/// A malformed canonical path. Diagnostics never retain the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid canonical path")]
pub struct CanonicalPathError;

/// One parsed canonical segment. Key values borrow the original literal bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalSegment<'a> {
    /// Qualified node name.
    pub name: &'a str,
    /// Qualified key names and literal values, in supplied order.
    pub keys: Vec<(&'a str, &'a str)>,
}

impl fmt::Debug for CanonicalSegment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CanonicalSegment { .. }")
    }
}

/// A syntax-checked canonical path, with no XPath evaluation or escape syntax.
///
/// This establishes syntax only. Use the registry's complete-key resolution
/// before accepting an external concrete instance.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalPath<'a> {
    segments: Vec<CanonicalSegment<'a>>,
}

impl fmt::Debug for CanonicalPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CanonicalPath { .. }")
    }
}

impl<'a> CanonicalPath<'a> {
    /// Parses an absolute path. Quotes delimit XPath literals; backslashes are
    /// ordinary characters. Empty segments, duplicate keys and invalid names
    /// are rejected. Allocation is linear in the supplied path length.
    pub fn parse(path: &'a str) -> Result<Self, CanonicalPathError> {
        if path.chars().any(char::is_control) {
            return Err(CanonicalPathError);
        }
        let mut rest = path.strip_prefix('/').ok_or(CanonicalPathError)?;
        let mut segments = Vec::new();
        loop {
            let end = rest.find(['/', '[']).unwrap_or(rest.len());
            let name = &rest[..end];
            parse_qualified_name(name).ok_or(CanonicalPathError)?;
            rest = &rest[end..];
            let mut keys = Vec::new();
            let mut seen = BTreeSet::new();
            while let Some(predicate) = rest.strip_prefix('[') {
                let (key, value, remainder) = literal_predicate(predicate)?;
                parse_qualified_name(key).ok_or(CanonicalPathError)?;
                if !seen.insert(key) {
                    return Err(CanonicalPathError);
                }
                keys.push((key, value));
                rest = remainder;
            }
            segments.push(CanonicalSegment { name, keys });
            if rest.is_empty() {
                return Ok(Self { segments });
            }
            rest = rest.strip_prefix('/').ok_or(CanonicalPathError)?;
        }
    }

    /// Parsed path segments in root-to-leaf order.
    pub fn segments(&self) -> &[CanonicalSegment<'a>] {
        &self.segments
    }

    /// Whether `candidate` has equal node names and depth, and contains every
    /// key supplied by this selection. Omitted keys are unconstrained; `*` is
    /// literal here. Protocol wildcard normalization happens before parsing.
    pub fn matches_instance(&self, candidate: &Self) -> bool {
        self.segments.len() == candidate.segments.len()
            && self
                .segments
                .iter()
                .zip(&candidate.segments)
                .all(|(selected, actual)| {
                    selected.name == actual.name
                        && selected.keys.iter().all(|key| actual.keys.contains(key))
                })
    }

    /// Predicate-free, qualified path for registry lookup. This does not prove
    /// that the registry declares these keys or that the instance is complete.
    pub fn schema_path(&self) -> String {
        let mut out = String::new();
        for segment in &self.segments {
            out.push('/');
            out.push_str(segment.name);
        }
        out
    }

    /// Converts parsed literals into an owned request for schema resolution.
    pub fn to_request(&self) -> RequestPath {
        RequestPath::from_elems(
            self.segments
                .iter()
                .map(|segment| PathSegment::with_keys(segment.name, segment.keys.iter().copied())),
        )
    }
}

fn literal_predicate(predicate: &str) -> Result<(&str, &str, &str), CanonicalPathError> {
    let (key, literal) = predicate.split_once('=').ok_or(CanonicalPathError)?;
    let quote = match literal.as_bytes().first() {
        Some(b'\'') => '\'',
        Some(b'"') => '"',
        _ => return Err(CanonicalPathError),
    };
    let literal = &literal[1..];
    let end = literal.find(quote).ok_or(CanonicalPathError)?;
    let remaining = literal[end + 1..]
        .strip_prefix(']')
        .ok_or(CanonicalPathError)?;
    Ok((key, &literal[..end], remaining))
}

/// Matches only qualified node names and depth, without collecting key values.
///
/// This allocation-free structural check identifies an event's authorization
/// dependencies before byte limits or instance validation. It uses the same
/// literal boundaries as [`CanonicalPath::parse`], including ordinary
/// backslashes, but does not validate key names, uniqueness, types or tuples.
/// A matching authorized event still requires strict instance resolution.
pub fn instance_schema_matches(schema_path: &str, instance_path: &str) -> bool {
    let Some(mut rest) = instance_path.strip_prefix('/') else {
        return false;
    };
    let Some(schema) = schema_path.strip_prefix('/') else {
        return false;
    };
    let mut names = schema.split('/').peekable();
    while let Some(name) = names.next() {
        let end = rest.find(['/', '[']).unwrap_or(rest.len());
        if name.is_empty() || name != &rest[..end] {
            return false;
        }
        rest = &rest[end..];
        while let Some(predicate) = rest.strip_prefix('[') {
            let Ok((_, _, remainder)) = literal_predicate(predicate) else {
                return false;
            };
            rest = remainder;
        }
        if names.peek().is_none() {
            return rest.is_empty();
        }
        let Some(remainder) = rest.strip_prefix('/') else {
            return false;
        };
        rest = remainder;
    }
    false
}

/// Tests the syntax and instance relation of two canonical paths.
pub fn canonical_path_matches(selection: &str, candidate: &str) -> bool {
    match (
        CanonicalPath::parse(selection),
        CanonicalPath::parse(candidate),
    ) {
        (Ok(selection), Ok(candidate)) => selection.matches_instance(&candidate),
        _ => false,
    }
}

/// Appends a canonical key predicate without backslash escaping.
///
/// Uses single quotes unless the value contains an apostrophe, then double
/// quotes. Values containing both quote characters or control characters fail
/// without changing `out`. No value is included in the error.
pub fn append_key_predicate(
    out: &mut String,
    key: &str,
    value: &str,
) -> Result<(), CanonicalPathError> {
    parse_qualified_name(key).ok_or(CanonicalPathError)?;
    if value.chars().any(char::is_control) || (value.contains('\'') && value.contains('"')) {
        return Err(CanonicalPathError);
    }
    let quote = if value.contains('\'') { '"' } else { '\'' };
    out.push('[');
    out.push_str(key);
    out.push('=');
    out.push(quote);
    out.push_str(value);
    out.push(quote);
    out.push(']');
    Ok(())
}

/// Parses an absolute canonical path into owned request segments.
///
/// Uses the shared strict literal parser, including duplicate-key and control
/// character refusal. Schema resolution still validates complete instances.
pub fn parse_canonical_path(path: &str) -> Result<Vec<PathSegment>, CanonicalPathError> {
    Ok(CanonicalPath::parse(path)?.to_request().elems)
}

/// Tests the instance relation between parsed paths of equal depth.
///
/// Qualified node/key names and supplied key values compare exactly. Omitted
/// keys select any value; `*` is a literal. This neither expands descendants
/// nor validates schema types or completeness of the instance's keys.
pub fn path_segments_match_selection(selection: &[PathSegment], instance: &[PathSegment]) -> bool {
    selection.len() == instance.len()
        && selection.iter().zip(instance).all(|(selected, actual)| {
            selected.name == actual.name
                && selected.keys.iter().all(|key| actual.keys.contains(key))
        })
}
