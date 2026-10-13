//! Bounded list-key equalities for generated configuration projection.
//!
//! This deliberately does not implement arbitrary XPath expressions. Values
//! are literals (XPath 1.0 quoting), and every predicate names a real list key.

use opc_mgmt_schema::{NetconfKeyPredicate, NodeKind};

use super::*;

/// Separates schema selection from instance matching. Callers must authorize
/// the schema selection before passing these predicates to a renderer.
pub(crate) fn prepare_read_filter(
    registry: &'static dyn SchemaRegistry,
    filter: Option<&Filter>,
    limits: &MgmtLimits,
    supported: bool,
) -> Result<(Option<Filter>, Vec<NetconfKeyPredicate>), FilterError> {
    let Some(Filter::XPath(xpath)) = filter else {
        return Ok((filter.cloned(), Vec::new()));
    };
    limits.check_xpath_filter_bytes(xpath.select().len())?;
    if !xpath.select().contains('[') {
        return Ok((filter.cloned(), Vec::new()));
    }
    if !supported {
        return Err(FilterError::UnsupportedXPath);
    }
    let mut rest = xpath.select().trim();
    let mut schema = String::new();
    let mut predicates = Vec::new();
    while !rest.is_empty() {
        rest = rest
            .strip_prefix('/')
            .ok_or(FilterError::UnsupportedXPath)?;
        let end = rest.find(['/', '[']).unwrap_or(rest.len());
        let name = &rest[..end];
        if !matches!(parse_xpath_step(name, xpath)?, XPathStep::Name { .. }) {
            return Err(FilterError::UnsupportedXPath);
        }
        schema.push('/');
        schema.push_str(name);
        rest = &rest[end..];
        while let Some(predicate) = rest.strip_prefix('[') {
            let (key, literal) = predicate
                .split_once('=')
                .ok_or(FilterError::UnsupportedXPath)?;
            let key = key.trim();
            if !matches!(parse_xpath_step(key, xpath)?, XPathStep::Name { .. }) {
                return Err(FilterError::UnsupportedXPath);
            }
            let literal = literal.trim_start();
            let quote = literal.chars().next().ok_or(FilterError::InvalidXPath)?;
            if !matches!(quote, '\'' | '"') {
                return Err(FilterError::UnsupportedXPath);
            }
            let (value, tail) = literal[1..]
                .split_once(quote)
                .ok_or(FilterError::InvalidXPath)?;
            rest = tail
                .trim_start()
                .strip_prefix(']')
                .ok_or(FilterError::UnsupportedXPath)?;

            let list_selection = parse_xpath_location_path(&schema, xpath, &mut 0, limits)?;
            let lists = resolve_xpath_selection_paths(registry, &list_selection)?;
            let [list_path] = lists.as_slice() else {
                return Err(FilterError::UnsupportedXPath);
            };
            let list = registry.node(list_path).ok_or(FilterError::UnknownNode)?;
            if list.kind != NodeKind::List || !list.config {
                return Err(FilterError::UnsupportedXPath);
            }
            let key_selection =
                parse_xpath_location_path(&format!("{schema}/{key}"), xpath, &mut 0, limits)?;
            let keys = resolve_xpath_selection_paths(registry, &key_selection)?;
            let [key_path] = keys.as_slice() else {
                return Err(FilterError::UnsupportedXPath);
            };
            let key_node = registry.node(key_path).ok_or(FilterError::UnknownNode)?;
            let name = key_path.rsplit('/').next().unwrap_or_default();
            if key_node.kind != NodeKind::Leaf
                || !list.key_leaves.iter().any(|key| {
                    if key.contains(':') {
                        *key == name
                    } else {
                        key_node.module == list.module && name.rsplit(':').next() == Some(*key)
                    }
                })
            {
                return Err(FilterError::UnsupportedXPath);
            }
            predicates.push(NetconfKeyPredicate {
                list_path,
                key_path,
                value: value.to_string(),
            });
            limits.check_paths(predicates.len())?;
        }
    }
    // The ordinary parser still checks the full segment budget. Predicates are
    // supported for configuration projection; opaque operational payloads need
    // a provider-specific instance selector and must never be silently widened.
    let normalized = XPathFilter::new(schema, xpath.namespaces().clone());
    for selection in parse_xpath_filter(&normalized, limits)? {
        for path in resolve_xpath_selection_paths(registry, &selection)? {
            if registry.nodes().iter().any(|node| {
                !node.config
                    && (node.path == path
                        || node
                            .path
                            .strip_prefix(path)
                            .is_some_and(|suffix| suffix.starts_with('/')))
            }) {
                return Err(FilterError::UnsupportedXPath);
            }
        }
    }
    Ok((Some(Filter::XPath(normalized)), predicates))
}
