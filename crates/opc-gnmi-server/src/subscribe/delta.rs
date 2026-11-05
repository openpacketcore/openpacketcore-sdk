//! Diffs authorized snapshots without treating omitted data as a full subtree.

use std::collections::BTreeMap;

use prost::Message;

use super::{gnmi, now_nanos};

pub(super) fn snapshot_delta(
    previous: &[gnmi::SubscribeResponse],
    current: &[gnmi::SubscribeResponse],
    force: bool,
) -> (Vec<gnmi::SubscribeResponse>, bool) {
    let before = values(previous);
    let after = values(current);
    let changed = before.len() != after.len()
        || after
            .iter()
            .any(|(key, value)| !before.get(key).is_some_and(|old| same_value(old, value)));
    let mut result = Vec::new();
    for response in current {
        let Some(gnmi::subscribe_response::Response::Update(mut notification)) =
            response.response.clone()
        else {
            continue;
        };
        if !force {
            notification.update.retain(|update| {
                let key = snapshot_key(notification.prefix.as_ref(), update.path.as_ref());
                !before.get(&key).is_some_and(|old| same_value(old, update))
            });
        }
        notification.atomic = false;
        if !notification.update.is_empty() || !notification.delete.is_empty() {
            result.push(gnmi::SubscribeResponse {
                response: Some(gnmi::subscribe_response::Response::Update(notification)),
                extension: response.extension.clone(),
            });
        }
    }

    // Heartbeats also carry deletions: a forced refresh must not advance the
    // baseline past a removal before a queued ON_CHANGE event is processed.
    let observed_at = current
        .iter()
        .find_map(|response| match &response.response {
            Some(gnmi::subscribe_response::Response::Update(notification)) => {
                Some(notification.timestamp)
            }
            _ => None,
        })
        .unwrap_or_else(now_nanos);
    for response in previous {
        let Some(gnmi::subscribe_response::Response::Update(notification)) = &response.response
        else {
            continue;
        };
        let delete: Vec<_> = notification
            .update
            .iter()
            .filter(|update| {
                !after.contains_key(&snapshot_key(
                    notification.prefix.as_ref(),
                    update.path.as_ref(),
                ))
            })
            .map(|update| update.path.clone().unwrap_or_default())
            .collect();
        if !delete.is_empty() {
            result.push(gnmi::SubscribeResponse {
                response: Some(gnmi::subscribe_response::Response::Update(
                    gnmi::Notification {
                        timestamp: observed_at,
                        prefix: notification.prefix.clone(),
                        update: Vec::new(),
                        delete,
                        atomic: false,
                    },
                )),
                extension: response.extension.clone(),
            });
        }
    }
    (result, changed)
}

#[allow(deprecated)]
fn same_value(left: &gnmi::Update, right: &gnmi::Update) -> bool {
    left.val == right.val && left.value == right.value
}

fn values(responses: &[gnmi::SubscribeResponse]) -> BTreeMap<Vec<u8>, &gnmi::Update> {
    let mut result = BTreeMap::new();
    for response in responses {
        if let Some(gnmi::subscribe_response::Response::Update(notification)) = &response.response {
            for update in &notification.update {
                result.insert(
                    snapshot_key(notification.prefix.as_ref(), update.path.as_ref()),
                    update,
                );
            }
        }
    }
    result
}

// HashMap iteration order must not change path identity. Combine the prefix
// and relative path, then encode every key in lexical order with boundaries.
#[allow(deprecated)]
pub(super) fn snapshot_key(prefix: Option<&gnmi::Path>, path: Option<&gnmi::Path>) -> Vec<u8> {
    let mut full = prefix.cloned().unwrap_or_default();
    if let Some(path) = path {
        full.element.extend(path.element.iter().cloned());
        full.elem.extend(path.elem.iter().cloned());
        if !path.origin.is_empty() {
            full.origin.clone_from(&path.origin);
        }
        if !path.target.is_empty() {
            full.target.clone_from(&path.target);
        }
    }
    let mut keys = Vec::new();
    for element in &mut full.elem {
        let mut entries: Vec<_> = element.key.iter().collect();
        entries.sort_unstable_by_key(|(name, _)| *name);
        keys.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for (name, value) in entries {
            for text in [name, value] {
                keys.extend_from_slice(&(text.len() as u64).to_le_bytes());
                keys.extend_from_slice(text.as_bytes());
            }
        }
        element.key.clear();
    }
    let mut result = full.encode_length_delimited_to_vec();
    result.extend_from_slice(&(keys.len() as u64).to_le_bytes());
    result.extend_from_slice(&keys);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> gnmi::SubscribeResponse {
        gnmi::SubscribeResponse {
            response: Some(gnmi::subscribe_response::Response::Update(
                gnmi::Notification {
                    timestamp: 1,
                    prefix: Some(gnmi::Path {
                        origin: "origin".into(),
                        target: "target".into(),
                        elem: vec![gnmi::PathElem {
                            name: "list".into(),
                            key: [("name".into(), "literal['key']".into())].into(),
                        }],
                        ..Default::default()
                    }),
                    update: ["first", "second"]
                        .into_iter()
                        .map(|leaf| gnmi::Update {
                            path: Some(gnmi::Path {
                                elem: vec![gnmi::PathElem {
                                    name: leaf.into(),
                                    key: Default::default(),
                                }],
                                ..Default::default()
                            }),
                            val: Some(gnmi::TypedValue {
                                value: Some(gnmi::typed_value::Value::StringVal(leaf.into())),
                            }),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        }
    }

    #[test]
    fn delta_and_heartbeat_preserve_prefix_identity_and_removed_paths() {
        let original = response();
        let mut current = original.clone();
        let Some(gnmi::subscribe_response::Response::Update(notification)) = &mut current.response
        else {
            unreachable!()
        };
        notification.update.remove(0);
        notification.timestamp = 2;
        let (changes, changed) = snapshot_delta(
            std::slice::from_ref(&original),
            std::slice::from_ref(&current),
            false,
        );
        assert!(changed);
        assert_eq!(changes.len(), 1);
        let Some(gnmi::subscribe_response::Response::Update(deleted)) = &changes[0].response else {
            unreachable!()
        };
        assert_eq!(deleted.timestamp, 2);
        assert!(!deleted.atomic);
        assert!(deleted.update.is_empty());
        assert_eq!(deleted.delete[0].elem[0].name, "first");
        let Some(prefix) = &deleted.prefix else {
            panic!("deleted paths must retain their original prefix")
        };
        assert_eq!(prefix.origin, "origin");
        assert_eq!(prefix.target, "target");
        assert_eq!(prefix.elem[0].key["name"], "literal['key']");
        let (heartbeat, _) = snapshot_delta(
            std::slice::from_ref(&original),
            std::slice::from_ref(&current),
            true,
        );
        assert_eq!(
            heartbeat.len(),
            2,
            "forced refresh retains both current values and deletions"
        );
        let (unchanged, changed) = snapshot_delta(
            std::slice::from_ref(&current),
            std::slice::from_ref(&current),
            false,
        );
        assert!(!changed);
        assert!(unchanged.is_empty());
    }
}
