use std::cell::Cell;

use generated_ordered_test::{collections as model, defaults};
use model::patch::{apply_patch, ConfigDelta, OrderedListReplacement};
use model::types::{LeafPresence, Root};
use opc_config_model::{ConfigError, OpcConfig, YangPath};
use opc_gnmi_server::{GnmiJsonRenderer, ReadSelection, ReadSelectionEntry};
use opc_mgmt_schema::{DefaultReport, NetconfXmlRenderer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn path(value: &str) -> YangPath {
    YangPath::new(value).unwrap()
}

fn root(names: &[&str]) -> Root {
    serde_json::from_value(json!({"server": names.iter()
        .map(|name| json!({"name":name,"port":53})).collect::<Vec<_>>()}))
    .unwrap()
}

fn names(value: &Root) -> Vec<&str> {
    value.server.keys().map(String::as_str).collect()
}

#[test]
fn collection_update_and_merge_preserve_unmentioned_rows_and_append_new_keys() {
    for delta in [ConfigDelta::Update, ConfigDelta::Merge] {
        let mut value = root(&["z", "a", "m"]);
        apply_patch(
            &mut value,
            &[delta(
                path("/oc:root/oc:server"),
                json!([{"name":"z","port":853},{"name":"n","port":5353}]).to_string(),
            )],
        )
        .unwrap();
        assert_eq!(names(&value), ["z", "a", "m", "n"]);
        assert_eq!(
            value.server.get("z").unwrap().port,
            LeafPresence::Explicit(853)
        );
        assert_eq!(
            value.server.get("a").unwrap().port,
            LeafPresence::Explicit(53)
        );
        assert_eq!(
            value.server.get("m").unwrap().port,
            LeafPresence::Explicit(53)
        );
        assert_eq!(
            value.server.get("n").unwrap().port,
            LeafPresence::Explicit(5353)
        );
    }
}

#[test]
fn collection_delete_and_remove_clear_every_row() {
    for delta in [ConfigDelta::Delete, ConfigDelta::Remove] {
        let mut value = root(&["z", "a", "m"]);
        apply_patch(&mut value, &[delta(path("/oc:root/oc:server"))]).unwrap();
        assert!(value.server.is_empty());
        assert_eq!(serde_json::to_value(value).unwrap(), json!({}));
    }
}

#[test]
fn keyed_lookup_and_mutation_stay_consistent_after_removal_and_compaction() {
    let mut value = root(&["z", "a", "m"]);
    apply_patch(&mut value, &[ConfigDelta::Delete(path("/oc:root/oc:server[name='z']"))])
        .unwrap();
    for key in ["a", "m"] {
        assert_eq!(value.server.get(key).unwrap().name, LeafPresence::Explicit(key.into()));
    }
    value.server.get_mut("a").unwrap().port = LeafPresence::Explicit(5353);
    assert_eq!(
        value.server.values().map(|row| row.port.clone()).collect::<Vec<_>>(),
        [LeafPresence::Explicit(5353), LeafPresence::Explicit(53)]
    );

    // More than half the slots are now dead, so an implementation with lazy
    // removal can compact. The remaining row must still have the right index.
    value.server.remove("a").unwrap();
    assert_eq!(names(&value), ["m"]);
    assert_eq!(value.server.get("m").unwrap().name, LeafPresence::Explicit("m".into()));
    value.server.get_mut("m").unwrap().port = LeafPresence::Explicit(853);
    value.server.entry("m".into()).or_default().port = LeafPresence::Explicit(5354);
    assert_eq!(value.server.values().next().unwrap().port, LeafPresence::Explicit(5354));
    assert!(!value.server.contains_key("z"));
    assert!(!value.server.contains_key("a"));
    assert!(value.server.remove("absent").is_none());
    value.server.remove("m").unwrap();
    assert!(value.server.is_empty());
    let row = root(&["z"]).server.remove("z").unwrap();
    value.server.insert("z".into(), row).unwrap();
    assert_eq!(names(&value), ["z"]);
    assert_eq!(value.server.get("z").unwrap().name, LeafPresence::Explicit("z".into()));
}

#[test]
fn clearing_a_collection_removes_its_key_index() {
    let mut value = root(&["z", "a"]);
    apply_patch(&mut value, &[ConfigDelta::Delete(path("/oc:root/oc:server"))]).unwrap();
    assert!(!value.server.contains_key("z"));
    assert!(value.server.get("z").is_none());
    let row = root(&["z"]).server.remove("z").unwrap();
    assert_eq!(value.server.insert("z".into(), row), Ok(()));
    assert_eq!(names(&value), ["z"]);
}

#[test]
fn reinserting_a_removed_key_appends_instead_of_reusing_its_position() {
    let mut value = root(&["z", "a", "m"]);
    let removed = value.server.remove("z").unwrap();
    value.server.insert("z".into(), removed).unwrap();
    assert_eq!(names(&value), ["a", "m", "z"]);
    for key in ["a", "m", "z"] {
        assert_eq!(value.server.get(key).unwrap().name, LeafPresence::Explicit(key.into()));
    }
    value.server.remove("m").unwrap();
    value.server.entry("m".into()).or_default().name = LeafPresence::Explicit("m".into());
    assert_eq!(names(&value), ["a", "z", "m"]);
}

#[test]
fn equality_includes_row_order_but_not_removed_slots() {
    assert_ne!(root(&["z", "a"]), root(&["a", "z"]));
    assert_ne!(root(&["z", "a"]).server, root(&["a", "z"]).server);
    let mut removed = root(&["z", "a", "m"]);
    removed.server.remove("a").unwrap();
    let fresh = root(&["z", "m"]);
    assert_eq!(removed, fresh);
    let expected_debug = format!("{{{:?}: {:?}, {:?}: {:?}}}",
        "z", removed.server.get("z").unwrap(), "m", removed.server.get("m").unwrap());
    assert_eq!(format!("{:?}", removed.server), expected_debug);
    assert_eq!(format!("{:?}", removed.server), format!("{:?}", fresh.server));
    assert_eq!(format!("{:?}", removed.server), format!("{:?}", removed.server.clone()));
}

#[test]
fn ordered_iterators_count_only_remaining_live_rows() {
    let mut value = root(&["z", "a", "m", "n"]);
    value.server.remove("a").unwrap();
    value.server.remove("n").unwrap();
    assert_eq!(value.server.len(), 2);
    {
        let mut keys = value.server.keys();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.size_hint(), (2, Some(2)));
        assert_eq!(keys.next().map(String::as_str), Some("z"));
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.next().map(String::as_str), Some("m"));
        assert_eq!(keys.len(), 0);
        assert_eq!(keys.next(), None);
    }
    assert_eq!(value.server.values().len(), 2);
    {
        let mut rows = value.server.values_mut();
        assert_eq!(rows.len(), 2);
        rows.next().unwrap().port = LeafPresence::Explicit(853);
        assert_eq!(rows.len(), 1);
        rows.next().unwrap().port = LeafPresence::Explicit(5353);
        assert_eq!(rows.len(), 0);
        assert!(rows.next().is_none());
    }
    {
        let mut borrowed = (&value.server).into_iter();
        assert_eq!(borrowed.len(), 2);
        assert_eq!(borrowed.next().unwrap().0, "z");
        assert_eq!(borrowed.len(), 1);
        assert_eq!(borrowed.next().unwrap().0, "m");
        assert_eq!(borrowed.len(), 0);
        assert!(borrowed.next().is_none());
    }
    let wire = serde_json::to_value(&value).unwrap();
    assert_eq!(wire, json!({"ordered-collections:server":[
        {"name":"z","port":853}, {"name":"m","port":5353}
    ]}));
    let mut owned = value.server.into_iter();
    assert_eq!(owned.len(), 2);
    assert_eq!(owned.next().unwrap().0, "z");
    assert_eq!(owned.len(), 1);
    assert_eq!(owned.next().unwrap().0, "m");
    assert_eq!(owned.len(), 0);
    assert!(owned.next().is_none());

    let mut sparse = root(&["z", "a", "m", "n"]);
    sparse.server.remove("z").unwrap();
    sparse.server.remove("m").unwrap();
    {
        let mut borrowed = (&sparse.server).into_iter();
        assert_eq!(borrowed.next_back().unwrap().0, "n");
        assert_eq!(borrowed.len(), 1);
        assert_eq!(borrowed.next().unwrap().0, "a");
        assert_eq!(borrowed.len(), 0);
        assert!(borrowed.next_back().is_none());
    }
    let mut owned = sparse.server.into_iter();
    assert_eq!(owned.next_back().unwrap().0, "n");
    assert_eq!(owned.len(), 1);
    assert_eq!(owned.next().unwrap().0, "a");
    assert_eq!(owned.len(), 0);
    assert!(owned.next_back().is_none());
}

#[test]
fn typed_ordered_replacement_refuses_invalid_rows_and_wrong_targets_atomically() {
    let initial = root(&["z", "a"]);
    for (target, expected) in [
        ("/oc:root/oc:endpoint", ConfigError::new(
            "invalid-value", "ordered-list replacement type does not match its path")),
        ("/oc:root/oc:server[name='z']", ConfigError::new(
            "invalid-path", "ordered-list replacement requires its collection path")),
        ("/oc:root/oc:server[name='z']/oc:port", ConfigError::new(
            "invalid-path", "ordered-list replacement requires its collection path")),
    ] {
        let mut value = initial.clone();
        let delta = ConfigDelta::ReplaceOrderedList(
            path(target), OrderedListReplacement::Server(root(&["a", "z"]).server),
        );
        assert_eq!(apply_patch(&mut value, &[delta]), Err(expected));
        assert_eq!(value, initial);
    }
    let mut duplicated = root(&["a", "z"]);
    duplicated.server.get_mut("a").unwrap().preference = vec!["same".into(), "same".into()];
    let mut missing_key = root(&["a", "z"]);
    missing_key.server.get_mut("a").unwrap().name = LeafPresence::Absent;
    let mut inconsistent_key = root(&["a", "z"]);
    inconsistent_key.server.get_mut("a").unwrap().name = LeafPresence::Explicit("other".into());
    for invalid in [duplicated, missing_key, inconsistent_key] {
        let mut value = initial.clone();
        let delta = ConfigDelta::ReplaceOrderedList(
            path("/oc:root/oc:server"), OrderedListReplacement::Server(invalid.server),
        );
        assert_eq!(
            apply_patch(&mut value, &[delta]),
            Err(ConfigError::new("invalid-value", "invalid user-ordered list")),
        );
        assert_eq!(value, initial);
    }
}

#[test]
fn collection_merge_and_update_retain_nested_system_ordered_lists() {
    for delta in [ConfigDelta::Update, ConfigDelta::Merge] {
        let mut value: Root = serde_json::from_value(json!({"server":[
            {"name":"z","port":53,"preference":["keep-unless-cleared"],"hop":[{"name":"old","cost":7},{"name":"keep","cost":11}]},
            {"name":"a","port":853}
        ]}))
        .unwrap();
        apply_patch(
            &mut value,
            &[delta(
                path("/oc:root/oc:server"),
                json!([{"name":"z","preference":[],"hop":[{"name":"old","cost":9},{"name":"new","cost":3}]}])
                    .to_string(),
            )],
        )
        .unwrap();
        assert_eq!(names(&value), ["z", "a"]);
        let row = value.server.get("z").unwrap();
        assert_eq!(row.port, LeafPresence::Explicit(53));
        assert!(row.preference.is_empty());
        assert_eq!(
            row.hop.keys().map(String::as_str).collect::<Vec<_>>(),
            ["keep", "new", "old"]
        );
        assert_eq!(
            row.hop.get("keep").unwrap().cost,
            LeafPresence::Explicit(11)
        );
        assert_eq!(row.hop.get("new").unwrap().cost, LeafPresence::Explicit(3));
        assert_eq!(row.hop.get("old").unwrap().cost, LeafPresence::Explicit(9));
    }
}

#[test]
fn nested_system_list_merge_refuses_duplicate_keys_atomically() {
    for delta in [ConfigDelta::Update, ConfigDelta::Merge] {
        let mut value = root(&["z", "a"]);
        let before = value.clone();
        assert_eq!(
            apply_patch(&mut value, &[delta(
                path("/oc:root/oc:server[name='z']/oc:hop"),
                json!([{"name":"q","cost":1},{"name":"q","cost":2}]).to_string(),
            )]),
            Err(ConfigError::new("invalid-value", "invalid keyed list"))
        );
        assert_eq!(value, before);
    }
}

#[test]
fn unrelated_system_list_keeps_its_existing_list_path_refusal() {
    for delta in [ConfigDelta::Update, ConfigDelta::Merge] {
        let mut value = root(&["z", "a"]);
        let before = value.clone();
        assert_eq!(
            apply_patch(&mut value, &[delta(
                path("/oc:root/oc:system-server"),
                json!([{"name":"q","port":1},{"name":"q","port":2}]).to_string(),
            )]),
            Err(ConfigError::new("missing-key", "missing key: name"))
        );
        assert_eq!(value, before);
    }
}

#[test]
fn diff_apply_preserves_defaulted_leaves_on_append_delete_reorder_and_mid_insert() {
    fn config(names: &[&str]) -> defaults::types::Root {
        let mut config = defaults::types::Root::default();
        for name in names {
            config
                .server
                .insert(
                    (*name).into(),
                    defaults::types::Server {
                        name: defaults::types::LeafPresence::Explicit((*name).into()),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        config
    }
    for (before, after) in [
        (vec![], vec!["z", "a"]),
        (vec!["z", "a", "m"], vec!["a", "m"]),
        (vec!["z", "a"], vec!["a", "z"]),
        (vec!["z", "a"], vec!["z", "m", "a"]),
    ] {
        let previous = config(&before);
        let current = config(&after);
        let deltas = current.diff(&previous).unwrap();
        let mut applied = previous;
        for delta in deltas {
            applied.apply_delta(delta).unwrap();
        }
        assert_eq!(applied, current, "before={before:?}, after={after:?}");
        for row in applied.server.values() {
            assert_eq!(row.port, defaults::types::LeafPresence::Defaulted(53));
        }
        let xml = defaults::netconf_xml::renderer()
            .render_running_config(
                &applied,
                defaults::paths::CONFIG_PATHS,
                DefaultReport::Explicit,
            )
            .unwrap();
        assert!(!xml.contains("<od:port>"), "{xml}");
    }
}

#[test]
fn gnmi_list_read_emits_keyed_entries_in_configured_order_with_bounded_values() {
    let value = root(&["z", "a", "m"]);
    let selected = [
        "/oc:root/oc:server",
        "/oc:root/oc:server/oc:name",
        "/oc:root/oc:server/oc:port",
    ];
    let updates = model::gnmi_json::renderer()
        .render_running_json(&value, ReadSelection::new(&selected))
        .unwrap();
    assert_eq!(
        updates
            .iter()
            .map(|update| update.path().as_str())
            .collect::<Vec<_>>(),
        [
            "/oc:root/oc:server[oc:name='z']",
            "/oc:root/oc:server[oc:name='a']",
            "/oc:root/oc:server[oc:name='m']",
        ]
    );
    for (update, name) in updates.iter().zip(["z", "a", "m"]) {
        assert_eq!(
            serde_json::from_str::<Value>(update.value_json()).unwrap(),
            json!({"name":name,"port":53})
        );
        assert!(update.value_json().len() < 32);
    }
    let large: Root = serde_json::from_value(json!({"server": (0..128).rev().map(|index| {
        json!({"name":format!("{index:03}"),"port":53})
    }).collect::<Vec<_>>()}))
    .unwrap();
    let updates = model::gnmi_json::renderer()
        .render_running_json(&large, ReadSelection::new(&selected))
        .unwrap();
    assert_eq!(updates.len(), 128);
    assert!(updates.iter().all(|update| update.value_json().len() < 32));
    assert_eq!(
        updates.first().unwrap().path().as_str(),
        "/oc:root/oc:server[oc:name='127']"
    );
    assert_eq!(
        updates.last().unwrap().path().as_str(),
        "/oc:root/oc:server[oc:name='000']"
    );
}

#[test]
fn gnmi_entry_and_leaf_reads_match_system_ordered_keyed_paths() {
    let value = root(&["z", "a"]);
    let selected = ["/oc:root/oc:server/oc:port"];
    for (canonical, expected) in [
        (
            "/oc:root/oc:server[oc:name='z']/oc:port",
            vec!["/oc:root/oc:server[oc:name='z']/oc:port"],
        ),
        (
            "/oc:root/oc:server/oc:port",
            vec![
                "/oc:root/oc:server[oc:name='z']/oc:port",
                "/oc:root/oc:server[oc:name='a']/oc:port",
            ],
        ),
    ] {
        let entries = [ReadSelectionEntry::new(selected[0], path(canonical))];
        let updates = model::gnmi_json::renderer()
            .render_running_json(&value, ReadSelection::with_entries(&selected, &entries))
            .unwrap();
        assert_eq!(
            updates
                .iter()
                .map(|update| update.path().as_str())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(updates.iter().all(|update| update.value_json() == "53"));
    }
    let selected = [
        "/oc:root/oc:server",
        "/oc:root/oc:server/oc:name",
        "/oc:root/oc:server/oc:port",
    ];
    let entries = [
        ReadSelectionEntry::new(selected[0], path("/oc:root/oc:server[oc:name='z']")),
        ReadSelectionEntry::new(selected[1], path("/oc:root/oc:server[oc:name='z']/oc:name")),
        ReadSelectionEntry::new(selected[2], path("/oc:root/oc:server[oc:name='z']/oc:port")),
    ];
    let updates = model::gnmi_json::renderer()
        .render_running_json(&value, ReadSelection::with_entries(&selected, &entries))
        .unwrap();
    assert_eq!(
        updates
            .iter()
            .map(|update| update.path().as_str())
            .collect::<Vec<_>>(),
        [
            "/oc:root/oc:server[oc:name='z']/oc:name",
            "/oc:root/oc:server[oc:name='z']/oc:port",
        ]
    );
}

#[test]
fn gnmi_empty_user_list_emits_no_value() {
    let selected = ["/oc:root/oc:server", "/oc:root/oc:server/oc:name"];
    let updates = model::gnmi_json::renderer()
        .render_running_json(&Root::default(), ReadSelection::new(&selected))
        .unwrap();
    assert!(updates.is_empty());
}

#[test]
fn gnmi_row_without_selected_children_emits_nothing() {
    let value = root(&["z", "a"]);
    let selected = ["/oc:root/oc:server"];
    let updates = model::gnmi_json::renderer()
        .render_running_json(&value, ReadSelection::new(&selected))
        .unwrap();
    assert!(updates.is_empty());
    let entries = [ReadSelectionEntry::new(selected[0], path(selected[0]))];
    let updates = model::gnmi_json::renderer()
        .render_running_json(&value, ReadSelection::with_entries(&selected, &entries))
        .unwrap();
    assert!(updates.is_empty());
}

fn endpoints(first: usize, last: usize) -> Root {
    serde_json::from_value(json!({"endpoint": (first..last)
        .map(|key| json!({"region":"region", "name":key.to_string(), "port":53}))
        .collect::<Vec<_>>()}))
        .unwrap()
}

#[test]
fn unchanged_keyed_diff_uses_linear_comparisons() {
    const ROWS: usize = 2048;
    let previous = endpoints(0, ROWS);
    let current = previous.clone();
    model::types::take_key_comparisons();
    let deltas = current.diff(&previous).unwrap();
    let comparisons = model::types::take_key_comparisons();
    assert!(deltas.is_empty());
    assert!(comparisons < 16 * ROWS, "{comparisons} comparisons for {ROWS} rows");
}

#[test]
fn bulk_deletion_through_diff_and_apply_uses_linear_comparisons() {
    const ROWS: usize = 2048;
    for deleted in [ROWS / 2, 3 * ROWS / 4, ROWS] {
        let mut previous = endpoints(0, ROWS);
        let current = endpoints(deleted, ROWS);
        model::types::take_key_comparisons();
        let deltas = current.diff(&previous).unwrap();
        let diff_comparisons = model::types::take_key_comparisons();
        assert_eq!(deltas.len(), deleted);
        assert!(deltas.iter().all(|delta| matches!(delta, ConfigDelta::Delete(_))));
        assert!(diff_comparisons < 16 * ROWS, "{diff_comparisons} diff comparisons for {ROWS} rows");
        apply_patch(&mut previous, &deltas).unwrap();
        let apply_comparisons = model::types::take_key_comparisons();
        assert!(apply_comparisons < 16 * ROWS, "{apply_comparisons} apply comparisons for {ROWS} rows, {deleted} deleted");
        assert_eq!(previous, current);
        assert_eq!(previous.endpoint.keys().map(|key| key.name.clone()).collect::<Vec<_>>(),
            (deleted..ROWS).map(|key| key.to_string()).collect::<Vec<_>>());
    }
}

#[test]
fn redacted_key_collisions_suppress_the_collection() {
    use generated_ordered_test::sensitive_keys::{redaction::{DeterministicHash, Redactable}, types};
    // Distinct u16 keys with the same truncated deterministic hash.
    assert_ne!(10427_u16, 33024_u16);
    assert_eq!(10427_u16.deterministic_hash(), 33024_u16.deterministic_hash());
    let mut value: types::Root = serde_json::from_value(json!({"account": [
        {"token":10427, "label":"first"}, {"token":33024, "label":"second"}
    ]})).unwrap();
    assert_eq!(value.account.len(), 2);
    value.redact_sensitive();
    assert!(value.account.is_empty());
    assert_eq!(serde_json::to_value(value).unwrap(), json!({}));
}

thread_local! { static COMPARISONS: Cell<usize> = const { Cell::new(0) }; }

#[derive(Debug, Clone, Eq, std::hash::Hash, Serialize, Deserialize)]
#[serde(transparent)]
struct Counted(usize);

impl PartialEq for Counted {
    fn eq(&self, other: &Self) -> bool {
        COMPARISONS.with(|count| count.set(count.get() + 1));
        self.0 == other.0
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Row {
    key: Counted,
}

impl model::serde::ExtractKey<Counted> for Row {
    fn extract_key(&self) -> Option<Counted> {
        Some(self.key.clone())
    }
}

#[test]
fn keyed_deserialization_and_lookup_use_linear_comparisons() {
    const ROWS: usize = 2048;
    COMPARISONS.with(|count| count.set(0));
    let value = json!((0..ROWS).map(|key| json!({"key":key})).collect::<Vec<_>>());
    let mut map: model::serde::UserOrderedMap<Counted, Row> =
        serde_json::from_value(value).unwrap();
    for key in 0..ROWS {
        assert_eq!(map.get(&Counted(key)).unwrap().key.0, key);
        assert!(map.contains_key(&Counted(key)));
        assert_eq!(map.get_mut(&Counted(key)).unwrap().key.0, key);
    }
    let comparisons = COMPARISONS.with(Cell::get);
    assert!(
        comparisons < 16 * ROWS,
        "{comparisons} comparisons for {ROWS} keys"
    );
}

#[test]
fn leaf_list_uniqueness_uses_linear_comparisons() {
    const VALUES: usize = 2048;
    let mut values = (0..VALUES).map(Counted).collect::<Vec<_>>();
    COMPARISONS.with(|count| count.set(0));
    assert!(!model::serde::has_duplicate_values(&values));
    values.push(Counted(0));
    assert!(model::serde::has_duplicate_values(&values));
    let comparisons = COMPARISONS.with(Cell::get);
    assert!(
        comparisons < 16 * VALUES,
        "{comparisons} comparisons for {VALUES} values"
    );
}
