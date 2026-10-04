//! Regressions for the PR 830 catalog trust boundary.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use opc_n3iwf_fixtures::FixtureCatalog;
use serde_json::{json, Value};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "adversarial-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        copy(&FixtureCatalog::fixture_root(), &root);
        Self(root)
    }

    fn edit(&self, path: &str, edit: impl FnOnce(&mut Value)) {
        let path = self.0.join(path);
        let mut value =
            serde_json::from_slice(&fs::read(&path).expect("read fixture")).expect("json");
        edit(&mut value);
        fs::write(path, serde_json::to_vec_pretty(&value).expect("encode")).expect("write fixture");
    }

    fn rejected(&self) {
        assert!(
            FixtureCatalog::load_from(&self.0)
                .and_then(|catalog| catalog.detect())
                .is_err(),
            "invalid catalog was accepted"
        );
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn copy(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("directory");
    for entry in fs::read_dir(source).expect("entries") {
        let entry = entry.expect("entry");
        let dest = target.join(entry.file_name());
        if entry.path().is_dir() {
            copy(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).expect("copy");
        }
    }
}

#[test]
fn public_debug_surfaces_redact_loaded_values() {
    let catalog = FixtureCatalog::load().expect("catalog");
    assert!(
        format!("{catalog:?}") == "FixtureCatalog(<redacted>)",
        "catalog Debug exposed fields"
    );
    for (manifest, _) in catalog.manifests() {
        assert!(format!("{manifest:?}") == "FixtureManifest(<redacted>)");
        assert!(format!("{:?}", manifest.provenance) == "Provenance(<redacted>)");
        assert!(format!("{:?}", manifest.wire) == "WireRef(<redacted>)");
    }
}

#[test]
fn subset_load_does_not_require_siblings_and_validates_its_own_bytes() {
    let root = Scratch::new();
    for subset in opc_n3iwf_fixtures::SUBSETS {
        if *subset != "nas-tcp" {
            fs::remove_dir_all(root.0.join(subset)).expect("remove sibling");
        }
    }
    let catalog = FixtureCatalog::load_subset_from(&root.0, "nas-tcp").expect("independent subset");
    assert_eq!(catalog.completions().len(), 1);
    assert!(catalog
        .manifests()
        .all(|(manifest, _)| manifest.subset == "nas-tcp"));
    fs::remove_dir_all(root.0.join("nas-tcp")).expect("remove source");
    catalog
        .detect()
        .expect("immutable validated snapshot needs no filesystem reread");
    assert!(FixtureCatalog::load_subset_from(&root.0, "nas-tcp").is_err());
    assert!(FixtureCatalog::load_subset_from(&root.0, "../nas-tcp").is_err());
}

#[test]
fn oversized_files_fail_before_json_or_wire_decoding() {
    for path in [
        "nas-tcp/positive-envelope.json",
        "nas-tcp/wire/positive-envelope.hex",
    ] {
        let root = Scratch::new();
        fs::write(root.0.join(path), vec![b' '; 256 * 1024 + 1]).expect("oversized file");
        root.rejected();
    }
}

#[test]
fn release_matrix_presence_and_criticality_cannot_drift() {
    for (field, value) in [("presence", "optional"), ("criticality", "ignore")] {
        let root = Scratch::new();
        root.edit("ngap/matrices/ng-setup-request.json", |matrix| {
            matrix["ies"][0][field] = json!(value)
        });
        root.rejected();
    }
}

#[test]
fn completion_sets_cannot_hide_missing_entries_with_duplicates() {
    let root = Scratch::new();
    root.edit("ngap/COMPLETION.json", |m| {
        m["admitted_outcomes"][0] = m["admitted_outcomes"][1].clone()
    });
    root.rejected();
    let root = Scratch::new();
    root.edit("nas-tcp/COMPLETION.json", |m| {
        let first = m["case_classes"][0].clone();
        m["case_classes"]
            .as_array_mut()
            .expect("classes")
            .push(first);
    });
    root.rejected();
}

#[test]
fn matrix_cannot_link_a_different_procedure_even_with_matching_octets() {
    let root = Scratch::new();
    root.edit("ngap/matrices/ng-setup-request.json", |m| {
        m["procedure_code"] = json!(14);
        m["direction"] = json!("amf-to-n3iwf");
        m["wire_fixture_id"] =
            json!("opc.n3iwf.ngap.v1.receive-empty-initial-context-setup-request");
    });
    root.rejected();
}

#[test]
fn load_rejects_invalid_digest_before_exposing_bytes() {
    let root = Scratch::new();
    root.edit("nas-tcp/positive-envelope.json", |m| {
        m["wire"]["digest_sha256"] = json!("0".repeat(64))
    });
    assert!(
        FixtureCatalog::load_from(&root.0).is_err(),
        "load must validate its documented invariants"
    );
}

#[test]
fn decoded_json_is_scanned_instead_of_escaped_source_text() {
    let root = Scratch::new();
    let path = root.0.join("nas-tcp/positive-envelope.json");
    let raw = fs::read_to_string(&path).expect("read");
    let mut value: Value = serde_json::from_str(&raw).expect("json");
    value["provenance"]["notes"] = json!("PRIVATE KEY");
    let encoded = serde_json::to_string(&value)
        .expect("encode")
        .replace("PRIVATE KEY", "\\u0050RIVATE KEY");
    fs::write(path, encoded).expect("write");
    root.rejected();
}

#[test]
fn duplicate_json_keys_cannot_hide_escaped_unreviewed_content() {
    let root = Scratch::new();
    let path = root.0.join("nas-tcp/positive-envelope.json");
    let raw = fs::read_to_string(&path).expect("read");
    let altered = raw.replace(
        "\"context\": {",
        "\"context\": {\"hidden\": \"\\u0050RIVATE KEY\", \"hidden\": \"synthetic\",",
    );
    assert_ne!(raw, altered);
    fs::write(path, altered).expect("write");
    root.rejected();
}

#[test]
fn wire_path_cannot_escape_its_subset() {
    let root = Scratch::new();
    root.edit("nas-tcp/positive-envelope.json", |m| {
        m["wire"]["path"] = json!("../nas-tcp/wire/positive-envelope.hex");
    });
    root.rejected();
}

#[cfg(unix)]
#[test]
fn symlinked_wire_is_rejected() {
    let root = Scratch::new();
    let path = root.0.join("nas-tcp/wire/positive-envelope.hex");
    fs::remove_file(&path).expect("unlink");
    std::os::unix::fs::symlink(
        FixtureCatalog::fixture_root().join("nas-tcp/wire/positive-envelope.hex"),
        path,
    )
    .expect("symlink");
    root.rejected();
}

#[test]
fn empty_wire_with_correct_digest_is_rejected() {
    let root = Scratch::new();
    fs::write(root.0.join("nas-tcp/wire/positive-envelope.hex"), "\n").expect("write");
    root.edit("nas-tcp/positive-envelope.json", |m| {
        m["wire"]["digest_sha256"] = json!(opc_n3iwf_fixtures::wire_digest(b""))
    });
    root.rejected();
}

#[test]
fn unknown_fields_and_empty_inventory_entries_are_rejected() {
    let root = Scratch::new();
    root.edit("nas-tcp/positive-envelope.json", |m| {
        m["unreviewed_payload"] = json!("unreviewed")
    });
    root.rejected();
    let root = Scratch::new();
    root.edit("nas-tcp/positive-envelope.json", |m| {
        m["sanitized_fields"] = json!([{"name":"", "treatment":"", "value_class":""}])
    });
    root.rejected();
}

#[test]
fn duplicate_matrix_rows_are_rejected() {
    let root = Scratch::new();
    root.edit("ngap/matrices/ng-setup-request.json", |m| {
        let row = m["ies"][0].clone();
        m["ies"].as_array_mut().expect("rows").push(row);
    });
    root.rejected();
}

#[test]
fn matrix_requires_exact_completion_membership_and_wire_reference() {
    let root = Scratch::new();
    root.edit("ngap/COMPLETION.json", |m| {
        m["matrices"][0] = json!("matrices/nonexistent.json")
    });
    root.rejected();
    let root = Scratch::new();
    root.edit("ngap/matrices/ng-setup-request.json", |m| {
        m.as_object_mut().expect("object").remove("wire_fixture_id");
    });
    root.rejected();
}
