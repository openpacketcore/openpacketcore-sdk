//! Failing detector, fix-removal, and adversarial mutation for issue 784.

use std::fs;
use std::path::PathBuf;

use opc_n3iwf_fixtures::{
    ContractErrorCode, FixtureCatalog, FixtureManifest, REQUIRED_CASE_CLASSES,
};

fn scratch_copy() -> PathBuf {
    let src = FixtureCatalog::fixture_root();
    let dest = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "n3iwf-fixtures-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0)
    ));
    copy_dir(&src, &dest);
    dest
}

fn copy_dir(src: &std::path::Path, dest: &std::path::Path) {
    fs::create_dir_all(dest).expect("scratch dir");
    for entry in fs::read_dir(src).expect("read src") {
        let entry = entry.expect("entry");
        let to = dest.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), to).expect("copy");
        }
    }
}

#[test]
fn detector_is_green_on_committed_tree() {
    FixtureCatalog::load()
        .expect("load")
        .detect()
        .expect("committed detector is green");
}

#[test]
fn fix_removal_of_required_case_class_fails_detector() {
    let root = scratch_copy();
    let eap5g = root.join("eap5g");
    for entry in fs::read_dir(&eap5g).expect("eap5g") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("COMPLETION.json") {
            continue;
        }
        let raw = fs::read_to_string(&path).expect("manifest");
        if raw.contains("\"case_class\": \"truncation\"") {
            fs::remove_file(&path).expect("remove truncation manifest");
        }
    }
    let completion_path = eap5g.join("COMPLETION.json");
    let completion_raw = fs::read_to_string(&completion_path).expect("completion");
    let mut completion: opc_n3iwf_fixtures::SubsetCompletion =
        serde_json::from_str(&completion_raw).expect("completion json");
    completion
        .case_classes
        .retain(|value| value != "truncation");
    completion
        .fixture_ids
        .retain(|value| !value.contains("truncated"));
    fs::write(
        &completion_path,
        serde_json::to_string_pretty(&completion).expect("encode completion"),
    )
    .expect("rewrite completion");
    let catalog = FixtureCatalog::load_from(&root);
    match catalog {
        Ok(catalog) => {
            let err = catalog.detect().expect_err("removal must fail");
            assert_eq!(err.code(), ContractErrorCode::IncompleteSubset);
        }
        Err(err) => {
            assert_eq!(err.code(), ContractErrorCode::IncompleteSubset);
        }
    }
    assert!(REQUIRED_CASE_CLASSES.contains(&"truncation"));
}

#[test]
fn adversarial_digest_mutation_fails_detector() {
    let root = scratch_copy();
    let wire = root.join("gre-qfi/wire/positive-downlink-rqi.hex");
    let original = fs::read_to_string(&wire).expect("wire");
    fs::write(&wire, "ff ff ff ff\n").expect("mutate");
    let err = FixtureCatalog::load_from(&root)
        .and_then(|catalog| catalog.detect())
        .expect_err("mutated digest must fail");
    assert_eq!(err.code(), ContractErrorCode::DigestMismatch);
    assert_ne!(original.trim(), "ff ff ff ff");
}

#[test]
fn runtime_claim_true_is_rejected() {
    let root = scratch_copy();
    let path = root.join("n2-sctp/positive-ppid60-port.json");
    let raw = fs::read_to_string(&path).expect("manifest");
    let mutated = raw.replace("\"runtime_claim\": false", "\"runtime_claim\": true");
    fs::write(&path, mutated).expect("write");
    let err = FixtureCatalog::load_from(&root)
        .and_then(|catalog| catalog.detect())
        .expect_err("runtime claim must fail");
    assert_eq!(err.code(), ContractErrorCode::RuntimeClaimForbidden);
}

#[test]
fn personal_name_in_notes_is_rejected() {
    let root = scratch_copy();
    let path = root.join("nas-tcp/positive-envelope.json");
    let mut manifest: FixtureManifest =
        serde_json::from_str(&fs::read_to_string(&path).expect("manifest")).expect("json");
    manifest.provenance.notes = "reviewed by a forbidden personal name token".to_string();
    // The detector scans file text, so write a forbidden token that is not a
    // product name.
    let raw = serde_json::to_string_pretty(&manifest).expect("encode");
    let token: String = [65u8, 97, 114, 111, 110]
        .into_iter()
        .map(char::from)
        .collect();
    fs::write(&path, raw.replace("forbidden personal name token", &token)).expect("write");
    let err = FixtureCatalog::load_from(&root)
        .and_then(|catalog| catalog.detect())
        .expect_err("personal name must fail");
    assert_eq!(err.code(), ContractErrorCode::ForbiddenContent);
}
