mod evidence_common;
use evidence_common::*;

#[test]
fn test_gap_006_003_provenance() {
    let subjects = vec![ProvenanceSubject {
        name: "opc-evidence-bin".to_string(),
        digest: ProvenanceDigest {
            sha256: "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff".to_string(),
        },
    }];
    let git_commit = "abcdef0123456789abcdef0123456789abcdef01".to_string();
    let builder_id = "https://github.com/openpacketcore/builder".to_string();
    let build_command = vec![
        "cargo".to_string(),
        "build".to_string(),
        "--release".to_string(),
    ];
    let materials = vec![ProvenanceMaterial {
        uri: "git+https://github.com/openpacketcore/openpacketcore-sdk".to_string(),
        digest: ProvenanceDigest {
            sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        },
    }];

    let ts = "2026-06-08T12:00:00Z".to_string();

    let prov1 = generate_provenance(
        subjects.clone(),
        git_commit.clone(),
        false,
        builder_id.clone(),
        build_command.clone(),
        materials.clone(),
        "0.1.0".to_string(),
        "0.1.0".to_string(),
        ts.clone(),
    )
    .unwrap();

    let prov2 = generate_provenance(
        subjects.clone(),
        git_commit.clone(),
        false,
        builder_id.clone(),
        build_command.clone(),
        materials.clone(),
        "0.1.0".to_string(),
        "0.1.0".to_string(),
        ts.clone(),
    )
    .unwrap();

    assert_eq!(prov1, prov2);

    let different_subjects = vec![ProvenanceSubject {
        name: "opc-evidence-bin".to_string(),
        digest: ProvenanceDigest {
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        },
    }];
    let prov3 = generate_provenance(
        different_subjects,
        git_commit.clone(),
        false,
        builder_id.clone(),
        build_command.clone(),
        materials.clone(),
        "0.1.0".to_string(),
        "0.1.0".to_string(),
        ts.clone(),
    )
    .unwrap();

    assert_ne!(prov1, prov3);

    let prov_dirty = generate_provenance(
        subjects,
        git_commit,
        true,
        builder_id,
        build_command,
        materials,
        "0.1.0".to_string(),
        "0.1.0".to_string(),
        ts,
    )
    .unwrap();

    assert!(prov_dirty.predicate.invocation.environment.worktree_dirty);
}
