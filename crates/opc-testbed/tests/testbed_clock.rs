mod testbed_common;
use testbed_common::*;

#[test]
fn deterministic_seed_default_and_explicit() {
    let yaml_default = "id: TEST-001\ntitle: minimal\nschema_version: \"0.1.0\"\ntopology:\n  nfs: {}\nsteps:\n  - kind: send_ngap\n    from: a\n    to: b\n    message: m\n";
    let s1 = Scenario::from_str(yaml_default).expect("from_str works");
    assert_eq!(s1.deterministic_seed(), 0, "default seed is 0");

    let yaml_seed = "id: TEST-002\ntitle: seeded\nschema_version: \"0.1.0\"\nseed: 42\ntopology:\n  nfs: {}\nsteps:\n  - kind: send_ngap\n    from: a\n    to: b\n    message: m\n";
    let s2 = Scenario::from_str(yaml_seed).expect("from_str with seed works");
    assert_eq!(s2.deterministic_seed(), 42, "explicit seed parsed");
}

#[test]
fn scenario_seed_schema_documents_reserved_status() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/rfc012/v1/scenario.schema.json"))
            .expect("scenario schema parses");
    let description = schema["properties"]["seed"]["description"]
        .as_str()
        .expect("seed description exists");

    assert!(description.contains("Reserved for future deterministic simulator behavior"));
    assert!(description.contains("do not consume it"));
}

#[test]
fn local_runner_records_reserved_seed_without_consuming_it() {
    let yaml_template = |seed| {
        format!(
            r#"
id: TEST-SEED-{seed}
title: reserved seed
schema_version: "0.1.0"
seed: {seed}
topology:
  nfs:
    amf: {{ simulator: amf }}
steps:
  - send_ngap:
      from: gnb
      to: amf
      message: registration
"#
        )
    };

    let scenario_a = Scenario::from_str(&yaml_template(7)).expect("seeded scenario parses");
    let scenario_b = Scenario::from_str(&yaml_template(99)).expect("seeded scenario parses");

    let mut runner_a = LocalRunner::new(VirtualClock::new(opc_types::Timestamp::now_utc()));
    let mut runner_b = LocalRunner::new(VirtualClock::new(opc_types::Timestamp::now_utc()));
    let evidence_a = runner_a.run(&scenario_a).expect("first scenario runs");
    let evidence_b = runner_b.run(&scenario_b).expect("second scenario runs");

    assert_eq!(evidence_a.seed, Some(7));
    assert_eq!(evidence_b.seed, Some(99));
    assert_eq!(runner_a.state, runner_b.state);
}

#[test]
fn virtual_clock_advances_deterministically() {
    let start = opc_types::Timestamp::now_utc();
    let mut clock = VirtualClock::new(start);

    let t0 = clock.now();
    let m0 = clock.monotonic();

    clock.advance(time::Duration::seconds(5));

    let t1 = clock.now();
    let m1 = clock.monotonic();

    let delta = (*t1.as_offset_datetime() - *t0.as_offset_datetime()).whole_seconds();
    assert_eq!(delta, 5);

    assert!(m1 > m0, "monotonic must advance with virtual time");

    clock.reset_to(start);
    assert_eq!(clock.now(), start);
}

#[test]
#[should_panic(expected = "virtual clock cannot go backwards")]
fn virtual_clock_rejects_negative_advance() {
    let start = opc_types::Timestamp::now_utc();
    let mut clock = VirtualClock::new(start);
    clock.advance(time::Duration::seconds(-1));
}

#[test]
fn virtual_clock_monotonic_extreme_advance_does_not_panic() {
    let start = opc_types::Timestamp::now_utc();
    let mut clock = VirtualClock::new(start);
    clock.advance(time::Duration::days(220_000));
    let _ = clock.monotonic();
    assert_eq!(clock.monotonic_elapsed().as_secs(), 220_000 * 24 * 60 * 60);
}

#[test]
fn virtual_clock_monotonic_matches_identical_advance_sequences() {
    let start = opc_types::Timestamp::now_utc();
    let mut first = VirtualClock::new(start);
    let mut second = VirtualClock::new(start);

    first.advance(time::Duration::seconds(5));
    first.advance(time::Duration::milliseconds(250));
    second.advance(time::Duration::seconds(5));
    second.advance(time::Duration::milliseconds(250));

    assert_eq!(first.monotonic_elapsed(), second.monotonic_elapsed());
    assert_eq!(first.monotonic(), second.monotonic());
}
