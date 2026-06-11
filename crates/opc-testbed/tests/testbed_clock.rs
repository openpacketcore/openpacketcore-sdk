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
#[should_panic(expected = "virtual offset overflow")]
fn virtual_clock_monotonic_overflow_panics() {
    let start = opc_types::Timestamp::now_utc();
    let mut clock = VirtualClock::new(start);
    clock.advance(time::Duration::days(220_000));
    let _ = clock.monotonic();
}
