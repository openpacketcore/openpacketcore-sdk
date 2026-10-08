//! Real process loss at CBC empty-reply and ordinary-acknowledgement boundaries.
//! The small test-only store names public fixture keys by row; it is not an SDK
//! storage format. Only metadata, protected packets and fixed outcomes cross the
//! process boundary. Each child restores the same immutable key binding.
#![allow(clippy::unwrap_used)]

use crate::canonical::Ikev2CanonicalPolicy;
use crate::recovery::{
    cbc_test_fixtures::*, Ikev2CbcEpochInputs, Ikev2CbcEpochRecord as Epoch,
    Ikev2CommittedExchangeRecord as ExchangeRecord, Ikev2CommittedWindowDomain as Domain,
    Ikev2CommittedWindowRecord as Record, Ikev2EmptyReplyObservation as Observation,
    Ikev2OrdinaryRequestDisposition as Disposition, Ikev2WindowError as Error,
};
use crate::{PayloadChain, PayloadType};
use bytes::Bytes;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const IDS: [u32; 3] = [1, 0x8000_0000, u32::MAX];
const ROWS: usize = 48 * 2 * IDS.len();

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> Bytes {
    if value == "-" {
        return Bytes::new();
    }
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .into()
}

fn store(epoch: &Epoch, record: &Record<Cbc>) -> String {
    assert!(record.outbound().is_none());
    assert!(record.sync_state().is_none());
    assert!(record.sync_recovery().is_none());
    let (request, response, outcome) = record.inbound().map_or_else(
        || ("-".into(), "-".into(), "-".into()),
        |entry| {
            (
                hex(entry.request()),
                hex(entry.response().unwrap()),
                hex(entry.outcome().unwrap()),
            )
        },
    );
    format!(
        "{} {} {} {} {} {} {}",
        epoch.canonical_format().unwrap(),
        record.generation(),
        record.next_send().unwrap(),
        record.next_receive().unwrap(),
        request,
        response,
        outcome
    )
}

fn restore(f: &mut Fixture, serialized: &str) -> Record<Cbc> {
    let fields: Vec<_> = serialized.split_whitespace().collect();
    assert_eq!(fields.len(), 7);
    let epoch = Epoch::from_persisted(
        Ikev2CbcEpochInputs {
            initiator_spi: f.epoch.initiator_spi(),
            responder_spi: f.epoch.responder_spi(),
            sending_direction: f.epoch.direction(),
            profile: f.profile,
            keys: &f.keys,
        },
        Some(fields[0].parse().unwrap()),
    )
    .unwrap();
    assert_eq!(
        epoch, f.epoch,
        "the same atomic fixture-key binding is restored"
    );
    f.epoch = epoch;
    f.domain = Domain::from_cbc_epoch(&f.epoch);
    let inbound = if fields[4] == "-" {
        assert_eq!(&fields[5..], &["-", "-"]);
        None
    } else {
        Some(
            ExchangeRecord::from_persisted(
                unhex(fields[4]),
                Some(unhex(fields[5])),
                Some(unhex(fields[6])),
            )
            .unwrap(),
        )
    };
    let record = Record::from_persisted(
        f.domain.clone(),
        fields[1].parse().unwrap(),
        Some(fields[2].parse().unwrap()),
        Some(fields[3].parse().unwrap()),
        None,
        inbound,
    )
    .unwrap();
    assert_eq!(store(&f.epoch, &record), serialized);
    record
}

fn rows(text: &str, prefix: &str) -> BTreeMap<usize, String> {
    let mut result = BTreeMap::new();
    for line in text.lines().filter_map(|line| line.strip_prefix(prefix)) {
        let (row, value) = line.split_once(':').unwrap();
        assert!(result
            .insert(row.parse().unwrap(), value.to_owned())
            .is_none());
    }
    result
}

fn run_child(stage: &str, input: &BTreeMap<usize, String>) -> String {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "recovery::profile::restart_tests::cbc_restart_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("OPC_CBC_RESTART_STAGE", stage)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Drain both pipes while the child runs: the all-profile store exceeds a
    // pipe buffer. A deadline also bounds a provider or harness regression.
    let mut stdout = child.stdout.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).unwrap();
        text
    });
    let mut stderr = child.stderr.take().unwrap();
    let err = std::thread::spawn(move || {
        let mut text = String::new();
        stderr.read_to_string(&mut text).unwrap();
        text
    });
    let mut stdin = child.stdin.take().unwrap();
    let input: String = input
        .iter()
        .map(|(row, value)| format!("STORE:{row}:{value}\n"))
        .collect();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let deadline = Instant::now() + Duration::from_secs(30);
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break (status, false);
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            break (child.wait().unwrap(), true);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = out.join().unwrap();
    let stderr = err.join().unwrap();
    let written = writer.join().unwrap();
    assert!(
        !timed_out && status.success() && written.is_ok(),
        "{stage}: {status}, timed out={timed_out}\n{stdout}\n{stderr}"
    );
    assert!(stdout
        .lines()
        .any(|line| line == format!("DONE:{stage}:{ROWS}")));
    stdout
}

#[test]
fn cbc_all_profiles_reconstruct_identical_bytes_across_real_process_crashes() {
    let before = run_child("before-enable", &BTreeMap::new());
    let initial = rows(&before, "STORE:");
    assert_eq!(initial.len(), ROWS);
    assert!(rows(&before, "PACKET:").is_empty());
    let enabled = run_child("after-enable", &initial);
    assert_eq!(rows(&enabled, "STORE:"), initial);
    assert!(rows(&enabled, "PACKET:").is_empty());

    let verified = run_child("verified", &initial);
    let expected = rows(&verified, "PACKET:");
    assert_eq!(expected.len(), ROWS);
    assert_eq!(rows(&verified, "STORE:"), initial);
    for stage in ["submitted", "restored"] {
        let output = run_child(stage, &initial);
        assert_eq!(
            rows(&output, "STORE:"),
            initial,
            "DPD must not change the durable record"
        );
        assert_eq!(rows(&output, "PACKET:"), expected, "{stage}");
    }

    for stage in ["ordinary-prepared", "ordinary-committed"] {
        let output = run_child(stage, &initial);
        let committed = rows(&output, "STORE:");
        assert_eq!(committed.len(), ROWS);
        assert_ne!(committed, initial);
        if stage == "ordinary-prepared" {
            assert!(rows(&output, "PACKET:").is_empty());
        } else {
            assert_eq!(rows(&output, "PACKET:"), expected);
        }
        let restored = run_child("ordinary-restored", &committed);
        assert_eq!(rows(&restored, "STORE:"), committed);
        assert_eq!(rows(&restored, "PACKET:"), expected);
        let replayed = rows(&restored, "REPLAY:");
        assert_eq!(replayed.len(), ROWS);
        for (row, stored) in committed {
            assert_eq!(
                replayed[&row],
                stored.split_whitespace().nth(5).unwrap(),
                "ordinary acknowledgements replay their exact persisted random-IV bytes"
            );
        }
    }
}

#[test]
fn cbc_restart_child() {
    let Ok(stage) = std::env::var("OPC_CBC_RESTART_STAGE") else {
        return;
    };
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let persisted = rows(&input, "STORE:");
    println!(); // End libtest's same-line test-name prefix before framed rows.
    assert_eq!(
        persisted.len(),
        if stage == "before-enable" { 0 } else { ROWS }
    );
    let mut live = Vec::with_capacity(ROWS);
    for (index, profile) in profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            for (position, id) in IDS.into_iter().enumerate() {
                let row = (index * 2 + role) * IDS.len() + position;
                let mut f = Fixture::new(profile, direction, 1_200_000 + row as u64);
                let mut durable = if stage == "before-enable" {
                    Record::initial(f.domain.clone(), 1, 0)
                } else {
                    restore(&mut f, &persisted[&row])
                };
                let mut window = f.restore(&durable);
                if stage == "before-enable" {
                    println!("STORE:{row}:{}", store(&f.epoch, &durable));
                    live.push(window);
                    continue;
                }
                if stage == "ordinary-restored" {
                    let entry = durable.inbound().unwrap();
                    let request = window.open_peer(profile, &f.keys, entry.request()).unwrap();
                    assert_eq!(
                        window.request_disposition(&request),
                        Ok(Disposition::CachedResponse)
                    );
                    assert_eq!(
                        window.replay_response(&request).unwrap().bytes(),
                        entry.response().unwrap()
                    );
                    assert_eq!(entry.outcome(), Some(&b"ordinary result"[..]));
                    println!(
                        "REPLAY:{row}:{}",
                        hex(window.replay_response(&request).unwrap().bytes())
                    );
                }
                window
                    .enable_empty_replies(Ikev2CanonicalPolicy::default())
                    .unwrap();
                assert!(window.is_reconstructing());
                if stage.starts_with("ordinary-") && stage != "ordinary-restored" {
                    let wire =
                        f.peer_wire(id - 1, PayloadChain::new(PayloadType::Delete, DELETE), 0);
                    let request = window.open_peer(profile, &f.keys, &wire).unwrap();
                    assert_eq!(window.request_disposition(&request), Ok(Disposition::New));
                    let prepared = window
                        .prepare_response(
                            profile,
                            &f.keys,
                            &request,
                            PayloadChain::new(PayloadType::NoNext, &[]),
                            Bytes::from_static(b"ordinary result"),
                        )
                        .unwrap();
                    durable = prepared.record().clone();
                    assert_eq!(durable.generation(), 1);
                    assert_eq!(durable.next_receive(), Some(id));
                    if stage == "ordinary-prepared" {
                        // Storage landed but the process dies before its ack.
                        drop(prepared);
                        assert_eq!(window.ready(), Err(Error::CommitUncertain));
                        println!("STORE:{row}:{}", store(&f.epoch, &durable));
                        live.push(window);
                        continue;
                    }
                    let token = prepared.commit_after_durable(&durable).unwrap();
                    // Crash before consuming this outcome permission. Restore
                    // can replay stored bytes, never remint that effect token.
                    std::mem::forget(token);
                    assert!(!window.is_reconstructing());
                }
                if stage == "after-enable" {
                    println!("STORE:{row}:{}", store(&f.epoch, &durable));
                    live.push(window);
                    continue;
                }
                let padding = if stage.ends_with("restored") { 0xa5 } else { 0 };
                let request = f.request(id, padding);
                let reply = window.reply_empty(&request).unwrap();
                assert_eq!(
                    reply.observation(),
                    if stage == "ordinary-committed" {
                        Observation::Fresh
                    } else {
                        Observation::Uncertain
                    }
                );
                let packet = reply.bytes().to_vec();
                if stage == "submitted" {
                    let (send, receive) = std::sync::mpsc::channel();
                    send.send(packet.clone()).unwrap();
                    assert_eq!(receive.recv().unwrap(), packet);
                }
                // Abrupt exit below bypasses the verified reply's destructor.
                std::mem::forget(reply);
                assert_eq!(window.next_receive(), id.checked_add(1));
                let duplicate = window.reply_empty(&request).unwrap();
                assert_eq!(duplicate.observation(), Observation::Replayed);
                assert_eq!(duplicate.bytes(), packet);
                drop(duplicate);
                assert_eq!(window.record(), &durable);
                if let Some(next) = id.checked_add(1) {
                    let wire = f.peer_wire(next, PayloadChain::new(PayloadType::Delete, DELETE), 0);
                    let work = window.open_peer(profile, &f.keys, &wire).unwrap();
                    assert_eq!(
                        window.request_disposition(&work),
                        Ok(Disposition::New),
                        "DPD must not wedge the peer's next ordinary request"
                    );
                    assert_eq!(window.reply_empty(&request).unwrap_err(), Error::Drop);
                } else {
                    assert_eq!(
                        window.reply_empty(&f.request(0, 0)).unwrap_err(),
                        Error::Drop
                    );
                }
                assert_eq!(window.record(), &durable);
                println!("STORE:{row}:{}", store(&f.epoch, &durable));
                println!("PACKET:{row}:{}", hex(&packet));
                live.push(window);
            }
        }
    }
    assert_eq!(live.len(), ROWS);
    println!("DONE:{stage}:{ROWS}");
    std::io::stdout().flush().unwrap();
    // None of the 288 windows, epoch bindings or canonical caches are dropped.
    std::process::exit(0);
}
