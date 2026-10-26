//! Zero-write probes composed with fenced storage and an independent peer window.

use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{
        Ikev2LivenessProbePolicy as ProbePolicy, Ikev2SyncClock as Clock,
        Ikev2WindowError as WindowError,
    },
    Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncMode as Mode,
};

use super::{
    authority::{EpochOwners, Transport},
    driver::{self, Cut, Error, Runtime, State},
    envelope::Provider,
    lifecycle::{child_delete, matrix},
    peer::{Event, PeerModel, Sync},
    row::{Row, WindowImage},
    store::{CasStore, Command},
    sync_driver::Start,
    sync_tests::policy,
    wire::Wire,
};
use crate::canonical_fixtures::{empty, opposite};

macro_rules! window {
    ($runtime:expr, $window:ident, $body:expr) => {
        match &mut $runtime.state {
            State::Gcm {
                window: $window, ..
            } => $body,
            State::Cbc {
                window: $window, ..
            } => $body,
        }
    };
}

pub(super) fn setup(row: &Row) -> (Provider, CasStore, EpochOwners, Command, Runtime) {
    let provider = Provider::new();
    let mut store = CasStore::new(7);
    let owners = EpochOwners::new(7);
    let initial = driver::create(&provider, &mut store, row).unwrap();
    let mut runtime = Runtime::restore(
        &provider,
        &owners,
        &store.fenced_read(&initial, row.key).unwrap(),
        true,
    )
    .unwrap();
    runtime
        .reserve(
            &provider,
            &mut store,
            1,
            32,
            100,
            Cut::Complete,
            Cut::Complete,
        )
        .unwrap();
    (provider, store, owners, initial, runtime)
}

fn peer(row: &Row) -> PeerModel<'_> {
    PeerModel::new(
        Wire::new(row.profile, &row.keys, row.spis, opposite(row.direction)),
        row.window.next_receive.unwrap(),
        row.window.next_send.unwrap(),
        row.mode == Mode::Negotiated,
    )
}

fn enable(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    bound: u32,
    cut: Cut,
) -> Command {
    runtime.protocol_check().unwrap();
    let image = match &mut runtime.state {
        State::Gcm { window, .. } => {
            WindowImage::gcm(window.prepare_liveness(bound).unwrap().record())
        }
        State::Cbc { window, .. } => {
            WindowImage::cbc(window.prepare_liveness(bound).unwrap().record())
        }
    };
    let candidate = runtime
        .row
        .next_write(store.stamp(), |row| row.window = image)
        .unwrap();
    let command = driver::command(provider, store, Some(runtime.row.version), &candidate).unwrap();
    runtime.pending = Some(command.clone());
    if driver::dispatch(store, &command, cut).unwrap() {
        runtime.resolve(provider, store, &command).unwrap();
    }
    command
}

// One logical time interval per Message ID keeps the peer-model schedule
// deterministic without wall-clock sleeps. The SDK owns retry and expiry checks.
fn send(runtime: &mut Runtime, transport: &mut Transport) -> Result<u32, Error> {
    runtime.protocol_check()?;
    let permit = runtime.permit();
    let now = u64::from(window!(runtime, window, window.next_send()).unwrap_or(0)) * 10_000;
    let policy = ProbePolicy::new(4_000, 6, 100).unwrap();
    let request = match &mut runtime.state {
        State::Gcm { window, allocator } => {
            let probe = window.start_empty_probe(
                runtime.row.profile,
                &runtime.row.keys,
                allocator,
                policy,
                now,
            )?;
            transport.submit(&permit, probe.bytes())?;
            probe.message_id()
        }
        State::Cbc { window, .. } => {
            let probe =
                window.start_empty_probe(runtime.row.profile, &runtime.row.keys, policy, now)?;
            transport.submit(&permit, probe.bytes())?;
            probe.message_id()
        }
    };
    Ok(request)
}

fn retransmit_at(
    runtime: &mut Runtime,
    transport: &mut Transport,
    now: u64,
) -> Result<bool, Error> {
    runtime.protocol_check()?;
    let permit = runtime.permit();
    window!(runtime, window, {
        match window.retry_empty_probe(now) {
            Ok(request) => {
                transport.submit(&permit, request.bytes())?;
                Ok(true)
            }
            Err(WindowError::Drop) => Ok(false),
            Err(error) => Err(error.into()),
        }
    })
}

fn retransmit(runtime: &mut Runtime, transport: &mut Transport) -> Result<bool, Error> {
    let id = window!(runtime, window, window.pending_empty_request_message_id()).unwrap_or(0);
    retransmit_at(runtime, transport, u64::from(id) * 10_000 + 100)
}

fn complete(runtime: &mut Runtime, wire: &[u8]) -> Result<u32, Error> {
    runtime.protocol_check()?;
    window!(runtime, window, {
        let response = window.open_peer(runtime.row.profile, &runtime.row.keys, wire)?;
        let id = window
            .pending_empty_request_message_id()
            .ok_or(WindowError::Drop)?;
        window.complete_empty_probe(&response, u64::from(id) * 10_000 + 100)?;
        Ok(id)
    })
}

pub(super) fn recover(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    peer: &mut PeerModel<'_>,
) {
    let mut transport = Transport::default();
    runtime
        .sync_request(
            provider,
            store,
            Start::New(policy(9)),
            Clock::new(100, 9),
            Clock::new(100, 9),
            Cut::Complete,
            &mut transport,
        )
        .unwrap();
    let Event::SyncReply { wire, .. } = peer.receive(transport.submitted.last().unwrap()).unwrap()
    else {
        panic!("independent peer must accept the bounded recovery proposal");
    };
    runtime
        .sync_complete(
            provider,
            store,
            &wire,
            Clock::new(101, 9),
            Clock::new(101, 9),
            Cut::Complete,
        )
        .unwrap();
    assert_eq!(window!(runtime, window, window.ready()), Ok(()));
}

#[test]
fn probes_are_fresh_zero_write_and_exactly_retransmitted_for_every_profile_role_and_mode() {
    matrix(4_100_000, |row| {
        let (provider, mut store, _owners, _initial, mut runtime) = setup(&row);
        enable(&mut runtime, &provider, &mut store, 4, Cut::Complete);
        let mut peer = peer(&row);
        let mut transport = Transport::default();
        let durable = store.encrypted_snapshot();
        let envelope_calls = provider.calls();
        for id in 0..4 {
            assert_eq!(send(&mut runtime, &mut transport), Ok(id));
            let request = transport.submitted.last().unwrap().clone();
            assert_eq!(peer.receive(&request), Ok(Event::NewRequest(id)));
            let response = peer.respond(id, empty()).unwrap();
            assert!(retransmit(&mut runtime, &mut transport).unwrap());
            assert_eq!(transport.submitted.last(), Some(&request));
            assert_eq!(peer.receive(&request), Ok(Event::Replay(response.clone())));
            for bad in [
                peer.wire.seal(id + 1, true, 37, empty()),
                peer.wire.seal(id, false, 37, empty()),
                peer.wire.seal(id, true, 36, empty()),
                peer.wire.seal(id, true, 37, child_delete()),
            ] {
                assert!(complete(&mut runtime, &bad).is_err());
            }
            let mut corrupt = response.to_vec();
            *corrupt.last_mut().unwrap() ^= 0x80;
            assert!(complete(&mut runtime, &corrupt).is_err());
            assert_eq!(complete(&mut runtime, &response), Ok(id));
            assert!(complete(&mut runtime, &response).is_err());
            assert!(!retransmit(&mut runtime, &mut transport).unwrap());
            assert_eq!(runtime.row.window.next_send, Some(0));
            assert_eq!(window!(runtime, window, window.next_send()), Some(id + 1));
        }
        assert_eq!(
            send(&mut runtime, &mut transport),
            Err(Error::Window(WindowError::LivenessLeadExhausted))
        );
        assert_eq!(store.encrypted_snapshot(), durable);
        assert_eq!(provider.calls(), envelope_calls);
        enable(&mut runtime, &provider, &mut store, 4, Cut::Complete);
        assert_eq!(runtime.row.window.next_send, Some(4));
        assert_eq!(send(&mut runtime, &mut transport), Ok(4));
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::NewRequest(4))
        );
    });
}

#[test]
fn cold_restore_never_reuses_unwritten_probe_ids_or_accepts_old_liveness() {
    matrix(4_110_000, |row| {
        let (provider, mut store, owners, initial, mut runtime) = setup(&row);
        enable(&mut runtime, &provider, &mut store, 4, Cut::Complete);
        let mut peer = peer(&row);
        let mut transport = Transport::default();
        send(&mut runtime, &mut transport).unwrap();
        assert_eq!(
            peer.receive(&transport.submitted[0]),
            Ok(Event::NewRequest(0))
        );
        let old_response = peer.respond(0, empty()).unwrap();
        complete(&mut runtime, &old_response).unwrap();
        send(&mut runtime, &mut transport).unwrap();
        // Lose the still-untransmitted second probe and all volatile send knowledge.
        drop(runtime);
        runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(
            window!(runtime, window, window.ready()),
            Err(WindowError::LivenessRecoveryRequired)
        );
        assert!(complete(&mut runtime, &old_response).is_err());
        assert!(send(&mut runtime, &mut transport).is_err());
        assert!(runtime
            .publish_request(
                &provider,
                &mut store,
                Exchange::Informational,
                child_delete(),
                |_| {},
                Cut::Complete
            )
            .is_err());
        assert!(window!(runtime, window, window.prepare_liveness(1).map(|_| ())).is_err());
        if row.mode == Mode::Negotiated {
            recover(&mut runtime, &provider, &mut store, &mut peer);
            runtime
                .reserve(
                    &provider,
                    &mut store,
                    12,
                    16,
                    200,
                    Cut::Complete,
                    Cut::Complete,
                )
                .unwrap();
            let next = send(&mut runtime, &mut transport).unwrap();
            assert!(next >= 4);
            assert!(complete(&mut runtime, &old_response).is_err());
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::NewRequest(next))
            );
            assert_eq!(
                complete(&mut runtime, &peer.respond(next, empty()).unwrap()),
                Ok(next)
            );
        } else {
            assert!(window!(
                runtime,
                window,
                window
                    .begin_sync(policy(9), Clock::new(100, 9), None)
                    .map(|_| ())
            )
            .is_err());
            // Base IKE has no safe counter-resynchronization path: retire this epoch.
            runtime.revoke();
            assert!(retransmit(&mut runtime, &mut transport).is_err());
        }
    });
}

#[test]
fn pending_probe_preserves_the_independent_peer_direction_and_blocks_local_rekey_delete() {
    matrix(4_120_000, |row| {
        let (provider, mut store, _owners, _initial, mut runtime) = setup(&row);
        enable(&mut runtime, &provider, &mut store, 4, Cut::Complete);
        let mut peer = peer(&row);
        let mut transport = Transport::default();
        send(&mut runtime, &mut transport).unwrap();
        let probe = transport.submitted.last().unwrap().clone();
        for exchange in [Exchange::Informational, Exchange::CreateChildSa] {
            assert_eq!(
                runtime.publish_request(
                    &provider,
                    &mut store,
                    exchange,
                    child_delete(),
                    |_| {},
                    Cut::Complete
                ),
                Err(Error::Window(WindowError::RequestOutstanding))
            );
        }
        let incoming_empty = peer.request(37, empty()).unwrap();
        runtime
            .reply_empty(&incoming_empty, &mut transport)
            .unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Completed(0))
        );
        let incoming = peer.request(37, child_delete()).unwrap();
        runtime
            .publish_response(
                &provider,
                &mut store,
                &incoming,
                empty(),
                Bytes::from_static(b"peer-child-deleted"),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
        runtime.replay_response(&incoming, &mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::Completed(1))
        );
        assert_eq!(runtime.row.window.next_send, Some(1));
        assert_eq!(runtime.row.window.next_receive, Some(2));
        assert!(retransmit(&mut runtime, &mut transport).unwrap());
        assert_eq!(transport.submitted.last(), Some(&probe));
        assert_eq!(peer.receive(&probe), Ok(Event::NewRequest(0)));
        complete(&mut runtime, &peer.respond(0, empty()).unwrap()).unwrap();
        runtime
            .publish_request(
                &provider,
                &mut store,
                Exchange::CreateChildSa,
                child_delete(),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
        runtime.dispatch_replay(&mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::NewRequest(1))
        );
        // The latest complete row remains independently reconstructible after the fold.
        if row.profile.encryption().is_aead() {
            runtime.row.gcm().unwrap();
        } else {
            runtime.row.cbc().unwrap();
        }
    });
}

#[test]
fn deadline_expiry_never_skips_a_missing_request_at_the_peer() {
    matrix(4_130_000, |row| {
        let (provider, mut store, _owners, _initial, mut runtime) = setup(&row);
        enable(&mut runtime, &provider, &mut store, 4, Cut::Complete);
        let mut peer = peer(&row);
        let mut transport = Transport::default();
        let durable = store.encrypted_snapshot();
        send(&mut runtime, &mut transport).unwrap();
        let first = transport.submitted[0].clone();
        // The transport loses every attempt; the SDK enforces exponential backoff.
        let mut now = 0;
        for delay in [100, 200, 400, 800, 1600] {
            peer.advance(delay);
            now += delay;
            assert!(retransmit_at(&mut runtime, &mut transport, now).unwrap());
            assert_eq!(transport.submitted.last(), Some(&first));
        }
        assert_eq!(
            window!(runtime, window, window.check_empty_probe_deadline(4_000)),
            Err(WindowError::LivenessExpired)
        );
        assert!(send(&mut runtime, &mut transport).is_err());
        assert!(retransmit(&mut runtime, &mut transport).is_err());
        assert!(complete(&mut runtime, &peer.wire.seal(0, true, 37, empty())).is_err());
        assert_eq!(store.encrypted_snapshot(), durable);
        // RFC 7296 section 2.4 requires deleting the IKE SA after failed
        // liveness. A local deadline is terminal, including for negotiated sync.
        assert!(window!(
            runtime,
            window,
            window
                .begin_sync(policy(9), Clock::new(4_000, 9), None)
                .map(|_| ())
        )
        .is_err());
        runtime.revoke();
        assert!(send(&mut runtime, &mut transport).is_err());
    });
}

#[test]
fn peer_sync_cutover_discards_a_probe_and_covers_a_cold_unwritten_lead() {
    for cold in [false, true] {
        matrix(4_140_000 + u64::from(cold) * 1000, |row| {
            if row.mode != Mode::Negotiated {
                return;
            }
            let (provider, mut store, owners, initial, mut runtime) = setup(&row);
            enable(&mut runtime, &provider, &mut store, 4, Cut::Complete);
            let mut peer = peer(&row);
            let mut transport = Transport::default();
            send(&mut runtime, &mut transport).unwrap();
            if cold {
                drop(runtime);
                runtime = Runtime::restore(
                    &provider,
                    &owners,
                    &store.fenced_read(&initial, row.key).unwrap(),
                    false,
                )
                .unwrap();
            }
            let request = peer
                .begin_sync(Sync {
                    nonce: [9, 8, 7, 6],
                    send: 1,
                    receive: 0,
                })
                .unwrap();
            runtime
                .sync_response(
                    &provider,
                    &mut store,
                    &request,
                    None,
                    policy(10),
                    Clock::new(100, 9),
                    Cut::Complete,
                    &mut transport,
                )
                .unwrap();
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::Synchronized)
            );
            assert!(runtime.row.window.next_send.unwrap() >= if cold { 4 } else { 1 });
            assert!(!retransmit(&mut runtime, &mut transport).unwrap());
            assert_eq!(window!(runtime, window, window.ready()), Ok(()));
            if cold {
                runtime
                    .reserve(
                        &provider,
                        &mut store,
                        12,
                        16,
                        200,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
            }
            let next = send(&mut runtime, &mut transport).unwrap();
            assert_eq!(
                peer.receive(transport.submitted.last().unwrap()),
                Ok(Event::NewRequest(next))
            );
        });
    }
}

#[test]
fn activation_cannot_escape_an_uncertain_write_and_readback_preserves_its_actual_result() {
    for (offset, cut) in [
        Cut::BeforeDispatch,
        Cut::Dispatched,
        Cut::Applied,
        Cut::Acknowledged,
    ]
    .into_iter()
    .enumerate()
    {
        matrix(4_150_000 + offset as u64 * 1000, |row| {
            let (provider, mut store, _owners, initial, mut runtime) = setup(&row);
            let command = enable(&mut runtime, &provider, &mut store, 4, cut);
            let mut transport = Transport::default();
            assert!(send(&mut runtime, &mut transport).is_err());
            assert!(transport.submitted.is_empty());
            if cut == Cut::BeforeDispatch {
                // The owner has joined the undispatched preparation; no write can still arrive.
                runtime.resolve(&provider, &store, &initial).unwrap();
                assert_eq!(
                    send(&mut runtime, &mut transport),
                    Err(Error::Window(WindowError::LivenessDisabled))
                );
                enable(&mut runtime, &provider, &mut store, 4, Cut::Complete);
            } else {
                if cut == Cut::Dispatched {
                    assert!(runtime.resolve(&provider, &store, &command).is_err());
                    store.apply(command.request()).unwrap();
                }
                runtime.resolve(&provider, &store, &command).unwrap();
            }
            assert_eq!(send(&mut runtime, &mut transport), Ok(0));
        });
    }
}

#[test]
fn folding_probes_preserves_the_settled_outcome_and_keeps_the_row_restorable() {
    matrix(4_160_000, |row| {
        let (provider, mut store, owners, initial, mut runtime) = setup(&row);
        let mut peer = peer(&row);
        let mut transport = Transport::default();
        runtime
            .publish_request(
                &provider,
                &mut store,
                Exchange::Informational,
                child_delete(),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
        runtime.dispatch_replay(&mut transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::NewRequest(0))
        );
        let answer = peer.respond(0, empty()).unwrap();
        assert_eq!(
            runtime
                .complete(
                    &provider,
                    &mut store,
                    &answer,
                    Bytes::from_static(b"settled"),
                    |_| {},
                    Cut::Complete
                )
                .unwrap(),
            Some(Bytes::from_static(b"settled"))
        );
        let settled = runtime.row.window.outbound.clone().unwrap();
        assert_eq!(
            settled.response().unwrap().single_packet(),
            Ok(answer.as_ref())
        );
        assert_eq!(settled.outcome(), Some(b"settled".as_slice()));
        enable(&mut runtime, &provider, &mut store, 4, Cut::Complete);
        assert_eq!(send(&mut runtime, &mut transport), Ok(1));
        let probe = transport.submitted.last().unwrap().clone();
        let incoming = peer.request(37, child_delete()).unwrap();
        runtime
            .publish_response(
                &provider,
                &mut store,
                &incoming,
                empty(),
                Bytes::from_static(b"peer work"),
                |_| {},
                Cut::Applied,
            )
            .unwrap();
        let command = runtime.pending.clone().unwrap();
        assert!(retransmit(&mut runtime, &mut transport).is_err());
        runtime.resolve(&provider, &store, &command).unwrap();
        assert_eq!(runtime.row.window.next_send, Some(2));
        // RFC 7296 section 2.2 separates the two request directions. This
        // SDK retains settled local outcomes when folding probes during peer work.
        assert_eq!(runtime.row.window.outbound.as_ref(), Some(&settled));
        retransmit(&mut runtime, &mut transport).unwrap();
        assert_eq!(transport.submitted.last(), Some(&probe));
        assert_eq!(peer.receive(&probe), Ok(Event::NewRequest(1)));
        complete(&mut runtime, &peer.respond(1, empty()).unwrap()).unwrap();
        drop(runtime);
        let mut restored = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(
            window!(restored, window, window.ready()),
            Err(WindowError::LivenessRecoveryRequired)
        );
        assert_eq!(restored.row.window.next_send, Some(2));
        assert!(restored.row.window.inbound.is_some());
        assert_eq!(restored.row.window.outbound.as_ref(), Some(&settled));
    });
}

#[test]
fn persisted_pending_ordinary_request_proves_no_later_probe_escaped_before_restart() {
    matrix(4_170_000, |row| {
        let (provider, mut store, owners, initial, mut runtime) = setup(&row);
        enable(&mut runtime, &provider, &mut store, 4, Cut::Complete);
        let mut peer = peer(&row);
        let mut transport = Transport::default();
        send(&mut runtime, &mut transport).unwrap();
        peer.receive(transport.submitted.last().unwrap()).unwrap();
        complete(&mut runtime, &peer.respond(0, empty()).unwrap()).unwrap();
        runtime
            .publish_request(
                &provider,
                &mut store,
                Exchange::Informational,
                child_delete(),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
        runtime.dispatch_replay(&mut transport).unwrap();
        let ordinary = transport.submitted.last().unwrap().clone();
        assert_eq!(peer.receive(&ordinary), Ok(Event::NewRequest(1)));
        let answer = peer.respond(1, empty()).unwrap();
        drop(runtime);
        runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(window!(runtime, window, window.ready()), Ok(()));
        runtime.dispatch_replay(&mut transport).unwrap();
        assert_eq!(transport.submitted.last(), Some(&ordinary));
        assert_eq!(peer.receive(&ordinary), Ok(Event::Replay(answer.clone())));
        runtime
            .complete(
                &provider,
                &mut store,
                &answer,
                Bytes::from_static(b"settled after restart"),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
        runtime
            .reserve(
                &provider,
                &mut store,
                12,
                8,
                200,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        assert_eq!(send(&mut runtime, &mut transport), Ok(2));
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::NewRequest(2))
        );
    });
}

fn process_cases() -> Vec<(Row, bool)> {
    let mut cases = Vec::new();
    for (index, profile) in super::inputs::profiles().enumerate() {
        if ![0, 3].contains(&index) {
            continue;
        }
        for direction in crate::canonical_fixtures::DIRECTIONS {
            for mode in [Mode::BaseFallback, Mode::Negotiated] {
                for answered in [false, true] {
                    cases.push((
                        super::inputs::fresh(
                            4_200_000 + cases.len() as u64,
                            profile,
                            direction,
                            mode,
                        ),
                        answered,
                    ));
                }
            }
        }
    }
    cases
}

pub fn run_process(root: &std::path::Path, stage: &str, provider: &Provider) {
    use super::crash::{packet_name, read, write};
    for (row, answered) in process_cases() {
        let rows = format!("liveness-{}.rows", row.key.0);
        let packet = packet_name("liveness-first", row.key.0);
        let mut peer = peer(&row);
        let mut transport = Transport::default();
        if stage == "liveness-start" {
            let (_provider, mut store, _owners, _initial, mut runtime) = setup(&row);
            enable(&mut runtime, provider, &mut store, 4, Cut::Complete);
            let writes = (store.dispatches, store.publications);
            send(&mut runtime, &mut transport).unwrap();
            write(root, &packet, &transport.submitted[0]);
            if answered {
                peer.receive(&transport.submitted[0]).unwrap();
                complete(&mut runtime, &peer.respond(0, empty()).unwrap()).unwrap();
            }
            assert_eq!((store.dispatches, store.publications), writes);
            write(root, &rows, &store.encrypted_snapshot());
        } else {
            assert_eq!(stage, "liveness-restore");
            let (mut store, cuts) = CasStore::reopen_after_join(&read(root, &rows), 8).unwrap();
            let owners = EpochOwners::new(8);
            let mut runtime = Runtime::restore(provider, &owners, &cuts[0], false).unwrap();
            assert_eq!(
                runtime
                    .row
                    .window
                    .liveness
                    .as_ref()
                    .map(|state| state.max_unwritten()),
                Some(4)
            );
            assert_eq!(peer.receive(&read(root, &packet)), Ok(Event::NewRequest(0)));
            let old_response = peer.respond(0, empty()).unwrap();
            assert!(complete(&mut runtime, &old_response).is_err());
            assert_eq!(
                window!(runtime, window, window.ready()),
                Err(WindowError::LivenessRecoveryRequired)
            );
            if row.mode == Mode::Negotiated {
                recover(&mut runtime, provider, &mut store, &mut peer);
                runtime
                    .reserve(
                        provider,
                        &mut store,
                        12,
                        8,
                        200,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                let next = send(&mut runtime, &mut transport).unwrap();
                assert!(next >= 4);
                assert!(complete(&mut runtime, &old_response).is_err());
                assert_eq!(
                    peer.receive(transport.submitted.last().unwrap()),
                    Ok(Event::NewRequest(next))
                );
                complete(&mut runtime, &peer.respond(next, empty()).unwrap()).unwrap();
            } else {
                runtime.revoke();
                assert!(send(&mut runtime, &mut transport).is_err());
            }
        }
    }
}

#[test]
fn actual_process_loss_preserves_the_probe_bound_for_answered_and_outstanding_probes() {
    let directory = super::crash::RunDir::new();
    super::crash::child(
        &directory.0,
        "liveness-start",
        "liveness",
        "liveness-before-crash",
    );
    super::crash::child(
        &directory.0,
        "liveness-restore",
        "liveness",
        "liveness-after-crash",
    );
}
