use super::*;
use crate::scope::{lifecycle::EffectGate, AuthenticationClock, IntervalClock};
use opc_tls::AuthenticationTimeInterval;
use opc_types::Timestamp;
use std::sync::atomic::{AtomicUsize, Ordering};

const UNCERTAINTY: Duration = Duration::from_micros(10_522);

struct ScriptedKernel {
    value: Mutex<KernelSample>,
    active: AtomicUsize,
}

impl ScriptedKernel {
    fn set(&self, value: KernelSample) {
        *self.value.lock().unwrap() = value;
    }
}

impl KernelReader for ScriptedKernel {
    fn sample(&self) -> KernelSample {
        assert_eq!(self.active.fetch_add(1, Ordering::SeqCst), 0);
        std::thread::yield_now();
        let value = *self.value.lock().unwrap();
        assert_eq!(self.active.fetch_sub(1, Ordering::SeqCst), 1);
        value
    }
}

fn snapshot() -> RealtimeSnapshot {
    RealtimeSnapshot {
        state: TIME_OK,
        status: STA_PLL | STA_NANO,
        seconds: 1_800_000_000,
        subsecond: 123_456_000,
        maximum_error_micros: 10_000,
        estimated_error_micros: 2_000,
        precision_micros: 1,
        tolerance_scaled_ppm: 32_768_000,
    }
}

fn sample(observation: RealtimeSnapshot) -> KernelSample {
    KernelSample {
        observations: [Ok(observation); 2],
        elapsed: Duration::from_micros(20),
    }
}

fn source() -> (Arc<ScriptedKernel>, Arc<PlatformAuthenticationTimeSource>) {
    let kernel = Arc::new(ScriptedKernel {
        value: Mutex::new(sample(snapshot())),
        active: AtomicUsize::new(0),
    });
    let source = Arc::new(PlatformAuthenticationTimeSource::with_reader(
        kernel.clone(),
    ));
    (kernel, source)
}

fn timestamp(nanos: i128) -> Timestamp {
    Timestamp::from_offset_datetime(time::OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap())
}

fn now() -> Timestamp {
    timestamp(1_800_000_000_123_456_000)
}

fn at(now: Timestamp) -> KernelSample {
    let nanos = now.as_offset_datetime().unix_timestamp_nanos();
    sample(RealtimeSnapshot {
        seconds: nanos.div_euclid(1_000_000_000),
        subsecond: nanos.rem_euclid(1_000_000_000),
        ..snapshot()
    })
}

fn interval(now: Timestamp) -> AuthenticationTimeInterval {
    let nanos = now.as_offset_datetime().unix_timestamp_nanos();
    AuthenticationTimeInterval::new(timestamp(nanos - 10_522_000), timestamp(nanos + 10_522_000))
        .unwrap()
}

#[test]
fn linux_time_healthy_units_and_error_fields_have_exact_bounds() {
    for nano in [false, true] {
        for (estimate, uncertainty) in [(2_000, 10_522), (12_000, 12_522), (0, 10_522)] {
            let (kernel, source) = source();
            let mut observed = snapshot();
            if !nano {
                observed.status &= !STA_NANO;
                observed.subsecond /= 1_000;
            }
            observed.estimated_error_micros = estimate;
            kernel.set(sample(observed));
            assert_eq!(
                source.read(),
                Ok(RealtimeReading {
                    now: now(),
                    uncertainty: Duration::from_micros(uncertainty),
                    synchronization_generation: 1,
                })
            );
        }
    }
    for (state, flag) in [(TIME_INS, STA_INS), (TIME_DEL, STA_DEL), (TIME_WAIT, 0)] {
        let (kernel, source) = source();
        kernel.set(sample(RealtimeSnapshot {
            state,
            status: snapshot().status | flag,
            ..snapshot()
        }));
        assert_eq!(source.read().unwrap().uncertainty, UNCERTAINTY);
    }
}

#[test]
fn linux_time_real_kernel_query_has_an_independently_bounded_result() {
    struct RecordingKernel(Mutex<Option<KernelSample>>);
    impl KernelReader for RecordingKernel {
        fn sample(&self) -> KernelSample {
            let sampled = LinuxKernel.sample();
            *self.0.lock().unwrap() = Some(sampled);
            sampled
        }
    }
    let kernel = Arc::new(RecordingKernel(Mutex::new(None)));
    let source = PlatformAuthenticationTimeSource::with_reader(kernel.clone());
    let actual = source.read();
    let observed = kernel.0.lock().unwrap().unwrap();
    let [Ok(first), Ok(last)] = observed.observations else {
        assert_eq!(actual, Err(AuthenticationTimeError));
        return;
    };
    // Compute the oracle from the captured syscall fields, without calling the
    // adapter's validator or its unit conversion helpers.
    let mut valid = first.state == last.state && first.status == last.status;
    let mut instants = Vec::new();
    let mut error_micros = 0_i128;
    let mut precision_micros = 0_i128;
    let mut drift_scaled = 0_i128;
    for raw in [first, last] {
        let pps_loss = ((raw.status & (STA_PPSFREQ | STA_PPSTIME) != 0)
            && raw.status & STA_PPSSIGNAL == 0)
            || (raw.status & STA_PPSTIME != 0 && raw.status & STA_PPSJITTER != 0)
            || (raw.status & STA_PPSFREQ != 0 && raw.status & (STA_PPSWANDER | STA_PPSERROR) != 0);
        let unit = if raw.status & STA_NANO == 0 { 1_000 } else { 1 };
        valid &= matches!(raw.state, TIME_OK | TIME_INS | TIME_DEL | TIME_WAIT)
            && raw.status & !0xffff == 0
            && raw.status & (STA_UNSYNC | STA_CLOCKERR) == 0
            && raw.status & (STA_INS | STA_DEL) != STA_INS | STA_DEL
            && !pps_loss
            && raw.maximum_error_micros > 0
            && raw.estimated_error_micros >= 0
            && raw.precision_micros > 0
            && raw.tolerance_scaled_ppm > 0
            && (0..1_000_000_000 / unit).contains(&raw.subsecond);
        instants.push(raw.seconds * 1_000_000_000 + raw.subsecond * unit);
        error_micros = error_micros
            .max(raw.maximum_error_micros)
            .max(raw.estimated_error_micros);
        precision_micros = precision_micros.max(raw.precision_micros);
        drift_scaled = drift_scaled.max(raw.tolerance_scaled_ppm);
    }
    let elapsed = i128::try_from(observed.elapsed.as_nanos()).unwrap();
    let delta = instants[1] - instants[0];
    valid &= delta >= 0 && delta <= elapsed + 2 * (1 + precision_micros) * 1_000;
    let uncertainty = (error_micros + 1 + precision_micros) * 1_000
        + (drift_scaled * 1_000 + 65_535) / 65_536
        + elapsed;
    valid &= uncertainty <= 1_000_000_000;
    if valid {
        let result = actual.expect("synchronized bounded kernel data must produce a reading");
        assert_eq!(
            result.now.as_offset_datetime().unix_timestamp_nanos(),
            instants[1]
        );
        assert_eq!(
            i128::try_from(result.uncertainty.as_nanos()).unwrap(),
            uncertainty
        );
        assert_eq!(result.synchronization_generation, 1);
    } else {
        assert_eq!(actual, Err(AuthenticationTimeError));
    }
}

#[test]
fn linux_time_unknown_malformed_and_overflowing_observations_are_refused() {
    let mut bad = Vec::new();
    for state in [TIME_OOP, -1, 99] {
        bad.push(RealtimeSnapshot {
            state,
            ..snapshot()
        });
    }
    for status in [1 << 16, -1, STA_INS | STA_DEL] {
        bad.push(RealtimeSnapshot {
            status,
            ..snapshot()
        });
    }
    for maximum_error_micros in [-1, 0, i128::MAX] {
        bad.push(RealtimeSnapshot {
            maximum_error_micros,
            ..snapshot()
        });
    }
    bad.push(RealtimeSnapshot {
        estimated_error_micros: -1,
        ..snapshot()
    });
    for precision_micros in [-1, 0, i128::MAX] {
        bad.push(RealtimeSnapshot {
            precision_micros,
            ..snapshot()
        });
    }
    for tolerance_scaled_ppm in [-1, 0, i128::MAX] {
        bad.push(RealtimeSnapshot {
            tolerance_scaled_ppm,
            ..snapshot()
        });
    }
    for subsecond in [-1, 1_000_000_000] {
        bad.push(RealtimeSnapshot {
            subsecond,
            ..snapshot()
        });
    }
    bad.push(RealtimeSnapshot {
        status: STA_PLL,
        subsecond: 1_000_000,
        ..snapshot()
    });
    bad.push(RealtimeSnapshot {
        seconds: i128::MAX,
        ..snapshot()
    });
    for observed in bad {
        let (kernel, source) = source();
        kernel.set(sample(observed));
        assert_eq!(source.read(), Err(AuthenticationTimeError), "{observed:?}");
    }
    let (kernel, source) = source();
    kernel.set(KernelSample {
        elapsed: Duration::MAX,
        ..sample(snapshot())
    });
    assert_eq!(source.read(), Err(AuthenticationTimeError));
}

#[test]
fn linux_time_pair_state_change_and_steps_are_not_an_atomic_observation() {
    let first = snapshot();
    for second in [
        RealtimeSnapshot {
            state: TIME_WAIT,
            ..first
        },
        RealtimeSnapshot {
            status: first.status | STA_FREQHOLD,
            ..first
        },
        RealtimeSnapshot {
            seconds: first.seconds - 1,
            ..first
        },
        RealtimeSnapshot {
            seconds: first.seconds + 1,
            ..first
        },
    ] {
        let (kernel, source) = source();
        kernel.set(KernelSample {
            observations: [Ok(first), Ok(second)],
            elapsed: Duration::from_micros(20),
        });
        assert_eq!(source.read(), Err(AuthenticationTimeError), "{second:?}");
    }
}

#[test]
fn linux_time_observed_loss_recovers_once_and_cold_start_begins_at_one() {
    let mut failures = vec![RealtimeSnapshot {
        state: TIME_ERROR,
        ..snapshot()
    }];
    for flags in [
        STA_UNSYNC,
        STA_CLOCKERR,
        STA_PPSFREQ,
        STA_PPSTIME,
        STA_PPSTIME | STA_PPSSIGNAL | STA_PPSJITTER,
        STA_PPSFREQ | STA_PPSSIGNAL | STA_PPSWANDER,
        STA_PPSFREQ | STA_PPSSIGNAL | STA_PPSERROR,
    ] {
        failures.push(RealtimeSnapshot {
            status: snapshot().status | flags,
            ..snapshot()
        });
    }
    for failed in failures {
        let (kernel, source) = source();
        assert_eq!(source.read().unwrap().synchronization_generation, 1);
        kernel.set(sample(failed));
        for _ in 0..3 {
            assert_eq!(source.read(), Err(AuthenticationTimeError));
        }
        kernel.set(sample(snapshot()));
        for _ in 0..3 {
            assert_eq!(source.read().unwrap().synchronization_generation, 2);
        }
        let (kernel, source) = self::source();
        kernel.set(sample(failed));
        assert_eq!(source.read(), Err(AuthenticationTimeError));
        kernel.set(sample(snapshot()));
        assert_eq!(source.read().unwrap().synchronization_generation, 1);
    }
}

#[test]
fn linux_time_loss_is_retained_when_the_other_query_fails() {
    for failed_index in [0, 1] {
        let (kernel, source) = source();
        assert_eq!(source.read().unwrap().synchronization_generation, 1);
        let mut observations = [Err(io::ErrorKind::PermissionDenied); 2];
        observations[failed_index] = Ok(RealtimeSnapshot {
            state: TIME_ERROR,
            ..snapshot()
        });
        kernel.set(KernelSample {
            observations,
            elapsed: Duration::from_micros(20),
        });
        assert_eq!(source.read(), Err(AuthenticationTimeError));
        kernel.set(sample(snapshot()));
        assert_eq!(source.read().unwrap().synchronization_generation, 2);
    }
}

#[test]
fn linux_time_transient_errors_and_invalid_data_do_not_forge_resynchronization() {
    let (kernel, source) = source();
    assert_eq!(source.read().unwrap().synchronization_generation, 1);
    for error in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Unsupported,
        io::ErrorKind::Other,
    ] {
        kernel.set(KernelSample {
            observations: [Err(error); 2],
            elapsed: Duration::ZERO,
        });
        assert_eq!(source.read(), Err(AuthenticationTimeError));
        kernel.set(sample(snapshot()));
        assert_eq!(source.read().unwrap().synchronization_generation, 1);
    }
    for observed in [
        RealtimeSnapshot {
            state: 99,
            ..snapshot()
        },
        RealtimeSnapshot {
            state: 99,
            status: STA_UNSYNC,
            ..snapshot()
        },
        RealtimeSnapshot {
            status: STA_UNSYNC | (1 << 16),
            ..snapshot()
        },
        RealtimeSnapshot {
            state: TIME_OOP,
            ..snapshot()
        },
        RealtimeSnapshot {
            maximum_error_micros: 0,
            ..snapshot()
        },
    ] {
        kernel.set(sample(observed));
        assert_eq!(source.read(), Err(AuthenticationTimeError));
        kernel.set(sample(snapshot()));
        assert_eq!(source.read().unwrap().synchronization_generation, 1);
    }
}

#[tokio::test(start_paused = true)]
async fn linux_time_budget_is_fixed_and_endpoint_overflow_is_refused() {
    let (kernel, source) = source();
    let exact = IntervalClock::new(source.clone(), UNCERTAINTY).unwrap();
    let smaller = IntervalClock::new(source.clone(), Duration::from_micros(10_521)).unwrap();
    assert_eq!(exact.interval(), Ok(interval(now())));
    for _ in 0..3 {
        assert_eq!(smaller.interval(), Err(AuthenticationTimeError));
    }
    kernel.set(sample(RealtimeSnapshot {
        maximum_error_micros: 10_001,
        ..snapshot()
    }));
    assert_eq!(exact.interval(), Err(AuthenticationTimeError));
    kernel.set(sample(snapshot()));
    assert_eq!(exact.interval(), Ok(interval(now())));
    assert_eq!(source.read().unwrap().synchronization_generation, 1);
    for value in [time::PrimitiveDateTime::MIN, time::PrimitiveDateTime::MAX] {
        kernel.set(at(Timestamp::from_offset_datetime(value.assume_utc())));
        let clock = IntervalClock::new(source.clone(), UNCERTAINTY).unwrap();
        assert_eq!(clock.interval(), Err(AuthenticationTimeError));
    }
}

#[tokio::test(start_paused = true)]
async fn linux_time_steps_recover_only_after_consistent_monotonic_progress() {
    for offset in [-10, 10] {
        let (kernel, source) = source();
        let clock = IntervalClock::new(source.clone(), UNCERTAINTY).unwrap();
        assert_eq!(clock.interval(), Ok(interval(now())));
        kernel.set(at(now().add_seconds(offset).unwrap()));
        for _ in 0..10 {
            assert_eq!(clock.interval(), Err(AuthenticationTimeError));
        }
        assert_eq!(source.read().unwrap().synchronization_generation, 1);
        for elapsed in 1..=3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            let observed = now().add_seconds(offset + elapsed).unwrap();
            kernel.set(at(observed));
            assert_eq!(
                clock.interval(),
                if elapsed < 3 {
                    Err(AuthenticationTimeError)
                } else {
                    Ok(interval(observed))
                }
            );
        }
    }
}

#[test]
fn linux_time_generations_never_wrap_and_concurrent_reads_share_one_episode() {
    let (kernel, source) = source();
    assert_eq!(source.read().unwrap().synchronization_generation, 1);
    kernel.set(sample(RealtimeSnapshot {
        state: TIME_ERROR,
        ..snapshot()
    }));
    assert_eq!(source.read(), Err(AuthenticationTimeError));
    kernel.set(sample(snapshot()));
    std::thread::scope(|threads| {
        for _ in 0..8 {
            let source = source.clone();
            threads.spawn(move || {
                assert_eq!(source.read().unwrap().synchronization_generation, 2);
            });
        }
    });
    let mut state = source.state.lock().unwrap();
    state.generation = u64::MAX;
    state.lost_synchronization = true;
    drop(state);
    assert_eq!(source.read(), Err(AuthenticationTimeError));
    assert_eq!(source.state.lock().unwrap().generation, u64::MAX);
}

#[tokio::test(start_paused = true)]
async fn linux_time_recovery_does_not_activate_close_or_drain_effects() {
    let (kernel, source) = source();
    let clock = IntervalClock::new(source.clone(), UNCERTAINTY).unwrap();
    let gate = EffectGate::new();
    assert_eq!(clock.interval(), Ok(interval(now())));
    assert!(gate.enter().await.is_err());
    let candidate = gate.candidate().await.unwrap();
    kernel.set(sample(RealtimeSnapshot {
        state: TIME_ERROR,
        ..snapshot()
    }));
    assert_eq!(clock.interval(), Err(AuthenticationTimeError));
    assert!(gate.enter().await.is_err());
    drop(candidate);
    gate.activate().await.unwrap();
    let effect = gate.enter().await.unwrap();
    kernel.set(sample(snapshot()));
    assert_eq!(clock.interval(), Ok(interval(now())));
    assert_eq!(source.read().unwrap().synchronization_generation, 2);
    drop(gate.enter().await.unwrap());
    let mut quiescence = Box::pin(gate.quiesce());
    assert!(futures_util::poll!(&mut quiescence).is_pending());
    kernel.set(sample(RealtimeSnapshot {
        state: TIME_ERROR,
        ..snapshot()
    }));
    assert_eq!(clock.interval(), Err(AuthenticationTimeError));
    assert!(futures_util::poll!(&mut quiescence).is_pending());
    kernel.set(sample(snapshot()));
    assert_eq!(clock.interval(), Ok(interval(now())));
    assert_eq!(source.read().unwrap().synchronization_generation, 3);
    assert!(futures_util::poll!(&mut quiescence).is_pending());
    assert!(gate.enter().await.is_err());
    assert!(gate.candidate().await.is_err());
    drop(effect);
    assert_ne!(quiescence.await.unwrap().fence_nonce(), &[0; 32]);
    assert!(gate.activate().await.is_err());
}

#[test]
fn linux_time_refusal_logs_only_changes_and_one_recovery() {
    struct Events(Arc<Mutex<Vec<tracing::Level>>>);
    impl tracing::Subscriber for Events {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target() == LOG_TARGET
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            self.0.lock().unwrap().push(*event.metadata().level());
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Events(events.clone()), || {
        let (kernel, source) = source();
        kernel.set(sample(RealtimeSnapshot {
            state: TIME_ERROR,
            ..snapshot()
        }));
        for _ in 0..16 {
            assert_eq!(source.read(), Err(AuthenticationTimeError));
        }
        assert_eq!(*events.lock().unwrap(), [tracing::Level::WARN]);
        kernel.set(KernelSample {
            observations: [Err(io::ErrorKind::PermissionDenied); 2],
            elapsed: Duration::ZERO,
        });
        for _ in 0..16 {
            assert_eq!(source.read(), Err(AuthenticationTimeError));
        }
        assert_eq!(
            *events.lock().unwrap(),
            [tracing::Level::WARN, tracing::Level::WARN]
        );
        kernel.set(sample(snapshot()));
        for _ in 0..16 {
            assert!(source.read().is_ok());
        }
        assert_eq!(
            *events.lock().unwrap(),
            [
                tracing::Level::WARN,
                tracing::Level::WARN,
                tracing::Level::INFO
            ]
        );
    });
}
