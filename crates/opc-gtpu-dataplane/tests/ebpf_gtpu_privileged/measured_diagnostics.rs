use super::*;
use std::fmt;
use std::process::Output;

/// Read diagnostics only while formatting a failed measured assertion.
pub(super) struct DatapathDiagnostics<'a> {
    pub pin_dir: &'a Path,
    pub redirects_before: u64,
    pub iteration: &'a str,
}

impl fmt::Display for DatapathDiagnostics<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&render(
            self.redirects_before,
            self.iteration,
            |map, index| read_counter(self.pin_dir, map, index),
            |arguments| {
                // Collect only after failure. A broken diagnostic command must
                // not hang the test or replace its original assertion.
                Command::new("timeout")
                    .args(["--signal=KILL", "1s", "ip"])
                    .args(arguments)
                    .output()
            },
        ))
    }
}

fn read_counter(pin_dir: &Path, name: &str, index: u32) -> Result<u64, String> {
    let data = MapData::from_pin(pin_dir.join(name)).map_err(|error| error.to_string())?;
    let map = Map::from_map_data(data).map_err(|error| error.to_string())?;
    let counters = PerCpuArray::<_, u64>::try_from(map).map_err(|error| error.to_string())?;
    let values = counters.get(&index, 0).map_err(|error| error.to_string())?;
    Ok(values.iter().copied().fold(0, u64::saturating_add))
}

fn render(
    redirects_before: u64,
    iteration: &str,
    mut counter: impl FnMut(&str, u32) -> Result<u64, String>,
    mut command: impl FnMut(&[&str]) -> io::Result<Output>,
) -> String {
    let redirects = counter(MAP_COUNTERS, COUNTER_UL_REDIRECT_RESOLVED);
    let delta = match &redirects {
        Ok(current) => match current.checked_sub(redirects_before) {
            Some(delta) => delta.to_string(),
            None => "unavailable (counter decreased)".to_owned(),
        },
        Err(error) => format!("unavailable ({error})"),
    };
    let mut report = format!(
        "DATAPATH_TIMEOUT {iteration} redirects_before={redirects_before} \
         redirects_current={redirects:?} redirect_delta={delta}\n"
    );
    for (map, index, name) in [
        (MAP_COUNTERS, COUNTER_UL_ENCAP, "uplink_encapsulated"),
        (MAP_COUNTERS, COUNTER_UL_FAR_MISS, "uplink_far_misses"),
        (
            MAP_COUNTERS,
            COUNTER_UL_FAR_MISS_PASSED,
            "uplink_far_misses_passed",
        ),
        (
            MAP_COUNTERS,
            COUNTER_UL_FAR_MISS_DROPPED,
            "uplink_far_misses_dropped",
        ),
        (MAP_COUNTERS, COUNTER_DL_DECAP, "downlink_decapsulated"),
        (
            MAP_COUNTERS,
            COUNTER_DL_UNKNOWN_TEID,
            "downlink_unknown_teid",
        ),
        (MAP_COUNTERS, COUNTER_DL_MALFORMED, "downlink_malformed"),
        (
            MAP_COUNTERS,
            COUNTER_DL_DST_MISMATCH,
            "downlink_destination_mismatches",
        ),
        (
            MAP_COUNTERS,
            COUNTER_DL_MISSING_CONSUMER,
            "downlink_missing_consumer",
        ),
        (
            MAP_DOWNLINK_BINDING_COUNTERS,
            COUNTER_DL_BINDING_INVALID,
            "downlink_binding_invalid",
        ),
        (
            MAP_DOWNLINK_BINDING_COUNTERS,
            COUNTER_DL_BINDING_FAMILY_MISMATCH,
            "downlink_binding_family_mismatches",
        ),
        (
            MAP_DOWNLINK_BINDING_COUNTERS,
            COUNTER_DL_BINDING_PEER_MISMATCH,
            "downlink_binding_peer_mismatches",
        ),
        (
            MAP_DOWNLINK_BINDING_COUNTERS,
            COUNTER_DL_BINDING_LOCAL_MISMATCH,
            "downlink_binding_local_mismatches",
        ),
        (
            MAP_DOWNLINK_BINDING_COUNTERS,
            COUNTER_DL_BINDING_INGRESS_MISMATCH,
            "downlink_binding_ingress_mismatches",
        ),
        (
            MAP_DOWNLINK_BINDING_COUNTERS,
            COUNTER_DL_BINDING_SOURCE_PORT_MISMATCH,
            "downlink_binding_source_port_mismatches",
        ),
        (
            MAP_UPLINK_PMTU_COUNTERS,
            COUNTER_UL_MTU_REJECT,
            "uplink_mtu_rejected",
        ),
        (
            MAP_UPLINK_PMTU_COUNTERS,
            COUNTER_UL_PMTU_CORRUPT,
            "uplink_mtu_policy_corrupt",
        ),
        (
            MAP_TFT_CLASSIFIER_COUNTERS,
            opc_gtpu_ebpf_common::COUNTER_TFT_CLASSIFIER_MALFORMED,
            "tft_classifier_malformed",
        ),
        (
            MAP_TFT_CLASSIFIER_COUNTERS,
            COUNTER_TFT_CLASSIFIER_NO_MATCH,
            "tft_classifier_no_match",
        ),
        (
            MAP_TFT_CLASSIFIER_COUNTERS,
            opc_gtpu_ebpf_common::COUNTER_TFT_CLASSIFIER_INVALID_STATE,
            "tft_classifier_invalid_state",
        ),
        (
            MAP_TFT_CLASSIFIER_COUNTERS,
            opc_gtpu_ebpf_common::COUNTER_TFT_CLASSIFIER_CAPACITY,
            "tft_classifier_capacity",
        ),
    ] {
        let value = match counter(map, index) {
            Ok(value) => value.to_string(),
            Err(error) => format!("unavailable ({error})"),
        };
        report.push_str(&format!("{name}={value}\n"));
    }
    for arguments in [
        &["-6", "addr", "show", "tentative"][..],
        &["-4", "neigh", "show"],
        &["-6", "neigh", "show"],
        &["-4", "route", "show", "table", "all"],
        &["-6", "route", "show", "table", "all"],
    ] {
        report.push_str(&format!("ip {}: ", arguments.join(" ")));
        match command(arguments) {
            Ok(output) => report.push_str(&format!(
                "status={} stdout={} stderr={}\n",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )),
            Err(error) => report.push_str(&format!("unavailable ({error})\n")),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn forced_timeout(report: impl FnOnce() -> String) -> String {
        let deadline = Instant::now();
        let failure = std::panic::catch_unwind(AssertUnwindSafe(|| {
            assert!(
                Instant::now() < deadline,
                "six GPDU redirects must precede retirement\n{}",
                report()
            );
        }))
        .expect_err("an expired measured assertion must still fail");
        *failure.downcast::<String>().expect("formatted panic")
    }

    #[test]
    fn forced_timeout_reports_redirect_delta_iteration_and_datapath_state() {
        for shared_peer_tunnel in [false, true] {
            let iteration = format!("shared_peer_tunnel={shared_peer_tunnel}");
            let message = forced_timeout(|| {
                render(
                    40,
                    &iteration,
                    |map, index| {
                        Ok(match (map, index) {
                            (MAP_COUNTERS, COUNTER_UL_REDIRECT_RESOLVED) => 43,
                            (MAP_COUNTERS, COUNTER_UL_ENCAP) => 17,
                            (MAP_COUNTERS, COUNTER_UL_FAR_MISS_PASSED) => 2,
                            (MAP_COUNTERS, COUNTER_UL_FAR_MISS_DROPPED) => 3,
                            (MAP_COUNTERS, COUNTER_DL_MISSING_CONSUMER) => 8,
                            (MAP_DOWNLINK_BINDING_COUNTERS, COUNTER_DL_BINDING_PEER_MISMATCH) => 4,
                            (MAP_UPLINK_PMTU_COUNTERS, COUNTER_UL_MTU_REJECT) => 5,
                            (MAP_TFT_CLASSIFIER_COUNTERS, COUNTER_TFT_CLASSIFIER_NO_MATCH) => 6,
                            (
                                MAP_TFT_CLASSIFIER_COUNTERS,
                                opc_gtpu_ebpf_common::COUNTER_TFT_CLASSIFIER_CAPACITY,
                            ) => 7,
                            _ => 0,
                        })
                    },
                    |arguments| {
                        Ok(Output {
                            status: std::process::ExitStatus::from_raw(9 << 8),
                            stdout: format!("state for {}", arguments.join(" ")).into_bytes(),
                            stderr: b"diagnostic warning".to_vec(),
                        })
                    },
                )
            });
            for expected in [
                "six GPDU redirects must precede retirement",
                &iteration,
                "redirect_delta=3",
                "uplink_encapsulated=17",
                "uplink_far_misses_passed=2",
                "uplink_far_misses_dropped=3",
                "downlink_missing_consumer=8",
                "downlink_binding_peer_mismatches=4",
                "uplink_mtu_rejected=5",
                "tft_classifier_no_match=6",
                "tft_classifier_capacity=7",
                "-6 addr show tentative",
                "-4 neigh show",
                "-6 neigh show",
                "-4 route show table all",
                "-6 route show table all",
                "status=exit status: 9",
                "stderr=diagnostic warning",
            ] {
                assert!(
                    message.contains(expected),
                    "missing {expected:?}: {message}"
                );
            }
            assert!(
                !message.contains("INVITE") && !message.contains("password"),
                "diagnostics must stay value-free: {message}"
            );
        }
    }

    #[test]
    fn forced_timeout_preserves_the_failure_when_diagnostics_are_unavailable() {
        let message = forced_timeout(|| {
            render(
                40,
                "shared_peer_tunnel=true",
                |_, _| Err("counter unavailable".to_owned()),
                |_| Err(io::Error::new(io::ErrorKind::NotFound, "ip unavailable")),
            )
        });
        for expected in [
            "six GPDU redirects must precede retirement",
            "redirect_delta=unavailable",
            "counter unavailable",
            "ip unavailable",
            "-6 route show table all",
        ] {
            assert!(
                message.contains(expected),
                "missing {expected:?}: {message}"
            );
        }
    }
}
