//! Independent actual-object oracle for the root-cgroup egress fence.
//!
//! This crate intentionally does not depend on `opc-egress-fence-common` or
//! the host crate. Every map layout, command byte, L3 packet, return value, and
//! expected transition below is independently encoded from the frozen ABI.

use std::error::Error;
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Barrier};

use aya::maps::{Array, Map, MapData};
use aya::programs::{CgroupSkb, SchedClassifier, TestRun, TestRunOptions};
use aya::{Ebpf, EbpfLoader};

const PROGRAM_GATE: &str = "opc_egress_gate";
const PROGRAM_CONTROL: &str = "opc_fence_ctl";
const PROGRAM_VIEW: &str = "opc_fence_view";

const MAP_CONFIG: &str = "OPC_FENCE_CFG";
const MAP_COOKIES: &str = "OPC_FENCE_CKS";
const MAP_COUNTERS: &str = "OPC_FENCE_CTR";
const MAP_CURRENT: &str = "OPC_FENCE_CUR";
const MAP_LOCK: &str = "OPC_FENCE_LOCK";
const MAP_MUTATION: &str = "OPC_FENCE_MUT";
const MAP_FAULT: &str = "OPC_FENCE_FLT";

const ABI_VERSION: u16 = 5;
const CONFIG_LEN: usize = 40;
const COMMAND_LEN: usize = 48;
const VIEW_LEN: usize = 128;
const COOKIE_KEY_LEN: u32 = 16;
const COOKIE_VALUE_LEN: usize = 40;
const CURRENT_LEN: usize = 24;
const MUTATION_LEN: usize = 16;
const ROOT_CGROUP_ID: u64 = 1;
const PRODUCTION_CAPACITY: u32 = 4_096;
const MAX_GATE_LIFETIME_NS: u64 = 300_000_000_000;
const ORACLE_DEFECTIVE: &str =
    "egress-fence independent object oracle: DEFECTIVE (object validation failed)";

const OP_PUBLISH_LIFECYCLE: u8 = 1;
const OP_REGISTER: u8 = 2;
const OP_ACTIVATE: u8 = 3;
const OP_REFRESH: u8 = 4;
const OP_CLOSE: u8 = 5;
const OP_RECLAIM: u8 = 6;
const OP_INSPECT: u8 = 7;
const OP_PUBLISH_RETIREMENT: u8 = 8;

const RESULT_APPLIED: u32 = 0;
const RESULT_INVALID: u32 = 1;
const RESULT_STALE_TOKEN: u32 = 2;
const RESULT_COOKIE_MISSING: u32 = 3;
const RESULT_EPOCH_MISMATCH: u32 = 4;
const RESULT_TERMINAL: u32 = 5;
const RESULT_DEADLINE_ELAPSED: u32 = 6;
const RESULT_STATE_MISMATCH: u32 = 7;
const RESULT_MAP_ERROR: u32 = 8;
const RESULT_NOT_RECLAIMABLE: u32 = 9;

const COOKIE_INITIAL: u32 = 0x4f45_0101;
const COOKIE_ACTIVE: u32 = 0x4f45_0102;
const COOKIE_TERMINAL: u32 = 0x4f45_0103;
const COOKIE_RECLAIMING: u32 = 0x4f45_01ff;
const CURRENT_OPEN: u32 = 0x4f45_0201;
const CURRENT_CLOSED: u32 = 0x4f45_0202;
const COOKIE_INITIAL_EPOCH: u64 = 1;

// Deliberately non-palindromic RFC documentation fixtures catch byte swaps.
const IPV4_PROTECTED: [u8; 4] = [192, 0, 2, 37];
const IPV4_UNRELATED: [u8; 4] = [198, 51, 100, 91];
const IPV4_DESTINATION: [u8; 4] = [203, 0, 113, 143];
const IPV6_PROTECTED: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0x9a, 0xbc,
];
const IPV6_UNRELATED: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0x87, 0x65, 0x43, 0x21, 0, 0, 0, 0, 0, 0, 0xcb, 0xa9,
];
const IPV6_DESTINATION: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0xef, 0x01, 0, 0, 0, 0, 0, 0, 0x24, 0x68,
];
const PROTECTED_PORT: u16 = 0x1235;
const UNRELATED_PORT: u16 = 0x4567;

#[derive(Clone, Copy)]
struct Options {
    capacity: u32,
    pressure: bool,
    fault_delete: bool,
}

type ConfigMutation = (&'static str, fn(&mut [u8; CONFIG_LEN]));

#[derive(Clone, Copy)]
struct Command {
    operation: u8,
    cookie: u64,
    token: u64,
    deadline: u64,
    epoch: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Current {
    control: u32,
    token: u64,
    cookie: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Mutation {
    generation: u64,
    claim: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Entry {
    control: u32,
    cookie: u64,
    token: u64,
    deadline: u64,
    epoch: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Snapshot {
    current: Current,
    mutation: Mutation,
    entry: Option<Entry>,
}

struct Run {
    return_value: u32,
    data_size_out: u32,
    ctx_size_out: u32,
    output: Vec<u8>,
}

struct Lab {
    ebpf: Ebpf,
    root_cgroup_id: u64,
}

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    match std::panic::catch_unwind(run) {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(error)) => {
            println!("{}", redacted_failure_line(error.as_ref()));
            ExitCode::from(2)
        }
        Err(_) => {
            println!("{ORACLE_DEFECTIVE}");
            ExitCode::from(2)
        }
    }
}

fn redacted_failure_line(_error: &dyn Error) -> &'static str {
    ORACLE_DEFECTIVE
}

fn run() -> Result<(), Box<dyn Error>> {
    let (object, options) = parse_args()?;

    let ipv4 = config_ipv4(options.capacity);
    let race_lab = Lab::load(&object, ipv4, options)?;
    race_lab.verify_register_race()?;
    drop(race_lab);

    let mut lab = Lab::load(&object, ipv4, options)?;
    lab.verify_program_separation()?;
    lab.verify_control_lifecycle(options.fault_delete)?;
    lab.verify_expired_refresh()?;
    lab.verify_refresh_completion_crossing(options.fault_delete)?;
    lab.verify_stale_reclaim_states(options.fault_delete)?;
    lab.verify_ipv4_l3_gate()?;
    if options.pressure {
        lab.verify_capacity_pressure(options.capacity)?;
    }
    drop(lab);

    let ipv6 = config_ipv6(options.capacity);
    let lab = Lab::load(&object, ipv6, options)?;
    lab.verify_ipv6_l3_gate()?;
    drop(lab);

    verify_config_mutations(&object, options)?;
    verify_test_run_contract_mutations()?;

    println!(
        "egress-fence independent object oracle: PASS (pressure={}, fault_delete={})",
        options.pressure, options.fault_delete
    );
    Ok(())
}

fn parse_args() -> Result<(PathBuf, Options), Box<dyn Error>> {
    let mut pressure = false;
    let mut fault_delete = false;
    let mut object = None;
    for argument in std::env::args_os().skip(1) {
        match argument.to_str() {
            Some("--pressure") => pressure = true,
            Some("--fault-delete") => fault_delete = true,
            Some(value) if value.starts_with('-') => {
                return Err(io::Error::other("unknown oracle option").into());
            }
            _ if object.is_none() => object = Some(PathBuf::from(argument)),
            _ => return Err("multiple object paths supplied".into()),
        }
    }
    let object = object.ok_or(
        "usage: opc-egress-fence-object-oracle [--pressure] \
         [--fault-delete] OBJECT",
    )?;
    Ok((
        object,
        Options {
            capacity: PRODUCTION_CAPACITY,
            pressure,
            fault_delete,
        },
    ))
}

impl Lab {
    fn load(
        object: &Path,
        configuration: [u8; CONFIG_LEN],
        options: Options,
    ) -> Result<Self, Box<dyn Error>> {
        let mut ebpf = EbpfLoader::new().load_file(object)?;
        verify_inventory(&ebpf, options)?;

        {
            let map = ebpf.map_mut(MAP_CONFIG).ok_or("configuration map absent")?;
            let mut config: Array<_, [u8; CONFIG_LEN]> = Array::try_from(map)?;
            config.set(0, configuration, 0)?;
        }
        for name in [
            MAP_CONFIG,
            MAP_COOKIES,
            MAP_COUNTERS,
            MAP_CURRENT,
            MAP_MUTATION,
        ] {
            freeze_map(ebpf.map(name).ok_or("authority map absent")?)?;
        }
        {
            let map = ebpf.map_mut(MAP_CONFIG).ok_or("configuration map absent")?;
            let mut config: Array<_, [u8; CONFIG_LEN]> = Array::try_from(map)?;
            ensure(
                config.set(0, configuration, 0).is_err(),
                "frozen CONFIG accepted a userspace update",
            )?;
        }

        let gate: &mut CgroupSkb = ebpf
            .program_mut(PROGRAM_GATE)
            .ok_or("gate program absent")?
            .try_into()?;
        gate.load()?;
        let control: &mut SchedClassifier = ebpf
            .program_mut(PROGRAM_CONTROL)
            .ok_or("control program absent")?
            .try_into()?;
        control.load()?;
        let view: &mut SchedClassifier = ebpf
            .program_mut(PROGRAM_VIEW)
            .ok_or("view program absent")?
            .try_into()?;
        view.load()?;

        Ok(Self {
            ebpf,
            root_cgroup_id: ROOT_CGROUP_ID,
        })
    }

    fn verify_program_separation(&self) -> Result<(), Box<dyn Error>> {
        let inspect = command_bytes(
            self.root_cgroup_id,
            Command {
                operation: OP_INSPECT,
                cookie: 0,
                token: 0,
                deadline: 0,
                epoch: 0,
            },
        );
        let mut inspect_request = [0_u8; VIEW_LEN];
        inspect_request[..COMMAND_LEN].copy_from_slice(&inspect);
        expect(
            self.run_control_raw(&inspect_request)?.return_value,
            RESULT_INVALID,
            "mutation control accepted Inspect",
        )?;

        let publish = command_bytes(
            self.root_cgroup_id,
            Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token: 1,
                deadline: 0,
                epoch: 0,
            },
        );
        let mut publish_as_view = [0_u8; VIEW_LEN];
        publish_as_view[..COMMAND_LEN].copy_from_slice(&publish);
        expect(
            self.run_view_raw(&publish_as_view)?.return_value,
            RESULT_INVALID,
            "read-only view accepted mutation operation",
        )?;
        expect(
            self.run_view_raw(&inspect)?.return_value,
            RESULT_INVALID,
            "read-only view accepted a short request",
        )?;

        let mut nonzero_tail = inspect_request;
        nonzero_tail[VIEW_LEN - 1] = 1;
        expect(
            self.run_view_raw(&nonzero_tail)?.return_value,
            RESULT_INVALID,
            "read-only view accepted nonzero request tail",
        )?;
        Ok(())
    }

    fn verify_register_race(&self) -> Result<(), Box<dyn Error>> {
        const COOKIE: u64 = 0xc39d_71a5_2468_bdf1;
        const TOKEN: u64 = 91;
        const CONCURRENCY: usize = 16;

        expect(
            self.control(Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token: TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "race lifecycle publish",
        )?;

        let input = command_bytes(
            self.root_cgroup_id,
            Command {
                operation: OP_REGISTER,
                cookie: COOKIE,
                token: TOKEN,
                deadline: 0,
                epoch: 0,
            },
        );
        let control: &SchedClassifier = self
            .ebpf
            .program(PROGRAM_CONTROL)
            .ok_or("control program absent")?
            .try_into()?;
        let barrier = Arc::new(Barrier::new(CONCURRENCY + 1));
        let results = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(CONCURRENCY);
            for _ in 0..CONCURRENCY {
                let barrier = Arc::clone(&barrier);
                handles.push(scope.spawn(move || {
                    barrier.wait();
                    let run = run_sched(control, &input)
                        .map_err(|_| "racing control TEST_RUN failed".to_owned())?;
                    if run.data_size_out != COMMAND_LEN as u32
                        || run.ctx_size_out != 0
                        || run.output != input
                    {
                        return Err("racing control TEST_RUN shape changed".to_owned());
                    }
                    Ok(run.return_value)
                }));
            }
            barrier.wait();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| "racing control thread panicked".to_owned())?
                })
                .collect::<Result<Vec<_>, String>>()
        })
        .map_err(io::Error::other)?;

        ensure(
            results.contains(&RESULT_APPLIED),
            "register race had no successful linearization",
        )?;
        ensure(
            results
                .iter()
                .all(|result| matches!(*result, RESULT_APPLIED | RESULT_MAP_ERROR)),
            "register race returned a noncanonical contention result",
        )?;

        let snapshot = self.view(COOKIE, TOKEN)?;
        ensure(
            snapshot.current
                == Current {
                    control: CURRENT_OPEN,
                    token: TOKEN,
                    cookie: COOKIE,
                }
                && snapshot.entry
                    == Some(Entry {
                        control: COOKIE_INITIAL,
                        cookie: COOKIE,
                        token: TOKEN,
                        deadline: 0,
                        epoch: COOKIE_INITIAL_EPOCH,
                    })
                && snapshot.mutation.generation > 0
                && snapshot.mutation.claim == 0,
            "register race left noncanonical authority",
        )
    }

    fn verify_control_lifecycle(&mut self, fault_delete: bool) -> Result<(), Box<dyn Error>> {
        const COOKIE: u64 = 0xa5c3_7e91_2468_bdf1;
        const TOKEN: u64 = 71;

        let initial = self.view(0, 0)?;
        expect_snapshot(
            initial,
            Snapshot {
                current: Current {
                    control: 0,
                    token: 0,
                    cookie: 0,
                },
                mutation: Mutation {
                    generation: 0,
                    claim: 0,
                },
                entry: None,
            },
            "fresh authority",
        )?;

        expect(
            self.control(Command {
                operation: OP_REGISTER,
                cookie: COOKIE,
                token: TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_STALE_TOKEN,
            "register before publication",
        )?;
        expect(
            self.control(Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token: TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "publish lifecycle",
        )?;
        expect(
            self.control(Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token: TOKEN - 2,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_STALE_TOKEN,
            "token regression",
        )?;
        expect(
            self.control(Command {
                operation: OP_ACTIVATE,
                cookie: COOKIE,
                token: TOKEN,
                deadline: checked_add(boottime_ns()?, 1_000_000_000)?,
                epoch: 1,
            })?,
            RESULT_COOKIE_MISSING,
            "activate missing cookie",
        )?;
        expect(
            self.control(Command {
                operation: OP_REGISTER,
                cookie: COOKIE,
                token: TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "register",
        )?;
        expect(
            self.control(Command {
                operation: OP_REGISTER,
                cookie: COOKIE + 1,
                token: TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_STATE_MISMATCH,
            "conflicting registration",
        )?;

        let registered = self.view(COOKIE, TOKEN)?;
        expect_snapshot(
            registered,
            Snapshot {
                current: Current {
                    control: CURRENT_OPEN,
                    token: TOKEN,
                    cookie: COOKIE,
                },
                mutation: Mutation {
                    generation: 1,
                    claim: 0,
                },
                entry: Some(Entry {
                    control: COOKIE_INITIAL,
                    cookie: COOKIE,
                    token: TOKEN,
                    deadline: 0,
                    epoch: 1,
                }),
            },
            "registered snapshot",
        )?;

        let now = boottime_ns()?;
        let deadline = checked_add(now, 30_000_000_000)?;
        expect(
            self.control(Command {
                operation: OP_ACTIVATE,
                cookie: COOKIE,
                token: TOKEN,
                deadline,
                epoch: 1,
            })?,
            RESULT_APPLIED,
            "activate",
        )?;
        expect(
            self.control(Command {
                operation: OP_REFRESH,
                cookie: COOKIE,
                token: TOKEN,
                deadline: deadline + 1,
                epoch: 1,
            })?,
            RESULT_EPOCH_MISMATCH,
            "refresh stale epoch",
        )?;
        expect(
            self.control(Command {
                operation: OP_RECLAIM,
                cookie: COOKIE,
                token: TOKEN,
                deadline: 0,
                epoch: 2,
            })?,
            RESULT_NOT_RECLAIMABLE,
            "reclaim current lifecycle",
        )?;

        let refreshed_deadline = deadline + 1_000_000_000;
        expect(
            self.control(Command {
                operation: OP_REFRESH,
                cookie: COOKIE,
                token: TOKEN,
                deadline: refreshed_deadline,
                epoch: 2,
            })?,
            RESULT_APPLIED,
            "refresh",
        )?;
        let active = self.view(COOKIE, TOKEN)?;
        expect(
            active.entry.map(|entry| entry.control).unwrap_or_default(),
            COOKIE_ACTIVE,
            "active state",
        )?;
        ensure(
            active.entry
                == Some(Entry {
                    control: COOKIE_ACTIVE,
                    cookie: COOKIE,
                    token: TOKEN,
                    deadline: refreshed_deadline,
                    epoch: 3,
                }),
            "active snapshot mismatch",
        )?;

        let too_far = checked_add(boottime_ns()?, MAX_GATE_LIFETIME_NS + 1_000_000_000)?;
        expect(
            self.control(Command {
                operation: OP_REFRESH,
                cookie: COOKIE,
                token: TOKEN,
                deadline: too_far,
                epoch: 3,
            })?,
            RESULT_DEADLINE_ELAPSED,
            "deadline ceiling",
        )?;
        expect(
            self.control(Command {
                operation: OP_CLOSE,
                cookie: COOKIE,
                token: TOKEN,
                deadline: 0,
                epoch: 3,
            })?,
            RESULT_APPLIED,
            "close",
        )?;
        expect(
            self.control(Command {
                operation: OP_ACTIVATE,
                cookie: COOKIE,
                token: TOKEN,
                deadline: refreshed_deadline + 1,
                epoch: 4,
            })?,
            RESULT_TERMINAL,
            "terminal reopen",
        )?;
        expect(
            self.control(Command {
                operation: OP_PUBLISH_RETIREMENT,
                cookie: 0,
                token: TOKEN + 1,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "publish retirement",
        )?;

        let first_reclaim = self.control(Command {
            operation: OP_RECLAIM,
            cookie: COOKIE,
            token: TOKEN,
            deadline: 0,
            epoch: 4,
        })?;
        if fault_delete {
            expect(
                first_reclaim,
                RESULT_MAP_ERROR,
                "faulted stale delete did not report unknown outcome",
            )?;
            let recovering = self.view(COOKIE, TOKEN)?;
            ensure(
                recovering.entry
                    == Some(Entry {
                        control: COOKIE_RECLAIMING,
                        cookie: COOKIE,
                        token: TOKEN,
                        deadline: 0,
                        epoch: 4,
                    })
                    && recovering.mutation.claim == 0,
                "stale delete did not retain exact RECLAIMING state",
            )?;
            expect(
                self.control(Command {
                    operation: OP_RECLAIM,
                    cookie: COOKIE,
                    token: TOKEN,
                    deadline: 0,
                    epoch: 4,
                })?,
                RESULT_APPLIED,
                "stale RECLAIMING retry",
            )?;
        } else {
            expect(first_reclaim, RESULT_APPLIED, "stale terminal reclaim")?;
        }

        let reclaimed = self.view(COOKIE, TOKEN)?;
        ensure(
            reclaimed.current
                == Current {
                    control: CURRENT_CLOSED,
                    token: TOKEN + 1,
                    cookie: 0,
                }
                && reclaimed.entry.is_none()
                && reclaimed.mutation.claim == 0,
            "reclaimed snapshot mismatch",
        )?;
        Ok(())
    }

    fn verify_expired_refresh(&self) -> Result<(), Box<dyn Error>> {
        const COOKIE: u64 = 0xb6d4_8fa2_3579_ce01;
        const TOKEN: u64 = 73;

        expect(
            self.control(Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token: TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "expiry lifecycle publish",
        )?;
        expect(
            self.control(Command {
                operation: OP_REGISTER,
                cookie: COOKIE,
                token: TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "expiry registration",
        )?;
        let prior_deadline = checked_add(boottime_ns()?, 10_000_000)?;
        expect(
            self.control(Command {
                operation: OP_ACTIVATE,
                cookie: COOKIE,
                token: TOKEN,
                deadline: prior_deadline,
                epoch: 1,
            })?,
            RESULT_APPLIED,
            "expiry activation",
        )?;
        while boottime_ns()? < prior_deadline {
            std::hint::spin_loop();
        }
        let requested_deadline = checked_add(boottime_ns()?, 1_000_000_000)?;
        expect(
            self.control(Command {
                operation: OP_REFRESH,
                cookie: COOKIE,
                token: TOKEN,
                deadline: requested_deadline,
                epoch: 2,
            })?,
            RESULT_DEADLINE_ELAPSED,
            "expired refresh",
        )?;
        let snapshot = self.view(COOKIE, TOKEN)?;
        ensure(
            snapshot.entry
                == Some(Entry {
                    control: COOKIE_TERMINAL,
                    cookie: COOKIE,
                    token: TOKEN,
                    deadline: 0,
                    epoch: 3,
                })
                && snapshot.mutation.claim == 0,
            "expired refresh did not leave a terminal entry",
        )?;
        expect(
            self.control(Command {
                operation: OP_PUBLISH_RETIREMENT,
                cookie: 0,
                token: TOKEN + 1,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "expiry retirement",
        )?;
        expect(
            self.control(Command {
                operation: OP_RECLAIM,
                cookie: COOKIE,
                token: TOKEN,
                deadline: 0,
                epoch: 3,
            })?,
            RESULT_APPLIED,
            "expiry reclaim",
        )
    }

    fn verify_refresh_completion_crossing(
        &mut self,
        fault_delete: bool,
    ) -> Result<(), Box<dyn Error>> {
        if !fault_delete {
            return Ok(());
        }

        const COOKIE: u64 = 0xc1a7_4d93_68be_250f;
        const TOKEN: u64 = 75;
        expect(
            self.control(Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token: TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "completion-crossing lifecycle publish",
        )?;
        expect(
            self.control(Command {
                operation: OP_REGISTER,
                cookie: COOKIE,
                token: TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "completion-crossing register",
        )?;
        let prior_deadline = checked_add(boottime_ns()?, 30_000_000_000)?;
        expect(
            self.control(Command {
                operation: OP_ACTIVATE,
                cookie: COOKIE,
                token: TOKEN,
                deadline: prior_deadline,
                epoch: 1,
            })?,
            RESULT_APPLIED,
            "completion-crossing activate",
        )?;
        let requested_deadline = checked_add(prior_deadline, 30_000_000_000)?;
        self.arm_refresh_completion_fault()?;
        expect(
            self.control(Command {
                operation: OP_REFRESH,
                cookie: COOKIE,
                token: TOKEN,
                deadline: requested_deadline,
                epoch: 2,
            })?,
            RESULT_DEADLINE_ELAPSED,
            "old-only completion crossing",
        )?;
        let terminal = self.view(COOKIE, TOKEN)?;
        ensure(
            terminal.current
                == Current {
                    control: CURRENT_OPEN,
                    token: TOKEN,
                    cookie: COOKIE,
                }
                && terminal.entry
                    == Some(Entry {
                        control: COOKIE_TERMINAL,
                        cookie: COOKIE,
                        token: TOKEN,
                        deadline: 0,
                        epoch: 3,
                    })
                && terminal.mutation.claim == 0,
            "old-only completion crossing did not terminalize",
        )?;
        expect(
            self.control(Command {
                operation: OP_PUBLISH_RETIREMENT,
                cookie: 0,
                token: TOKEN + 1,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "completion-crossing retirement",
        )?;
        expect(
            self.control(Command {
                operation: OP_RECLAIM,
                cookie: COOKIE,
                token: TOKEN,
                deadline: 0,
                epoch: 3,
            })?,
            RESULT_APPLIED,
            "completion-crossing reclaim",
        )
    }

    fn verify_stale_reclaim_states(&mut self, fault_delete: bool) -> Result<(), Box<dyn Error>> {
        const INITIAL_COOKIE: u64 = 0xc7e5_90b3_468a_df12;
        const ACTIVE_COOKIE: u64 = 0xd8f6_a1c4_579b_e023;
        const TERMINAL_COOKIE: u64 = 0xe907_b2d5_68ac_f134;
        const INITIAL_TOKEN: u64 = 81;
        const ACTIVE_TOKEN: u64 = 83;
        const TERMINAL_TOKEN: u64 = 85;
        const SUCCESSOR_TOKEN: u64 = 87;

        expect(
            self.control(Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token: INITIAL_TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "stale-initial lifecycle publish",
        )?;
        expect(
            self.control(Command {
                operation: OP_REGISTER,
                cookie: INITIAL_COOKIE,
                token: INITIAL_TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "stale-initial register",
        )?;
        expect(
            self.control(Command {
                operation: OP_RECLAIM,
                cookie: INITIAL_COOKIE,
                token: INITIAL_TOKEN,
                deadline: 0,
                epoch: 1,
            })?,
            RESULT_NOT_RECLAIMABLE,
            "non-stale initial reclaim",
        )?;
        expect(
            self.control(Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token: ACTIVE_TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "stale-initial successor publish",
        )?;
        expect(
            self.control(Command {
                operation: OP_RECLAIM,
                cookie: INITIAL_COOKIE,
                token: INITIAL_TOKEN,
                deadline: 0,
                epoch: 2,
            })?,
            RESULT_EPOCH_MISMATCH,
            "stale-initial exact epoch",
        )?;
        expect(
            self.control(Command {
                operation: OP_RECLAIM,
                cookie: INITIAL_COOKIE,
                token: INITIAL_TOKEN,
                deadline: 0,
                epoch: 1,
            })?,
            RESULT_APPLIED,
            "stale-initial reclaim",
        )?;
        ensure(
            self.view(INITIAL_COOKIE, INITIAL_TOKEN)?.entry.is_none(),
            "stale-initial entry survived reclaim",
        )?;

        expect(
            self.control(Command {
                operation: OP_REGISTER,
                cookie: ACTIVE_COOKIE,
                token: ACTIVE_TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "stale-active register",
        )?;
        expect(
            self.control(Command {
                operation: OP_ACTIVATE,
                cookie: ACTIVE_COOKIE,
                token: ACTIVE_TOKEN,
                deadline: checked_add(boottime_ns()?, 30_000_000_000)?,
                epoch: 1,
            })?,
            RESULT_APPLIED,
            "stale-active activate",
        )?;
        expect(
            self.control(Command {
                operation: OP_RECLAIM,
                cookie: ACTIVE_COOKIE,
                token: ACTIVE_TOKEN,
                deadline: 0,
                epoch: 2,
            })?,
            RESULT_NOT_RECLAIMABLE,
            "non-stale active reclaim",
        )?;
        expect(
            self.control(Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token: TERMINAL_TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "stale-active successor publish",
        )?;
        if fault_delete {
            self.arm_delete_fault()?;
        }
        let active_reclaim = self.control(Command {
            operation: OP_RECLAIM,
            cookie: ACTIVE_COOKIE,
            token: ACTIVE_TOKEN,
            deadline: 0,
            epoch: 2,
        })?;
        if fault_delete {
            expect(
                active_reclaim,
                RESULT_MAP_ERROR,
                "faulted stale-active delete did not report unknown outcome",
            )?;
            let recovering = self.view(ACTIVE_COOKIE, ACTIVE_TOKEN)?;
            ensure(
                recovering.current
                    == Current {
                        control: CURRENT_OPEN,
                        token: TERMINAL_TOKEN,
                        cookie: 0,
                    }
                    && recovering.entry
                        == Some(Entry {
                            control: COOKIE_RECLAIMING,
                            cookie: ACTIVE_COOKIE,
                            token: ACTIVE_TOKEN,
                            deadline: 0,
                            epoch: 2,
                        })
                    && recovering.mutation.claim == 0,
                "stale-active fault did not retain canonical RECLAIMING state",
            )?;
            expect(
                self.control(Command {
                    operation: OP_RECLAIM,
                    cookie: ACTIVE_COOKIE,
                    token: ACTIVE_TOKEN,
                    deadline: 0,
                    epoch: 2,
                })?,
                RESULT_APPLIED,
                "stale-active RECLAIMING retry",
            )?;
        } else {
            expect(active_reclaim, RESULT_APPLIED, "stale-active reclaim")?;
        }
        ensure(
            self.view(ACTIVE_COOKIE, ACTIVE_TOKEN)?.entry.is_none(),
            "stale-active entry survived reclaim",
        )?;

        expect(
            self.control(Command {
                operation: OP_REGISTER,
                cookie: TERMINAL_COOKIE,
                token: TERMINAL_TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "stale-terminal register",
        )?;
        expect(
            self.control(Command {
                operation: OP_CLOSE,
                cookie: TERMINAL_COOKIE,
                token: TERMINAL_TOKEN,
                deadline: 0,
                epoch: 1,
            })?,
            RESULT_APPLIED,
            "stale-terminal close",
        )?;
        expect(
            self.control(Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token: SUCCESSOR_TOKEN,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "stale-terminal successor publish",
        )?;
        expect(
            self.control(Command {
                operation: OP_RECLAIM,
                cookie: TERMINAL_COOKIE,
                token: TERMINAL_TOKEN,
                deadline: 0,
                epoch: 2,
            })?,
            RESULT_APPLIED,
            "stale-terminal reclaim",
        )?;
        let snapshot = self.view(TERMINAL_COOKIE, TERMINAL_TOKEN)?;
        ensure(
            snapshot.current
                == Current {
                    control: CURRENT_OPEN,
                    token: SUCCESSOR_TOKEN,
                    cookie: 0,
                }
                && snapshot.entry.is_none()
                && snapshot.mutation.claim == 0,
            "stale-state cleanup left ambiguous authority",
        )
    }

    fn arm_delete_fault(&mut self) -> Result<(), Box<dyn Error>> {
        let map = self
            .ebpf
            .map_mut(MAP_FAULT)
            .ok_or("delete-fault map absent")?;
        let mut faults: Array<_, u32> = Array::try_from(map)?;
        faults.set(1, 0, 0)?;
        Ok(())
    }

    fn arm_refresh_completion_fault(&mut self) -> Result<(), Box<dyn Error>> {
        let map = self
            .ebpf
            .map_mut(MAP_FAULT)
            .ok_or("refresh-fault map absent")?;
        let mut faults: Array<_, u32> = Array::try_from(map)?;
        faults.set(0, 1, 0)?;
        Ok(())
    }

    fn verify_ipv4_l3_gate(&self) -> Result<(), Box<dyn Error>> {
        expect(
            self.gate(&ipv4_udp(IPV4_PROTECTED, PROTECTED_PORT, 5, 0))?,
            0,
            "IPv4 protected",
        )?;
        expect(
            self.gate(&ipv4_udp(IPV4_UNRELATED, PROTECTED_PORT, 5, 0))?,
            1,
            "IPv4 unrelated source",
        )?;
        expect(
            self.gate(&ipv4_non_udp(IPV4_PROTECTED, 6))?,
            1,
            "IPv4 non-UDP",
        )?;
        expect(
            self.gate(&ipv4_udp(IPV4_PROTECTED, UNRELATED_PORT, 5, 0))?,
            1,
            "IPv4 unrelated UDP port",
        )?;
        expect(
            self.gate(&ipv4_udp(IPV4_PROTECTED, PROTECTED_PORT, 6, 0))?,
            0,
            "IPv4 options",
        )?;
        expect(
            self.gate(&ipv4_udp(IPV4_PROTECTED, PROTECTED_PORT, 5, 0x2000))?,
            0,
            "IPv4 more-fragments ambiguity",
        )?;
        expect(
            self.gate(&ipv4_udp(IPV4_PROTECTED, PROTECTED_PORT, 5, 1))?,
            0,
            "IPv4 noninitial fragment ambiguity",
        )?;
        expect(
            self.gate(&ipv4_udp(IPV4_PROTECTED, PROTECTED_PORT, 5, 0x8000))?,
            0,
            "IPv4 reserved-fragment ambiguity",
        )?;
        expect(self.gate(&[])?, 0, "empty L3 packet")?;
        expect(self.gate(&[0x45, 0, 0, 20])?, 0, "truncated IPv4")?;

        // A tc/Ethernet parser substituted into the cgroup hook reads the
        // source-address bytes as an EtherType and drops this valid unrelated
        // raw L3 packet, so the expected keep is a direct detector.
        expect(
            self.gate(&ipv4_udp(IPV4_UNRELATED, UNRELATED_PORT, 5, 0))?,
            1,
            "raw cgroup L3 detector",
        )
    }

    fn verify_ipv6_l3_gate(&self) -> Result<(), Box<dyn Error>> {
        expect(
            self.gate(&ipv6_udp(IPV6_PROTECTED, PROTECTED_PORT, 17, &[]))?,
            0,
            "IPv6 protected",
        )?;
        expect(
            self.gate(&ipv6_udp(IPV6_UNRELATED, PROTECTED_PORT, 17, &[]))?,
            1,
            "IPv6 unrelated source",
        )?;
        expect(
            self.gate(&ipv6_udp(IPV6_PROTECTED, UNRELATED_PORT, 17, &[]))?,
            1,
            "IPv6 unrelated UDP port",
        )?;
        expect(
            self.gate(&ipv6_udp(IPV6_PROTECTED, PROTECTED_PORT, 6, &[]))?,
            1,
            "IPv6 non-UDP",
        )?;

        let destination_options = ipv6_extension(17, 0);
        expect(
            self.gate(&ipv6_udp(
                IPV6_PROTECTED,
                PROTECTED_PORT,
                60,
                &destination_options,
            ))?,
            0,
            "IPv6 destination options",
        )?;
        let atomic = ipv6_fragment(17, 0);
        expect(
            self.gate(&ipv6_udp(IPV6_PROTECTED, PROTECTED_PORT, 44, &atomic))?,
            0,
            "IPv6 atomic fragment",
        )?;
        let fragmented = ipv6_fragment(17, 1);
        expect(
            self.gate(&ipv6_udp(IPV6_PROTECTED, PROTECTED_PORT, 44, &fragmented))?,
            0,
            "IPv6 fragmented ambiguity",
        )?;

        let mut too_many = Vec::new();
        for _ in 0..5 {
            too_many.extend_from_slice(&ipv6_extension(60, 0));
        }
        // Fix the last reachable header to UDP; the fifth extension still
        // exceeds the independently specified traversal bound.
        too_many[4 * 8] = 17;
        expect(
            self.gate(&ipv6_udp(IPV6_PROTECTED, PROTECTED_PORT, 60, &too_many))?,
            0,
            "IPv6 extension ambiguity",
        )
    }

    fn verify_capacity_pressure(&mut self, capacity: u32) -> Result<(), Box<dyn Error>> {
        ensure(
            capacity == PRODUCTION_CAPACITY,
            "pressure oracle requires production map capacity",
        )?;

        // Cycle more unique crash-abandoned initial entries than the frozen
        // map capacity. Each strictly higher lifecycle stales its predecessor,
        // and exact reclamation must keep occupancy bounded.
        let cleanup_rounds = capacity + 1;
        let cleanup_start_token = 101_u64;
        let cleanup_base_cookie = 0x8100_0000_0000_1000_u64;
        for index in 0..cleanup_rounds {
            let token = u64::from(index) * 2 + cleanup_start_token;
            let cookie = cleanup_base_cookie + u64::from(index);
            expect(
                self.control(Command {
                    operation: OP_PUBLISH_LIFECYCLE,
                    cookie: 0,
                    token,
                    deadline: 0,
                    epoch: 0,
                })?,
                RESULT_APPLIED,
                "cleanup-pressure lifecycle publish",
            )?;
            expect(
                self.control(Command {
                    operation: OP_REGISTER,
                    cookie,
                    token,
                    deadline: 0,
                    epoch: 0,
                })?,
                RESULT_APPLIED,
                "cleanup-pressure register",
            )?;
            expect(
                self.control(Command {
                    operation: OP_PUBLISH_LIFECYCLE,
                    cookie: 0,
                    token: token + 2,
                    deadline: 0,
                    epoch: 0,
                })?,
                RESULT_APPLIED,
                "cleanup-pressure successor publish",
            )?;
            expect(
                self.control(Command {
                    operation: OP_RECLAIM,
                    cookie,
                    token,
                    deadline: 0,
                    epoch: 1,
                })?,
                RESULT_APPLIED,
                "cleanup-pressure stale reclaim",
            )?;
        }
        let last_cleanup_token = cleanup_start_token + (u64::from(cleanup_rounds) - 1) * 2;
        let last_cleanup_cookie = cleanup_base_cookie + (u64::from(cleanup_rounds) - 1);
        let cleanup_snapshot = self.view(last_cleanup_cookie, last_cleanup_token)?;
        ensure(
            cleanup_snapshot.entry.is_none() && cleanup_snapshot.mutation.claim == 0,
            "cleanup pressure left an entry or mutation claim",
        )?;

        // Separately retain one terminal predecessor per slot to prove that a
        // genuinely full production map still rejects a successor registration
        // without leaving ambiguous CURRENT ownership.
        let fill_start_token = cleanup_start_token + u64::from(cleanup_rounds) * 2 + 2;
        let fill_base_cookie = 0x8200_0000_0000_1000_u64;
        for index in 0..capacity {
            let token = u64::from(index) * 2 + fill_start_token;
            let cookie = fill_base_cookie + u64::from(index);
            expect(
                self.control(Command {
                    operation: OP_PUBLISH_LIFECYCLE,
                    cookie: 0,
                    token,
                    deadline: 0,
                    epoch: 0,
                })?,
                RESULT_APPLIED,
                "pressure lifecycle publish",
            )?;
            expect(
                self.control(Command {
                    operation: OP_REGISTER,
                    cookie,
                    token,
                    deadline: 0,
                    epoch: 0,
                })?,
                RESULT_APPLIED,
                "pressure register",
            )?;
            expect(
                self.control(Command {
                    operation: OP_CLOSE,
                    cookie,
                    token,
                    deadline: 0,
                    epoch: 1,
                })?,
                RESULT_APPLIED,
                "pressure close",
            )?;
            expect(
                self.control(Command {
                    operation: OP_PUBLISH_RETIREMENT,
                    cookie: 0,
                    token: token + 1,
                    deadline: 0,
                    epoch: 0,
                })?,
                RESULT_APPLIED,
                "pressure retirement",
            )?;
        }
        let token = u64::from(capacity) * 2 + fill_start_token;
        let cookie = fill_base_cookie + u64::from(capacity);
        expect(
            self.control(Command {
                operation: OP_PUBLISH_LIFECYCLE,
                cookie: 0,
                token,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_APPLIED,
            "full-map successor publish",
        )?;
        expect(
            self.control(Command {
                operation: OP_REGISTER,
                cookie,
                token,
                deadline: 0,
                epoch: 0,
            })?,
            RESULT_MAP_ERROR,
            "full map did not fail closed",
        )?;
        let snapshot = self.view(cookie, token)?;
        ensure(
            snapshot.current.cookie == 0
                && snapshot.current.token == token
                && snapshot.entry.is_none()
                && snapshot.mutation.claim == 0,
            "full-map failure left ambiguous authority",
        )
    }

    fn control(&self, command: Command) -> Result<u32, Box<dyn Error>> {
        let input = command_bytes(self.root_cgroup_id, command);
        let run = self.run_control_raw(&input)?;
        ensure(
            run.data_size_out == COMMAND_LEN as u32 && run.ctx_size_out == 0 && run.output == input,
            "control TEST_RUN shape changed",
        )?;
        Ok(run.return_value)
    }

    fn view(&self, cookie: u64, token: u64) -> Result<Snapshot, Box<dyn Error>> {
        let command = command_bytes(
            self.root_cgroup_id,
            Command {
                operation: OP_INSPECT,
                cookie,
                token,
                deadline: 0,
                epoch: 0,
            },
        );
        let mut input = [0_u8; VIEW_LEN];
        input[..COMMAND_LEN].copy_from_slice(&command);
        let run = self.run_view_raw(&input)?;
        expect(run.return_value, RESULT_APPLIED, "view result")?;
        ensure(
            run.data_size_out == VIEW_LEN as u32 && run.ctx_size_out == 0,
            "view TEST_RUN shape changed",
        )?;
        decode_snapshot(&run.output)
    }

    fn gate(&self, packet: &[u8]) -> Result<u32, Box<dyn Error>> {
        // `bpf_prog_test_run_skb` consumes an L2 transport buffer and invokes
        // cgroup-skb after pulling to the network header. The oracle vectors
        // themselves remain raw L3; this envelope is test-run plumbing, not
        // input interpreted by the gate program.
        let input = test_run_skb_envelope(packet);
        let mut output = vec![0_u8; input.len()];
        let gate: &CgroupSkb = self
            .ebpf
            .program(PROGRAM_GATE)
            .ok_or("gate program absent")?
            .try_into()?;
        let result = gate.test_run(TestRunOptions {
            data_in: Some(&input),
            data_out: Some(&mut output),
            repeat: 1,
            ..Default::default()
        })?;
        ensure(
            result.data_size_out == input.len() as u32 && result.ctx_size_out == 0,
            "gate TEST_RUN packet shape changed",
        )?;
        ensure(
            result.return_value == 0 || result.return_value == 1,
            "cgroup gate returned noncanonical verdict/CN bits",
        )?;
        Ok(result.return_value)
    }

    fn run_control_raw(&self, input: &[u8]) -> Result<Run, Box<dyn Error>> {
        let control: &SchedClassifier = self
            .ebpf
            .program(PROGRAM_CONTROL)
            .ok_or("control program absent")?
            .try_into()?;
        run_sched(control, input)
    }

    fn run_view_raw(&self, input: &[u8]) -> Result<Run, Box<dyn Error>> {
        let view: &SchedClassifier = self
            .ebpf
            .program(PROGRAM_VIEW)
            .ok_or("view program absent")?
            .try_into()?;
        run_sched(view, input)
    }
}

fn test_run_skb_envelope(packet: &[u8]) -> Vec<u8> {
    let mut frame = vec![0_u8; 14];
    let ethertype = match packet.first().map(|byte| byte >> 4) {
        Some(4) => 0x0800_u16,
        Some(6) => 0x86dd_u16,
        _ => 0x0800_u16,
    };
    frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

fn run_sched(program: &SchedClassifier, input: &[u8]) -> Result<Run, Box<dyn Error>> {
    let mut output = vec![0_u8; input.len()];
    let result = program.test_run(TestRunOptions {
        data_in: Some(input),
        data_out: Some(&mut output),
        repeat: 1,
        ..Default::default()
    })?;
    Ok(Run {
        return_value: result.return_value,
        data_size_out: result.data_size_out,
        ctx_size_out: result.ctx_size_out,
        output,
    })
}

fn verify_inventory(ebpf: &Ebpf, options: Options) -> Result<(), Box<dyn Error>> {
    let mut programs: Vec<_> = ebpf.programs().map(|(name, _)| name).collect();
    programs.sort_unstable();
    ensure(
        programs == [PROGRAM_GATE, PROGRAM_CONTROL, PROGRAM_VIEW],
        "program inventory changed",
    )?;

    let mut expected_maps = vec![
        MAP_CONFIG,
        MAP_COOKIES,
        MAP_COUNTERS,
        MAP_CURRENT,
        MAP_LOCK,
        MAP_MUTATION,
    ];
    if options.fault_delete {
        expected_maps.push(MAP_FAULT);
    }
    expected_maps.sort_unstable();
    let mut maps: Vec<_> = ebpf.maps().map(|(name, _)| name).collect();
    maps.sort_unstable();
    ensure(maps == expected_maps, "map inventory changed")?;

    verify_map(ebpf, MAP_CONFIG, MapKind::Array, 4, 40, 1, 0)?;
    verify_map(
        ebpf,
        MAP_COOKIES,
        MapKind::Hash,
        COOKIE_KEY_LEN,
        COOKIE_VALUE_LEN as u32,
        options.capacity,
        0,
    )?;
    verify_map(ebpf, MAP_COUNTERS, MapKind::PerCpuArray, 4, 8, 8, 0)?;
    verify_map(
        ebpf,
        MAP_CURRENT,
        MapKind::Array,
        4,
        CURRENT_LEN as u32,
        1,
        0,
    )?;
    verify_map(ebpf, MAP_LOCK, MapKind::Array, 4, 4, 1, 0)?;
    verify_map(
        ebpf,
        MAP_MUTATION,
        MapKind::Array,
        4,
        MUTATION_LEN as u32,
        1,
        0,
    )?;
    if options.fault_delete {
        verify_map(ebpf, MAP_FAULT, MapKind::Array, 4, 4, 2, 0)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum MapKind {
    Array,
    Hash,
    PerCpuArray,
}

fn verify_map(
    ebpf: &Ebpf,
    name: &str,
    expected_kind: MapKind,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
) -> Result<(), Box<dyn Error>> {
    let map = ebpf.map(name).ok_or("required map absent")?;
    let kind_matches = matches!(
        (expected_kind, map),
        (MapKind::Array, Map::Array(_))
            | (MapKind::Hash, Map::HashMap(_))
            | (MapKind::PerCpuArray, Map::PerCpuArray(_))
    );
    ensure(kind_matches, "map kind changed")?;
    let data = map_data(map).ok_or("unexpected map kind")?;
    let info = data.info()?;
    ensure(
        info.key_size() == key_size
            && info.value_size() == value_size
            && info.max_entries() == max_entries
            && info.map_flags() == flags,
        "map metadata changed",
    )
}

fn map_data(map: &Map) -> Option<&MapData> {
    match map {
        Map::Array(data) | Map::HashMap(data) | Map::PerCpuArray(data) => Some(data),
        _ => None,
    }
}

fn freeze_map(map: &Map) -> Result<(), Box<dyn Error>> {
    const BPF_MAP_FREEZE: libc::c_long = 22;
    let data = map_data(map).ok_or("cannot freeze unexpected map kind")?;
    let map_fd = data.fd().as_fd().as_raw_fd() as u32;
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_FREEZE,
            (&raw const map_fd).cast::<libc::c_void>(),
            std::mem::size_of::<u32>(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

fn verify_config_mutations(object: &Path, options: Options) -> Result<(), Box<dyn Error>> {
    let valid = config_ipv4(options.capacity);
    let unrelated = ipv4_udp(IPV4_UNRELATED, UNRELATED_PORT, 5, 0);
    let mutations: [ConfigMutation; 11] = [
        ("magic", |value| value[0] ^= 1),
        ("version", |value| value[4] ^= 1),
        ("family", |value| value[6] = 5),
        ("reserved0", |value| value[7] = 1),
        ("reserved1-first", |value| value[10] = 1),
        ("reserved1-second", |value| value[11] = 1),
        ("capacity", |value| put_u32_le(value, 12, 0)),
        ("alternate-capacity", |value| {
            put_u32_le(value, 12, PRODUCTION_CAPACITY - 1)
        }),
        ("root", |value| put_u64_le(value, 16, 0)),
        ("ipv4-tail", |value| value[39] = 1),
        ("port-zero", |value| {
            value[8] = 0;
            value[9] = 0;
        }),
    ];
    for (label, mutate) in mutations {
        let mut value = valid;
        mutate(&mut value);
        let lab = Lab::load(object, value, options)?;
        expect(
            lab.gate(&unrelated)?,
            0,
            &format!("invalid CONFIG mutation passed: {label}"),
        )?;
    }

    let mut unspecified = valid;
    unspecified[24..28].fill(0);
    let lab = Lab::load(object, unspecified, options)?;
    expect(lab.gate(&unrelated)?, 0, "unspecified IPv4 CONFIG")?;

    let mut multicast = valid;
    multicast[24..28].copy_from_slice(&[224, 0, 0, 7]);
    let lab = Lab::load(object, multicast, options)?;
    expect(lab.gate(&unrelated)?, 0, "multicast IPv4 CONFIG")?;

    let mut mapped = config_ipv6(options.capacity);
    mapped[24..40].fill(0);
    mapped[34] = 0xff;
    mapped[35] = 0xff;
    mapped[36..40].copy_from_slice(&IPV4_PROTECTED);
    let lab = Lab::load(object, mapped, options)?;
    expect(lab.gate(&unrelated)?, 0, "IPv4-mapped IPv6 CONFIG")?;

    let mut link_local = config_ipv6(options.capacity);
    link_local[24..40].fill(0);
    link_local[24] = 0xfe;
    link_local[25] = 0x80;
    link_local[39] = 1;
    let lab = Lab::load(object, link_local, options)?;
    expect(lab.gate(&unrelated)?, 0, "scoped IPv6 CONFIG")?;
    link_local[25] = 0xbf;
    let lab = Lab::load(object, link_local, options)?;
    expect(lab.gate(&unrelated)?, 0, "upper scoped IPv6 CONFIG")?;
    link_local[25] = 0xc0;
    let lab = Lab::load(object, link_local, options)?;
    expect(lab.gate(&unrelated)?, 1, "adjacent unscoped IPv6 CONFIG")?;

    // CONFIG stores the port as two network-order bytes. Swapping them is a
    // different valid endpoint, so the original tuple must become unrelated.
    let mut swapped = valid;
    swapped.swap(8, 9);
    let lab = Lab::load(object, swapped, options)?;
    expect(
        lab.gate(&ipv4_udp(IPV4_PROTECTED, PROTECTED_PORT, 5, 0))?,
        1,
        "CONFIG port byte-order detector",
    )
}

fn verify_test_run_contract_mutations() -> Result<(), Box<dyn Error>> {
    for repeat in [0, 2] {
        ensure(
            !canonical_test_run_shape(COMMAND_LEN, COMMAND_LEN, 0, 0, repeat, 0),
            "non-unit control repeat accepted",
        )?;
    }
    ensure(
        !canonical_test_run_shape(COMMAND_LEN, COMMAND_LEN - 1, 0, 0, 1, 0),
        "short control output accepted",
    )?;
    ensure(
        !canonical_test_run_shape(VIEW_LEN, VIEW_LEN - 1, 0, 0, 1, 0),
        "short view output accepted",
    )?;
    ensure(
        !canonical_test_run_shape(COMMAND_LEN, COMMAND_LEN, 8, 0, 1, 0),
        "unexpected ctx input accepted",
    )?;
    ensure(
        !canonical_test_run_shape(COMMAND_LEN, COMMAND_LEN, 0, 8, 1, 0),
        "unexpected ctx output accepted",
    )?;
    ensure(
        !canonical_test_run_shape(COMMAND_LEN, COMMAND_LEN, 0, 0, 1, 1),
        "nonzero TEST_RUN flags accepted",
    )?;
    ensure(
        canonical_test_run_shape(COMMAND_LEN, COMMAND_LEN, 0, 0, 1, 0),
        "canonical control TEST_RUN rejected",
    )
}

const fn canonical_test_run_shape(
    input: usize,
    output: usize,
    ctx_input: usize,
    ctx_output: usize,
    repeat: u32,
    flags: u32,
) -> bool {
    (input == COMMAND_LEN && output == COMMAND_LEN || input == VIEW_LEN && output == VIEW_LEN)
        && ctx_input == 0
        && ctx_output == 0
        && repeat == 1
        && flags == 0
}

fn config_ipv4(capacity: u32) -> [u8; CONFIG_LEN] {
    let mut value = config_base(4, capacity);
    value[24..28].copy_from_slice(&IPV4_PROTECTED);
    value
}

fn config_ipv6(capacity: u32) -> [u8; CONFIG_LEN] {
    let mut value = config_base(6, capacity);
    value[24..40].copy_from_slice(&IPV6_PROTECTED);
    value
}

fn config_base(family: u8, capacity: u32) -> [u8; CONFIG_LEN] {
    let mut value = [0_u8; CONFIG_LEN];
    value[0..4].copy_from_slice(b"OEF1");
    put_u16_le(&mut value, 4, ABI_VERSION);
    value[6] = family;
    put_u16_be(&mut value, 8, PROTECTED_PORT);
    put_u32_le(&mut value, 12, capacity);
    put_u64_le(&mut value, 16, ROOT_CGROUP_ID);
    value
}

fn command_bytes(root_cgroup_id: u64, command: Command) -> [u8; COMMAND_LEN] {
    let mut value = [0_u8; COMMAND_LEN];
    value[0..4].copy_from_slice(b"OEC1");
    put_u16_le(&mut value, 4, ABI_VERSION);
    value[6] = command.operation;
    put_u64_le(&mut value, 8, root_cgroup_id);
    put_u64_le(&mut value, 16, command.cookie);
    put_u64_le(&mut value, 24, command.token);
    put_u64_le(&mut value, 32, command.deadline);
    put_u64_le(&mut value, 40, command.epoch);
    value
}

fn decode_snapshot(value: &[u8]) -> Result<Snapshot, Box<dyn Error>> {
    ensure(value.len() == VIEW_LEN, "view output width")?;
    ensure(&value[0..4] == b"OEI1", "view magic")?;
    ensure(get_u16_le(value, 4) == ABI_VERSION, "view version")?;
    ensure(value[6] <= 1 && value[7] == 0, "view presence/reserved")?;
    ensure(value[88..128].iter().all(|byte| *byte == 0), "view tail")?;

    let current = Current {
        control: get_u32_le(value, 12),
        token: get_u64_le(value, 16),
        cookie: get_u64_le(value, 24),
    };
    ensure(get_u32_le(value, 8) == 0, "CURRENT reserved")?;
    let current_is_canonical = current
        == Current {
            control: 0,
            token: 0,
            cookie: 0,
        }
        || current.control == CURRENT_OPEN && current.token != 0 && current.token & 1 == 1
        || current.control == CURRENT_CLOSED
            && current.token != 0
            && current.token & 1 == 0
            && current.cookie == 0;
    ensure(current_is_canonical, "CURRENT canonical form")?;

    let mutation = Mutation {
        generation: get_u64_le(value, 32),
        claim: get_u64_le(value, 40),
    };
    ensure(
        mutation.claim == 0
            || mutation.generation != u64::MAX && mutation.claim == mutation.generation + 1,
        "mutation claim canonical form",
    )?;

    let entry = if value[6] == 0 {
        ensure(
            value[48..88].iter().all(|byte| *byte == 0),
            "absent entry bytes",
        )?;
        None
    } else {
        let entry = Entry {
            control: get_u32_le(value, 52),
            cookie: get_u64_le(value, 56),
            token: get_u64_le(value, 64),
            deadline: get_u64_le(value, 72),
            epoch: get_u64_le(value, 80),
        };
        ensure(get_u32_le(value, 48) == 0, "entry reserved")?;
        let entry_is_canonical = entry.cookie != 0
            && entry.token != 0
            && match entry.control {
                COOKIE_INITIAL => entry.deadline == 0 && entry.epoch == 1,
                COOKIE_ACTIVE => entry.deadline != 0 && entry.epoch > 1,
                COOKIE_TERMINAL | COOKIE_RECLAIMING => entry.deadline == 0 && entry.epoch != 0,
                _ => false,
            };
        ensure(entry_is_canonical, "entry canonical form")?;
        Some(entry)
    };
    Ok(Snapshot {
        current,
        mutation,
        entry,
    })
}

fn expect_snapshot(
    actual: Snapshot,
    expected: Snapshot,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    ensure(actual == expected, label)
}

fn ipv4_udp(source: [u8; 4], source_port: u16, ihl_words: u8, fragment: u16) -> Vec<u8> {
    let header_len = usize::from(ihl_words) * 4;
    let udp_len = 12_usize;
    let total_len = header_len + udp_len;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x40 | ihl_words;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&fragment.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&IPV4_DESTINATION);
    packet[header_len..header_len + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[header_len + 2..header_len + 4].copy_from_slice(&UNRELATED_PORT.to_be_bytes());
    packet[header_len + 4..header_len + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet
}

fn ipv4_non_udp(source: [u8; 4], protocol: u8) -> Vec<u8> {
    let mut packet = vec![0_u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&IPV4_DESTINATION);
    packet
}

fn ipv6_udp(
    source: [u8; 16],
    source_port: u16,
    first_next_header: u8,
    extensions: &[u8],
) -> Vec<u8> {
    let udp_len = 12_usize;
    let payload_len = extensions.len() + udp_len;
    let mut packet = vec![0_u8; 40 + payload_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    packet[6] = first_next_header;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source);
    packet[24..40].copy_from_slice(&IPV6_DESTINATION);
    packet[40..40 + extensions.len()].copy_from_slice(extensions);
    let udp = 40 + extensions.len();
    packet[udp..udp + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[udp + 2..udp + 4].copy_from_slice(&UNRELATED_PORT.to_be_bytes());
    packet[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet
}

fn ipv6_extension(next_header: u8, length_field: u8) -> Vec<u8> {
    let length = (usize::from(length_field) + 1) * 8;
    let mut extension = vec![0_u8; length];
    extension[0] = next_header;
    extension[1] = length_field;
    extension
}

fn ipv6_fragment(next_header: u8, fragment_field: u16) -> Vec<u8> {
    let mut fragment = vec![0_u8; 8];
    fragment[0] = next_header;
    fragment[2..4].copy_from_slice(&fragment_field.to_be_bytes());
    fragment[4..8].copy_from_slice(&0x1357_9bdf_u32.to_be_bytes());
    fragment
}

fn boottime_ns() -> Result<u64, Box<dyn Error>> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let seconds = u64::try_from(value.tv_sec)?;
    let nanos = u64::try_from(value.tv_nsec)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanos))
        .ok_or_else(|| io::Error::other("BOOTTIME overflow").into())
}

fn checked_add(left: u64, right: u64) -> Result<u64, Box<dyn Error>> {
    left.checked_add(right)
        .ok_or_else(|| io::Error::other("deadline overflow").into())
}

fn expect(actual: u32, expected: u32, label: &str) -> Result<(), Box<dyn Error>> {
    ensure(
        actual == expected,
        &format!("{label}: expected {expected}, got {actual}"),
    )
}

fn ensure(condition: bool, label: &str) -> Result<(), Box<dyn Error>> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(label.to_owned()).into())
    }
}

fn put_u16_le<const N: usize>(value: &mut [u8; N], offset: usize, number: u16) {
    value[offset..offset + 2].copy_from_slice(&number.to_le_bytes());
}

fn put_u16_be<const N: usize>(value: &mut [u8; N], offset: usize, number: u16) {
    value[offset..offset + 2].copy_from_slice(&number.to_be_bytes());
}

fn put_u32_le<const N: usize>(value: &mut [u8; N], offset: usize, number: u32) {
    value[offset..offset + 4].copy_from_slice(&number.to_le_bytes());
}

fn put_u64_le<const N: usize>(value: &mut [u8; N], offset: usize, number: u64) {
    value[offset..offset + 8].copy_from_slice(&number.to_le_bytes());
}

fn get_u16_le(value: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([value[offset], value[offset + 1]])
}

fn get_u32_le(value: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
    ])
}

fn get_u64_le(value: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
        value[offset + 4],
        value[offset + 5],
        value[offset + 6],
        value[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_failure_erases_error_and_path_content() {
        let sensitive = "/must-not-appear/private/object.bpf.o";
        let error = io::Error::other(sensitive);
        let line = redacted_failure_line(&error);

        assert_eq!(line, ORACLE_DEFECTIVE);
        assert!(!line.contains(sensitive));
        assert!(!line.contains('/'));
    }
}
