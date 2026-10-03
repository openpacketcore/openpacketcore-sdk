//! Privileged proof of the actual kernel grace, independent of user scheduling.
//! No packet hooks, tracefs writes, named maps, or pinned objects are used.

use super::*;
use std::ffi::CString;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::thread;
use std::time::{Duration, Instant};

const BPF_MAP_LOOKUP_ELEM: libc::c_uint = 1;
const BPF_PROG_LOAD: libc::c_uint = 5;
const BPF_PROG_TEST_RUN: libc::c_uint = 10;
const BPF_BTF_LOAD: libc::c_uint = 18;
const BPF_PROG_TYPE_KPROBE: u32 = 2;
const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
// Linux request codes are 32-bit; libc accepts c_ulong on GNU and c_int on
// musl. Both values fit either ABI, so infer the request argument at each call.
const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;
const PERF_EVENT_IOC_SET_BPF: u32 = 0x4004_2408;

// armed, entry_ns, return_ns, entry_count, return_count, respectively.
type TraceRecord = [u64; 5];
// synthetic row, start_ns, end_ns, deadline_ns, first_sample, last_sample.
type ReaderRecord = [u64; 6];

#[derive(Debug, PartialEq, Eq)]
enum TraceFailure {
    MissingKernelGrace,
    UnpairedKernelGrace,
    InvalidNesting,
}

fn paired_grace_interval(
    normal: TraceRecord,
    expedited: TraceRecord,
) -> Result<(u64, u64), TraceFailure> {
    let pair = |record: TraceRecord| {
        if record[1..].iter().all(|field| *field == 0) {
            return Ok(None);
        }
        if record[0] != 1
            || record[1] == 0
            || record[2] < record[1]
            || record[3] != 1
            || record[4] != 1
        {
            return Err(TraceFailure::UnpairedKernelGrace);
        }
        Ok(Some((record[1], record[2])))
    };
    match (pair(normal)?, pair(expedited)?) {
        (None, None) => Err(TraceFailure::MissingKernelGrace),
        (Some(interval), None) | (None, Some(interval)) => Ok(interval),
        (Some(outer), Some(inner)) if outer.0 <= inner.0 && inner.1 <= outer.1 => Ok(outer),
        (Some(_), Some(_)) => Err(TraceFailure::InvalidNesting),
    }
}

#[test]
fn reader_grace_proof_requires_one_matched_kernel_call_or_exact_nesting() {
    let none = [1, 0, 0, 0, 0];
    assert_eq!(
        paired_grace_interval([1, 100, 400, 1, 1], none),
        Ok((100, 400))
    );
    assert_eq!(
        paired_grace_interval(none, [1, 100, 400, 1, 1]),
        Ok((100, 400))
    );
    assert_eq!(
        paired_grace_interval([1, 100, 400, 1, 1], [1, 120, 350, 1, 1]),
        Ok((100, 400))
    );
    assert_eq!(
        paired_grace_interval(none, none),
        Err(TraceFailure::MissingKernelGrace)
    );
    for malformed in [
        [1, 100, 0, 1, 0],
        [1, 0, 400, 0, 1],
        [1, 100, 400, 2, 2],
        [1, 100, 90, 1, 1],
        [0, 100, 400, 1, 1],
    ] {
        assert_eq!(
            paired_grace_interval(malformed, none),
            Err(TraceFailure::UnpairedKernelGrace)
        );
    }
    assert_eq!(
        paired_grace_interval([1, 100, 400, 1, 1], [1, 90, 350, 1, 1]),
        Err(TraceFailure::InvalidNesting)
    );
    assert_eq!(
        paired_grace_interval([1, 100, 400, 1, 1], [1, 120, 450, 1, 1]),
        Err(TraceFailure::InvalidNesting)
    );
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Insn {
    code: u8,
    registers: u8,
    offset: i16,
    immediate: i32,
}

fn insn(code: u8, dst: u8, src: u8, offset: i16, immediate: i32) -> Insn {
    Insn {
        code,
        registers: dst | src << 4,
        offset,
        immediate,
    }
}

#[repr(C, align(8))]
#[derive(Default)]
struct ProgramLoadAttr {
    program_type: u32,
    instruction_count: u32,
    instructions: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buffer: u64,
    kernel_version: u32,
    program_flags: u32,
    program_name: [u8; 16],
    program_ifindex: u32,
    expected_attach_type: u32,
    program_btf_fd: u32,
    function_info_record_size: u32,
    function_info: u64,
    function_info_count: u32,
    line_info_record_size: u32,
}

#[repr(C, align(8))]
#[derive(Default)]
struct BtfLoadAttr {
    btf: u64,
    log_buffer: u64,
    btf_size: u32,
    log_size: u32,
    log_level: u32,
    reserved: u32,
}

#[repr(C, align(8))]
#[derive(Default)]
struct ProgramTestRunAttr {
    program_fd: u32,
    return_value: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
}

#[repr(C, align(8))]
#[derive(Default)]
struct PerfEventAttr {
    event_type: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    breakpoint_type: u32,
    config1: u64,
    config2: u64,
}

const _: () = {
    assert!(mem::size_of::<Insn>() == 8);
    assert!(mem::size_of::<ProgramLoadAttr>() == 96);
    assert!(mem::offset_of!(ProgramLoadAttr, instructions) == 8);
    assert!(mem::offset_of!(ProgramLoadAttr, log_buffer) == 32);
    assert!(mem::offset_of!(ProgramLoadAttr, program_btf_fd) == 72);
    assert!(mem::offset_of!(ProgramLoadAttr, function_info) == 80);
    assert!(mem::offset_of!(ProgramLoadAttr, function_info_count) == 88);
    assert!(mem::size_of::<BtfLoadAttr>() == 32);
    assert!(mem::offset_of!(BtfLoadAttr, log_level) == 24);
    assert!(mem::size_of::<ProgramTestRunAttr>() == 40);
    assert!(mem::offset_of!(ProgramTestRunAttr, data_in) == 16);
    assert!(mem::size_of::<PerfEventAttr>() == 72);
    assert!(mem::offset_of!(PerfEventAttr, config1) == 56);
};

fn array_update<const N: usize>(fd: BorrowedFd<'_>, value: &[u64; N]) {
    let key = 0_u32;
    let attr = MapElementAttr {
        map_fd: fd.as_raw_fd() as u32,
        key: &key as *const u32 as u64,
        value: value.as_ptr() as u64,
        ..MapElementAttr::default()
    };
    // SAFETY: All callers use an ARRAY created with exactly this value size;
    // the initialized attr, key/value storage, and borrowed FD outlive the call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr,
            mem::size_of_val(&attr),
        )
    };
    assert_eq!(result, 0, "ARRAY update: {}", io::Error::last_os_error());
}

fn array_read<const N: usize>(fd: BorrowedFd<'_>) -> [u64; N] {
    let key = 0_u32;
    let mut value = [0_u64; N];
    let attr = MapElementAttr {
        map_fd: fd.as_raw_fd() as u32,
        key: &key as *const u32 as u64,
        value: value.as_mut_ptr() as u64,
        ..MapElementAttr::default()
    };
    // SAFETY: All callers match the created ARRAY's value size. The kernel
    // writes only the initialized, aligned local value buffer during this call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_LOOKUP_ELEM,
            &attr,
            mem::size_of_val(&attr),
        )
    };
    assert_eq!(result, 0, "ARRAY lookup: {}", io::Error::last_os_error());
    value
}

fn load_program(program_type: u32, instructions: &[Insn]) -> OwnedFd {
    load_program_with_btf(program_type, instructions, None)
}

fn load_program_with_btf(
    program_type: u32,
    instructions: &[Insn],
    functions: Option<(BorrowedFd<'_>, &[[u32; 2]])>,
) -> OwnedFd {
    let mut log = vec![0_u8; 65_536];
    let mut attr = ProgramLoadAttr {
        program_type,
        instruction_count: instructions
            .len()
            .try_into()
            .expect("bounded instruction count"),
        instructions: instructions.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
        log_level: 1,
        log_size: log.len().try_into().expect("bounded verifier log"),
        log_buffer: log.as_mut_ptr() as u64,
        ..ProgramLoadAttr::default()
    };
    if let Some((btf, functions)) = functions {
        attr.program_btf_fd = btf.as_raw_fd() as u32;
        attr.function_info_record_size = mem::size_of::<[u32; 2]>() as u32;
        attr.function_info = functions.as_ptr() as u64;
        attr.function_info_count = functions.len() as u32;
    }
    // SAFETY: The exact initialized load prefix references live instruction,
    // license and verifier-log storage. No ownership is assumed on failure.
    let fd = unsafe { libc::syscall(libc::SYS_bpf, BPF_PROG_LOAD, &attr, mem::size_of_val(&attr)) };
    assert!(
        fd >= 0,
        "BPF_PROG_LOAD: {}; verifier: {}",
        io::Error::last_os_error(),
        String::from_utf8_lossy(
            &log[..log.iter().position(|byte| *byte == 0).unwrap_or(log.len())]
        )
    );
    // SAFETY: The successful syscall returned this fresh uniquely-owned FD.
    unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) }
}

fn reader_btf() -> OwnedFd {
    // Minimal native-endian BTF for the main TC function and static bpf_loop
    // callback. Function info is required for BPF_PSEUDO_FUNC on every profile.
    let strings = b"\0int\0reader\0u32\0index\0ctx\0callback\0";
    let types: &[u32] = &[
        1,
        1 << 24,
        4,
        (1 << 24) | 32, // 1: signed int
        0,
        2 << 24,
        0, // 2: void *
        0,
        (13 << 24) | 1,
        1,
        22,
        2, // 3: int (void *ctx)
        5,
        12 << 24,
        3, // 4: static reader
        12,
        1 << 24,
        4,
        32, // 5: u32
        0,
        (13 << 24) | 2,
        1,
        16,
        5,
        22,
        2, // 6: int (u32 index, void *ctx)
        26,
        12 << 24,
        6, // 7: static callback
    ];
    let type_size = mem::size_of_val(types) as u32;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xeb9f_u16.to_ne_bytes());
    bytes.extend_from_slice(&[1, 0]); // version, flags
    for word in [24, 0, type_size, type_size, strings.len() as u32]
        .into_iter()
        .chain(types.iter().copied())
    {
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    bytes.extend_from_slice(strings);
    let mut log = vec![0_u8; 65_536];
    let attr = BtfLoadAttr {
        btf: bytes.as_ptr() as u64,
        log_buffer: log.as_mut_ptr() as u64,
        btf_size: bytes.len() as u32,
        log_size: log.len() as u32,
        log_level: 1,
        ..BtfLoadAttr::default()
    };
    // SAFETY: The initialized load prefix references live BTF/log buffers;
    // the kernel validates every encoded type before returning an owned FD.
    let fd = unsafe { libc::syscall(libc::SYS_bpf, BPF_BTF_LOAD, &attr, mem::size_of_val(&attr)) };
    assert!(
        fd >= 0,
        "BPF_BTF_LOAD: {}; verifier: {}",
        io::Error::last_os_error(),
        String::from_utf8_lossy(
            &log[..log.iter().position(|byte| *byte == 0).unwrap_or(log.len())]
        )
    );
    // SAFETY: The successful syscall returned this fresh uniquely-owned FD.
    unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) }
}

fn observer_program(map: BorrowedFd<'_>, returning: bool) -> OwnedFd {
    let (stamp, count) = if returning { (16, 32) } else { (8, 24) };
    load_program(
        BPF_PROG_TYPE_KPROBE,
        &[
            insn(0x62, 10, 0, -4, 0), // stack key = 0
            insn(0x18, 1, 1, 0, map.as_raw_fd()),
            Insn::default(),
            insn(0xbf, 2, 10, 0, 0),
            insn(0x07, 2, 0, 0, -4),
            insn(0x85, 0, 0, 0, 1), // map_lookup_elem
            insn(0x15, 0, 0, 8, 0), // missing map -> exit
            insn(0xbf, 6, 0, 0, 0),
            insn(0x79, 1, 6, 0, 0), // armed
            insn(0x15, 1, 0, 5, 0), // disarmed -> exit
            insn(0x85, 0, 0, 0, 5), // ktime_get_ns
            insn(0x7b, 6, 0, stamp, 0),
            insn(0x79, 1, 6, count, 0),
            insn(0x07, 1, 0, 0, 1),
            insn(0x7b, 6, 1, count, 0),
            insn(0xb7, 0, 0, 0, 0),
            insn(0x95, 0, 0, 0, 0),
        ],
    )
}

struct Probe {
    // Close the event before dropping its program reference.
    _event: OwnedFd,
    _program: OwnedFd,
}

impl Probe {
    fn attach(symbol: &str, map: BorrowedFd<'_>, returning: bool) -> Self {
        let event_type: u32 = std::fs::read_to_string("/sys/bus/event_source/devices/kprobe/type")
            .expect("kernel kprobe PMU is required")
            .trim()
            .parse()
            .expect("kprobe PMU type");
        let format =
            std::fs::read_to_string("/sys/bus/event_source/devices/kprobe/format/retprobe")
                .expect("kernel kretprobe PMU is required");
        let bit: u32 = format
            .trim()
            .strip_prefix("config:")
            .expect("retprobe config format")
            .parse()
            .expect("retprobe config bit");
        let return_flag = 1_u64.checked_shl(bit).expect("bounded retprobe config bit");
        let symbol = CString::new(symbol).expect("constant kernel symbol");
        let attr = PerfEventAttr {
            event_type,
            size: mem::size_of::<PerfEventAttr>() as u32,
            config: if returning { return_flag } else { 0 },
            flags: 1, // disabled until its BPF observer is installed
            config1: symbol.as_ptr() as u64,
            ..PerfEventAttr::default()
        };
        // SAFETY: gettid has no pointer arguments and identifies this updater
        // thread, not the reader or other processes on the host.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
        // SAFETY: The initialized attr and NUL-terminated symbol outlive this
        // call. pid=tid/cpu=-1 restricts this event to the updater task.
        let fd =
            unsafe { libc::syscall(libc::SYS_perf_event_open, &attr, tid, -1_i32, -1_i32, 8_u64) };
        assert!(
            fd >= 0,
            "perf kprobe prerequisite: {}",
            io::Error::last_os_error()
        );
        // SAFETY: perf_event_open returned this fresh uniquely-owned FD.
        let event = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
        let program = observer_program(map, returning);
        // SAFETY: These ioctls take integer arguments and borrowed live FDs.
        let attached = unsafe {
            libc::ioctl(
                event.as_raw_fd(),
                PERF_EVENT_IOC_SET_BPF as _,
                program.as_raw_fd(),
            )
        };
        assert_eq!(
            attached,
            0,
            "perf BPF attach: {}",
            io::Error::last_os_error()
        );
        // SAFETY: Enabling this owned perf event takes no pointer argument.
        let enabled = unsafe { libc::ioctl(event.as_raw_fd(), PERF_EVENT_IOC_ENABLE as _, 0_u64) };
        assert_eq!(
            enabled,
            0,
            "perf BPF enable: {}",
            io::Error::last_os_error()
        );
        Self {
            _event: event,
            _program: program,
        }
    }
}

fn reader_program(map: BorrowedFd<'_>) -> OwnedFd {
    let btf = reader_btf();
    load_program_with_btf(
        BPF_PROG_TYPE_SCHED_CLS,
        &[
            insn(0x62, 10, 0, -4, 0),
            insn(0x18, 1, 1, 0, map.as_raw_fd()),
            Insn::default(),
            insn(0xbf, 2, 10, 0, 0),
            insn(0x07, 2, 0, 0, -4),
            insn(0x85, 0, 0, 0, 1),
            insn(0x15, 0, 0, 19, 0), // missing row -> exit
            insn(0xbf, 6, 0, 0, 0),
            insn(0x79, 1, 6, 0, 0),
            insn(0x7b, 6, 1, 32, 0), // first old-row sample
            insn(0x85, 0, 0, 0, 5),
            insn(0x7b, 6, 0, 8, 0), // reader starts
            insn(0x07, 0, 0, 0, 1_000_000_000),
            insn(0x7b, 6, 0, 24, 0),
            insn(0x7b, 10, 0, -16, 0), // bounded deadline
            insn(0xb7, 1, 0, 0, 8_000_000),
            insn(0x18, 2, 4, 0, 11),
            Insn::default(), // callback at instruction 28
            insn(0xbf, 3, 10, 0, 0),
            insn(0x07, 3, 0, 0, -16),
            insn(0xb7, 4, 0, 0, 0),
            insn(0x85, 0, 0, 0, 181), // bounded bpf_loop
            insn(0x79, 1, 6, 0, 0),
            insn(0x7b, 6, 1, 40, 0), // last old-row sample
            insn(0x85, 0, 0, 0, 5),
            insn(0x7b, 6, 0, 16, 0), // reader ends
            insn(0xb7, 0, 0, 0, 0),
            insn(0x95, 0, 0, 0, 0),
            // callback(index, stack_deadline): stop at deadline or the loop bound.
            insn(0xbf, 6, 2, 0, 0),
            insn(0x85, 0, 0, 0, 5),
            insn(0x79, 1, 6, 0, 0),
            insn(0x3d, 0, 1, 2, 0),
            insn(0xb7, 0, 0, 0, 0),
            insn(0x95, 0, 0, 0, 0),
            insn(0xb7, 0, 0, 0, 1),
            insn(0x95, 0, 0, 0, 0),
        ],
        Some((btf.as_fd(), &[[0, 4], [28, 7]])),
    )
}

fn run_reader(program: BorrowedFd<'_>) {
    let mut packet = [0_u8; 64];
    packet[12..14].copy_from_slice(&[0x08, 0x00]);
    packet[14] = 0x45;
    let mut attr = ProgramTestRunAttr {
        program_fd: program.as_raw_fd() as u32,
        data_size_in: packet.len() as u32,
        data_in: packet.as_ptr() as u64,
        repeat: 1,
        ..ProgramTestRunAttr::default()
    };
    // SAFETY: The initialized test-run prefix and packet remain live. This
    // runs the TC program in the kernel test harness without attaching a hook.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_TEST_RUN,
            &mut attr,
            mem::size_of::<ProgramTestRunAttr>(),
        )
    };
    assert_eq!(
        result,
        0,
        "TC reader test-run: {}",
        io::Error::last_os_error()
    );
    assert_eq!(attr.return_value, 0);
}

struct AffinityGuard(libc::cpu_set_t);

impl AffinityGuard {
    fn current() -> libc::cpu_set_t {
        // SAFETY: An all-zero cpu_set_t is a valid empty mask for the syscall
        // to fill, and its storage remains writable for the call.
        let mut mask: libc::cpu_set_t = unsafe { mem::zeroed() };
        let result = unsafe { libc::sched_getaffinity(0, mem::size_of_val(&mask), &mut mask) };
        assert_eq!(result, 0, "read CPU affinity");
        mask
    }

    fn pin(cpu: usize) -> Self {
        let original = Self::current();
        // SAFETY: The caller selects a CPU from the initial allowed mask and
        // stays within CPU_SETSIZE; the initialized mask outlives the syscall.
        let mut mask: libc::cpu_set_t = unsafe { mem::zeroed() };
        unsafe { libc::CPU_SET(cpu, &mut mask) };
        let result = unsafe { libc::sched_setaffinity(0, mem::size_of_val(&mask), &mask) };
        assert_eq!(result, 0, "pin distinct reader/updater CPU");
        Self(original)
    }
}

impl Drop for AffinityGuard {
    fn drop(&mut self) {
        // SAFETY: This guard owns the valid original thread affinity mask.
        let result = unsafe { libc::sched_setaffinity(0, mem::size_of_val(&self.0), &self.0) };
        assert_eq!(result, 0, "restore CPU affinity");
    }
}

#[test]
#[ignore = "requires BPF/perf privileges, kprobe PMU, bpf_loop, and two allowed CPUs"]
fn map_in_map_grace_waits_for_live_non_sleepable_reader() {
    assert_eq!(
        std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(),
        Ok("1"),
        "privileged qualification must be explicitly enabled"
    );
    let allowed = AffinityGuard::current();
    let cpus = (0..libc::CPU_SETSIZE as usize)
        .filter(|cpu| {
            // SAFETY: The bounded index and initialized cpu_set_t are valid.
            unsafe { libc::CPU_ISSET(*cpu, &allowed) }
        })
        .take(2)
        .collect::<Vec<_>>();
    assert_eq!(
        cpus.len(),
        2,
        "distinct reader and updater CPUs are required"
    );
    let _updater_affinity = AffinityGuard::pin(cpus[0]);
    let grace = BpfMapReaderGrace::new().expect("private grace maps");
    grace.synchronize().expect("initial map update");
    let normal = create_map(BPF_MAP_TYPE_ARRAY, mem::size_of::<TraceRecord>() as u32, 0).unwrap();
    let expedited =
        create_map(BPF_MAP_TYPE_ARRAY, mem::size_of::<TraceRecord>() as u32, 0).unwrap();
    let reader = create_map(BPF_MAP_TYPE_ARRAY, mem::size_of::<ReaderRecord>() as u32, 0).unwrap();
    let control = create_map(BPF_MAP_TYPE_ARRAY, 8, 0).unwrap();
    let program = reader_program(reader.as_fd());
    let _probes = [
        Probe::attach("synchronize_rcu", normal.as_fd(), false),
        Probe::attach("synchronize_rcu", normal.as_fd(), true),
        Probe::attach("synchronize_rcu_expedited", expedited.as_fd(), false),
        Probe::attach("synchronize_rcu_expedited", expedited.as_fd(), true),
    ];
    // Installation/enable may itself synchronize; only subsequent armed
    // calls by this updater TID belong to the attempt under observation.
    let armed = [1, 0, 0, 0, 0];
    array_update(normal.as_fd(), &armed);
    array_update(expedited.as_fd(), &armed);
    array_update(control.as_fd(), &[7]);
    assert_eq!(
        paired_grace_interval(array_read(normal.as_fd()), array_read(expedited.as_fd())),
        Err(TraceFailure::MissingKernelGrace),
        "ordinary ARRAY update must fail the kernel-grace proof"
    );
    println!("\nOPC_GTPU_MAP_READER_GRACE_NEGATIVE_CONTROL_PROVEN");
    array_update(normal.as_fd(), &armed);
    array_update(expedited.as_fd(), &armed);
    array_update(reader.as_fd(), &[17, 0, 0, 0, 0, 0]);
    thread::scope(|scope| {
        let task = scope.spawn(|| {
            let _reader_affinity = AffinityGuard::pin(cpus[1]);
            run_reader(program.as_fd());
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let observed: ReaderRecord = array_read(reader.as_fd());
            if observed[1] != 0 {
                assert_eq!(observed[2], 0, "reader already completed; overlap unproven");
                break;
            }
            assert!(
                !task.is_finished(),
                "reader returned without entering its critical section"
            );
            assert!(
                Instant::now() < deadline,
                "reader did not enter its critical section"
            );
            thread::yield_now();
        }
        grace
            .synchronize()
            .expect("fresh production map-in-map grace");
        let observed: ReaderRecord = array_read(reader.as_fd());
        // Reclaim only after the production call returns. An early return
        // would overwrite the value before the reader's final old-row sample.
        let mut replacement = observed;
        replacement[0] = 29;
        array_update(reader.as_fd(), &replacement);
        task.join().expect("bounded TC reader completed");
        let after: ReaderRecord = array_read(reader.as_fd());
        let interval =
            paired_grace_interval(array_read(normal.as_fd()), array_read(expedited.as_fd()))
                .expect("exact paired in-kernel grace observations");
        println!(
            "reader_start_ns={} grace_entry_ns={} reader_end_ns={} grace_return_ns={}",
            after[1], interval.0, after[2], interval.1
        );
        assert!(
            after[1] <= interval.0 && interval.0 < after[2],
            "kernel grace must begin while the old reader is live"
        );
        assert!(
            after[2] <= interval.1,
            "kernel grace returned before the old reader exited"
        );
        assert_eq!(
            (after[0], after[4], after[5]),
            (29, 17, 17),
            "the old reader must retain its old row before post-grace replacement"
        );
    });
    array_update(normal.as_fd(), &[0_u64; 5]);
    array_update(expedited.as_fd(), &[0_u64; 5]);
    println!("OPC_GTPU_MAP_READER_GRACE_PROVEN");
}
