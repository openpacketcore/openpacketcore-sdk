//! Kernel cgroup-skb datapath for the lease-bound egress fence.
//!
//! The live classifier attaches only to the unified default-hierarchy root's
//! `BPF_CGROUP_INET_EGRESS` hook. The sched-cls mutation-control and read-only
//! synchronized-view programs are never attached; they exist solely for
//! `BPF_PROG_RUN`. All three programs share one BTF-visible spin lock in the
//! lock-only `OPC_FENCE_LOCK` map. Authorization data lives in separately
//! freezable maps. Control transitions perform no helper calls while the lock
//! is held. Protected packet decisions snapshot CURRENT, look up the exact
//! `(socket cookie, lifecycle token)` entry outside the lock, then re-lock and
//! require CURRENT to be unchanged before dereferencing the entry.
//! `bpf_ktime_get_boot_ns` is read only after unlocking.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(all(feature = "production", feature = "mutation-bypass-gate"))]
compile_error!("production and mutation-bypass-gate are mutually exclusive");
#[cfg(all(
    feature = "mutation-bypass-gate",
    any(feature = "mutation-bypass-deadline", feature = "fault-inject-delete")
))]
compile_error!("mutation-bypass-gate cannot be combined with another test feature");
#[cfg(all(feature = "mutation-bypass-deadline", not(feature = "production")))]
compile_error!("mutation-bypass-deadline requires the production gate");
#[cfg(all(feature = "mutation-bypass-deadline", feature = "fault-inject-delete"))]
compile_error!("mutation-bypass-deadline and fault-inject-delete are mutually exclusive");
#[cfg(not(any(feature = "production", feature = "mutation-bypass-gate")))]
compile_error!("select either production or the explicit mutation-bypass-gate test build");

use aya_ebpf::{
    bindings::{bpf_spin_lock as BpfSpinLock, BPF_NOEXIST},
    btf_maps::{Array, HashMap, PerCpuArray},
    helpers::{
        bpf_get_socket_cookie, bpf_ktime_get_boot_ns, bpf_sk_fullsock, bpf_spin_lock,
        bpf_spin_unlock,
    },
    macros::{btf_map, cgroup_skb, classifier},
    programs::{SkBuffContext, TcContext},
};
use opc_egress_fence_common::{
    decide_egress, evaluate_refresh_deadlines, ControlCommand, ControlOperation, CurrentFenceToken,
    FenceAuthoritySnapshot, FenceEntry, FenceEntryState, FenceVerdict, PacketEndpointDisposition,
    PacketFenceContext, RefreshDeadlineDecision, CONTROL_RESULT_APPLIED,
    CONTROL_RESULT_COOKIE_MISSING, CONTROL_RESULT_DEADLINE_ELAPSED, CONTROL_RESULT_EPOCH_MISMATCH,
    CONTROL_RESULT_INVALID, CONTROL_RESULT_MAP_ERROR, CONTROL_RESULT_NOT_RECLAIMABLE,
    CONTROL_RESULT_STALE_TOKEN, CONTROL_RESULT_STATE_MISMATCH, CONTROL_RESULT_TERMINAL,
    COOKIE_CONTROL_ACTIVE, COOKIE_CONTROL_INITIAL_CLOSED, COOKIE_CONTROL_RECLAIMING,
    COOKIE_CONTROL_TERMINAL_CLOSED, CURRENT_LIFECYCLE_OPEN_CONTROL,
    CURRENT_RETIREMENT_CLOSED_CONTROL, EGRESS_FENCE_ABI_VERSION, EGRESS_FENCE_CONFIG_VALUE_LEN,
    EGRESS_FENCE_CONTROL_COMMAND_LEN, EGRESS_FENCE_COOKIE_KEY_LEN, EGRESS_FENCE_COOKIE_VALUE_LEN,
    EGRESS_FENCE_COUNTER_SLOTS, EGRESS_FENCE_CURRENT_VALUE_LEN, EGRESS_FENCE_INITIAL_COOKIE_EPOCH,
    EGRESS_FENCE_INSPECT_BUFFER_LEN, EGRESS_FENCE_MAX_COOKIE_ENTRIES,
    EGRESS_FENCE_MAX_GATE_LIFETIME_NS,
};

const CONFIG_KEY: u32 = 0;
const CURRENT_KEY: u32 = 0;
const CONTROL_HEADER_FIXED_MASK: u64 = 0xff00_ffff_ffff_ffff;
const CONTROL_HEADER_FIXED: u64 =
    u32::from_le_bytes(*b"OEC1") as u64 | (EGRESS_FENCE_ABI_VERSION as u64) << 32;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_PROTOCOL_UDP: u8 = 17;
const IPV4_AMBIGUOUS_FRAGMENT_MASK: u16 = 0xbfff;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_NEXT_HEADER_HOP_BY_HOP: u8 = 0;
const IPV6_NEXT_HEADER_ROUTING: u8 = 43;
const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
const IPV6_NEXT_HEADER_ESP: u8 = 50;
const IPV6_NEXT_HEADER_AUTHENTICATION: u8 = 51;
const IPV6_NEXT_HEADER_NONE: u8 = 59;
const IPV6_NEXT_HEADER_DESTINATION: u8 = 60;
const IPV6_NEXT_HEADER_UDP: u8 = 17;
const IPV6_NEXT_HEADER_TCP: u8 = 6;
const IPV6_NEXT_HEADER_ICMPV6: u8 = 58;
const MAX_IPV6_EXTENSION_HEADERS: usize = 4;
const UDP_HEADER_LEN: usize = 8;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SOCK_DGRAM: u32 = 2;
const IPPROTO_UDP: u32 = 17;
const CGROUP_DROP: i32 = 0;
const CGROUP_ALLOW: i32 = 1;
const LAST_REFRESHABLE_EPOCH: u64 = u64::MAX - 2;
const BPF_EEXIST: i32 = -17;
const KERNEL_MAX_COOKIE_ENTRIES: usize = EGRESS_FENCE_MAX_COOKIE_ENTRIES as usize;

/// BTF-visible value containing only the shared synchronization primitive.
#[repr(C)]
#[derive(Clone, Copy)]
struct LockMapValue {
    lock: BpfSpinLock,
}

/// Frozen 24-byte current-authority ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct CurrentMapValue {
    reserved: u32,
    control: u32,
    durable_fence_token: u64,
    registered_socket_cookie: u64,
}

/// Frozen global structural-mutation generation and unique in-flight claim.
#[repr(C)]
#[derive(Clone, Copy)]
struct MutationMapValue {
    generation: u64,
    in_flight_claim: u64,
}

/// BTF-visible configuration value matching the fixed 40-byte wire ABI.
///
/// Keeping the verifier-facing value typed avoids copying the complete map
/// value onto the BPF stack before validation.
#[repr(C)]
#[derive(Clone, Copy)]
struct ConfigMapValue {
    magic: u32,
    version: u16,
    family: u8,
    reserved0: u8,
    port_be: [u8; 2],
    reserved1: [u8; 2],
    capacity: u32,
    root_cgroup_id: u64,
    address: [u8; 16],
}

#[derive(Clone, Copy)]
struct KernelConfig {
    endpoint: KernelEndpoint,
    root_cgroup_id: u64,
}

#[derive(Clone, Copy)]
struct KernelEndpoint {
    family: u8,
    address: [u8; 16],
    port: u16,
}

/// Fixed-offset prefix of the kernel `bpf_sock` context.
///
/// Named IPv6 words prevent LLVM from lowering an array comparison into
/// verifier-forbidden dynamic arithmetic on the socket context pointer.
#[repr(C)]
struct FullSocketView {
    bound_dev_if: u32,
    family: u32,
    socket_type: u32,
    protocol: u32,
    mark: u32,
    priority: u32,
    src_ip4: u32,
    src_ip6_0: u32,
    src_ip6_1: u32,
    src_ip6_2: u32,
    src_ip6_3: u32,
    src_port: u32,
}

/// Fixed synchronized Inspect response written after releasing the lock.
#[repr(C)]
#[derive(Clone, Copy)]
struct InspectionOutput {
    magic: u32,
    version: u16,
    entry_present: u8,
    reserved: u8,
    current: CurrentMapValue,
    mutation: MutationMapValue,
    entry: CookieMapValue,
    trailing_reserved: [u8; 40],
}

/// BTF-visible cookie entry matching the frozen 40-byte byte ABI.
///
/// The first word is reserved zero. The full cookie and token redundantly
/// identify the hash-map key so recycled value storage cannot be mistaken for
/// the lifecycle originally looked up by a retained BPF pointer. Every field
/// is read or changed only while the global current-token lock is held.
#[repr(C)]
#[derive(Clone, Copy)]
struct CookieMapValue {
    reserved: u32,
    control: u32,
    socket_cookie: u64,
    durable_fence_token: u64,
    deadline_boot_ns: u64,
    control_epoch: u64,
}

/// Exact map identity for one numeric socket-cookie lifecycle.
#[repr(C)]
#[derive(Clone, Copy)]
struct CookieMapKey {
    socket_cookie: u64,
    durable_fence_token: u64,
}

const _: [(); EGRESS_FENCE_COOKIE_KEY_LEN] = [(); core::mem::size_of::<CookieMapKey>()];
const _: [(); EGRESS_FENCE_COOKIE_VALUE_LEN] = [(); core::mem::size_of::<CookieMapValue>()];
const _: [(); EGRESS_FENCE_CURRENT_VALUE_LEN] = [(); core::mem::size_of::<CurrentMapValue>()];
const _: [(); EGRESS_FENCE_CONFIG_VALUE_LEN] = [(); core::mem::size_of::<ConfigMapValue>()];
const _: [(); 16] = [(); core::mem::size_of::<MutationMapValue>()];
const _: [(); 4] = [(); core::mem::size_of::<LockMapValue>()];
const _: [(); EGRESS_FENCE_INSPECT_BUFFER_LEN] = [(); core::mem::size_of::<InspectionOutput>()];

#[btf_map]
static OPC_FENCE_CKS: HashMap<CookieMapKey, CookieMapValue, KERNEL_MAX_COOKIE_ENTRIES, 0> =
    HashMap::new();

#[btf_map]
static OPC_FENCE_CFG: Array<ConfigMapValue, 1> = Array::new();

#[btf_map]
static OPC_FENCE_CTR: PerCpuArray<u64, { EGRESS_FENCE_COUNTER_SLOTS as usize }> =
    PerCpuArray::new();

#[btf_map]
static OPC_FENCE_CUR: Array<CurrentMapValue, 1> = Array::new();

#[btf_map]
static OPC_FENCE_LOCK: Array<LockMapValue, 1> = Array::new();

#[btf_map]
static OPC_FENCE_MUT: Array<MutationMapValue, 1> = Array::new();

#[cfg(feature = "fault-inject-delete")]
#[btf_map]
static OPC_FENCE_FLT: Array<u32, 2> = Array::new();

#[cgroup_skb(egress)]
pub fn opc_egress_gate(ctx: SkBuffContext) -> i32 {
    classify(&ctx)
}

#[classifier]
pub fn opc_fence_ctl(ctx: TcContext) -> i32 {
    control(&ctx) as i32
}

#[classifier]
pub fn opc_fence_view(ctx: TcContext) -> i32 {
    inspect_control(&ctx) as i32
}

#[inline(always)]
fn classify(ctx: &SkBuffContext) -> i32 {
    let Some(config) = load_config() else {
        count(opc_egress_fence_common::COUNTER_MALFORMED);
        return CGROUP_DROP;
    };

    let socket_endpoint_matches = socket_endpoint_matches(ctx, config.endpoint);
    let packet_endpoint_disposition = classify_endpoint(ctx, config.endpoint);
    #[cfg(feature = "mutation-bypass-gate")]
    if socket_endpoint_matches
        || matches!(
            packet_endpoint_disposition,
            PacketEndpointDisposition::Protected
        )
    {
        // Deliberate RED-only mutation. The build script refuses to place this
        // object at the production artifact path.
        return CGROUP_ALLOW;
    }
    match packet_endpoint_disposition {
        PacketEndpointDisposition::Unrelated if !socket_endpoint_matches => return CGROUP_ALLOW,
        PacketEndpointDisposition::Indeterminate => {
            if !socket_endpoint_matches {
                count(opc_egress_fence_common::COUNTER_MALFORMED);
                return CGROUP_DROP;
            }
        }
        PacketEndpointDisposition::Protected | PacketEndpointDisposition::Unrelated => {}
    }

    // SAFETY: the helper reads the full cookie associated with this
    // verifier-owned skb context. Zero is handled as a closed identity.
    let socket_cookie =
        socket_cookie_identity(unsafe { bpf_get_socket_cookie(ctx.skb.skb.cast()) });
    if socket_cookie == 0 {
        count(opc_egress_fence_common::COUNTER_COOKIE_ZERO);
        return CGROUP_DROP;
    }
    let Some(current_ptr) = OPC_FENCE_CUR.get_ptr_mut(CURRENT_KEY) else {
        count(opc_egress_fence_common::COUNTER_MALFORMED);
        return CGROUP_DROP;
    };
    let Some(lock_ptr) = OPC_FENCE_LOCK.get_ptr_mut(CURRENT_KEY) else {
        count(opc_egress_fence_common::COUNTER_MALFORMED);
        return CGROUP_DROP;
    };

    // First snapshot the exact lifecycle identity. No lookup helper may run
    // while the BTF spinlock is held.
    // SAFETY: current_ptr is a live BTF array-map value for this invocation.
    let current = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let current = decode_current(&*current_ptr);
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        current
    };
    let Some(current) = current else {
        count(opc_egress_fence_common::COUNTER_MALFORMED);
        return CGROUP_DROP;
    };
    if !current.is_lifecycle_open()
        || current.registered_socket_cookie() == 0
        || socket_cookie != current.registered_socket_cookie()
    {
        count(opc_egress_fence_common::COUNTER_STALE_TOKEN);
        return CGROUP_DROP;
    }
    let key = cookie_key(socket_cookie, current.durable_fence_token());
    let Some(entry_ptr) = OPC_FENCE_CKS.get_ptr_mut(key) else {
        count(opc_egress_fence_common::COUNTER_COOKIE_MISSING);
        return CGROUP_DROP;
    };

    // Revalidate the exact monotonic CURRENT value under the same lock while
    // copying the entry. A Publish, Close, or Reclaim in either lookup window
    // can therefore cause only a conservative drop. The composite key and
    // redundant entry identity reject recycled storage; the map-value pointer
    // itself remains alive under the BPF map helper's RCU lifetime guarantee.
    // SAFETY: both pointers are live map values for this invocation. Every
    // production entry mutation is serialized by the lock-only map.
    let (entry, current_unchanged) = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let current_after = decode_current(&*current_ptr);
        let unchanged = current_after == Some(current);
        let entry = if unchanged {
            decode_entry(&*entry_ptr, key)
        } else {
            None
        };
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        (entry, unchanged)
    };
    if !current_unchanged {
        count(opc_egress_fence_common::COUNTER_STALE_TOKEN);
        return CGROUP_DROP;
    }

    // Read suspend-aware time after the locked authority snapshot. A refresh
    // racing after the snapshot can cause only a conservative drop; an
    // expired deadline can never be admitted using a pre-contention clock.
    #[cfg(not(feature = "mutation-bypass-deadline"))]
    // SAFETY: this scalar helper has no pointer preconditions.
    let now_boot_ns = unsafe { bpf_ktime_get_boot_ns() };
    #[cfg(feature = "mutation-bypass-deadline")]
    // Deliberate RED-only mutation: retain exact cookie/token enforcement but
    // remove the classifier's live BOOTTIME deadline observation.
    let now_boot_ns = 0;
    let verdict = decide_egress(
        PacketFenceContext::new(
            true,
            socket_endpoint_matches,
            packet_endpoint_disposition,
            socket_cookie,
        ),
        FenceAuthoritySnapshot::new(
            entry,
            current.durable_fence_token(),
            current.registered_socket_cookie(),
            now_boot_ns,
        ),
    );
    count_verdict(verdict);
    match verdict {
        FenceVerdict::Allow => CGROUP_ALLOW,
        FenceVerdict::PassUnrelated => CGROUP_ALLOW,
        _ => CGROUP_DROP,
    }
}

#[inline(always)]
fn control(ctx: &TcContext) -> u32 {
    let Some(command) = load_control_command(ctx, false) else {
        return CONTROL_RESULT_INVALID;
    };
    let Some(config) = load_config() else {
        return CONTROL_RESULT_INVALID;
    };
    if command.root_cgroup_id() != config.root_cgroup_id {
        return CONTROL_RESULT_INVALID;
    }
    let Some(current_ptr) = OPC_FENCE_CUR.get_ptr_mut(CURRENT_KEY) else {
        return CONTROL_RESULT_MAP_ERROR;
    };
    let Some(lock_ptr) = OPC_FENCE_LOCK.get_ptr_mut(CURRENT_KEY) else {
        return CONTROL_RESULT_MAP_ERROR;
    };
    let Some(mutation_ptr) = OPC_FENCE_MUT.get_ptr_mut(CURRENT_KEY) else {
        return CONTROL_RESULT_MAP_ERROR;
    };
    if matches!(command.operation(), ControlOperation::Register) {
        return register(lock_ptr, current_ptr, mutation_ptr, command);
    }
    if matches!(command.operation(), ControlOperation::Reclaim) {
        return reclaim(lock_ptr, current_ptr, mutation_ptr, command);
    }
    if matches!(command.operation(), ControlOperation::PublishRetirement) {
        return publish_retirement(lock_ptr, current_ptr, mutation_ptr, command);
    }
    if matches!(command.operation(), ControlOperation::PublishLifecycle) {
        // SAFETY: both pointers are stable array-map values and no helper runs
        // while the lock is held.
        return unsafe {
            bpf_spin_lock(&mut (*lock_ptr).lock);
            let result = apply_control_locked(current_ptr, mutation_ptr, None, command, 0);
            bpf_spin_unlock(&mut (*lock_ptr).lock);
            result
        };
    }
    if matches!(command.operation(), ControlOperation::Refresh) {
        return refresh(lock_ptr, current_ptr, mutation_ptr, command);
    }

    let Some(mutation_generation) = snapshot_mutation_generation(lock_ptr, mutation_ptr) else {
        return CONTROL_RESULT_MAP_ERROR;
    };
    let key = cookie_key(command.socket_cookie(), command.durable_fence_token());
    let entry_ptr = OPC_FENCE_CKS.get_ptr_mut(key);
    if entry_ptr.is_none() {
        return CONTROL_RESULT_COOKIE_MISSING;
    }

    let now_boot_ns = match command.operation() {
        ControlOperation::Activate => {
            // SAFETY: this scalar helper has no pointer preconditions and runs
            // before acquiring the BPF spinlock.
            unsafe { bpf_ktime_get_boot_ns() }
        }
        ControlOperation::Refresh
        | ControlOperation::PublishLifecycle
        | ControlOperation::PublishRetirement
        | ControlOperation::Register
        | ControlOperation::Close
        | ControlOperation::Reclaim
        | ControlOperation::Inspect => 0,
    };

    // Revalidate the structural-mutation generation before the first
    // entry-pointer dereference. A concurrent Register/Reclaim and any
    // allocator reuse can therefore only reject this operation.
    let result = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        if !mutation_generation_matches(&*mutation_ptr, mutation_generation) {
            bpf_spin_unlock(&mut (*lock_ptr).lock);
            return CONTROL_RESULT_MAP_ERROR;
        }
        let result =
            apply_control_locked(current_ptr, mutation_ptr, entry_ptr, command, now_boot_ns);
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        result
    };

    if result != CONTROL_RESULT_APPLIED {
        return result;
    }
    if matches!(command.operation(), ControlOperation::Activate) {
        // A second BOOTTIME read detects an operation that crossed its
        // absolute deadline. The classifier independently checks the same
        // deadline after every locked snapshot, so no packet can escape
        // during terminalization.
        // SAFETY: scalar helper with no pointer preconditions.
        let completed_at = unsafe { bpf_ktime_get_boot_ns() };
        if completed_at >= command.deadline_boot_ns() {
            // SAFETY: pointers remain valid for this invocation. This second
            // critical section contains no helper call.
            unsafe {
                bpf_spin_lock(&mut (*lock_ptr).lock);
                if mutation_generation_matches(&*mutation_ptr, mutation_generation) {
                    terminalize_exact_active(current_ptr, entry_ptr, command);
                }
                bpf_spin_unlock(&mut (*lock_ptr).lock);
            }
            return CONTROL_RESULT_DEADLINE_ELAPSED;
        }
    }
    CONTROL_RESULT_APPLIED
}

#[inline(always)]
fn inspect_control(ctx: &TcContext) -> u32 {
    let Some(command) = load_control_command(ctx, true) else {
        return CONTROL_RESULT_INVALID;
    };
    let Some(config) = load_config() else {
        return CONTROL_RESULT_INVALID;
    };
    if command.root_cgroup_id() != config.root_cgroup_id {
        return CONTROL_RESULT_INVALID;
    }
    let Some(current_ptr) = OPC_FENCE_CUR.get_ptr_mut(CURRENT_KEY) else {
        return CONTROL_RESULT_MAP_ERROR;
    };
    let Some(lock_ptr) = OPC_FENCE_LOCK.get_ptr_mut(CURRENT_KEY) else {
        return CONTROL_RESULT_MAP_ERROR;
    };
    let Some(mutation_ptr) = OPC_FENCE_MUT.get_ptr_mut(CURRENT_KEY) else {
        return CONTROL_RESULT_MAP_ERROR;
    };
    inspect(ctx, lock_ptr, current_ptr, mutation_ptr, command)
}

#[inline(never)]
fn inspect(
    ctx: &TcContext,
    lock_ptr: *mut LockMapValue,
    current_ptr: *mut CurrentMapValue,
    mutation_ptr: *mut MutationMapValue,
    command: ControlCommand,
) -> u32 {
    // Snapshot before the optional hash lookup. A concurrent delete claim or
    // completed generation invalidates the retained pointer before any
    // dereference.
    let mutation_generation = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let generation = (*mutation_ptr).generation;
        let idle = (*mutation_ptr).in_flight_claim == 0;
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        if !idle {
            return CONTROL_RESULT_MAP_ERROR;
        }
        generation
    };
    let key = cookie_key(command.socket_cookie(), command.durable_fence_token());
    let entry_ptr = if command.socket_cookie() == 0 {
        None
    } else {
        OPC_FENCE_CKS.get_ptr_mut(key)
    };

    let mut output = InspectionOutput {
        magic: u32::from_le_bytes(*b"OEI1"),
        version: EGRESS_FENCE_ABI_VERSION,
        entry_present: 0,
        reserved: 0,
        current: CurrentMapValue {
            reserved: 0,
            control: 0,
            durable_fence_token: 0,
            registered_socket_cookie: 0,
        },
        mutation: MutationMapValue {
            generation: 0,
            in_flight_claim: 0,
        },
        entry: CookieMapValue {
            reserved: 0,
            control: 0,
            socket_cookie: 0,
            durable_fence_token: 0,
            deadline_boot_ns: 0,
            control_epoch: 0,
        },
        trailing_reserved: [0; 40],
    };
    // SAFETY: all array pointers and any hash pointer are valid for this
    // invocation. The delete generation is checked before the conditional
    // hash-pointer dereference, and no helper runs inside the critical section.
    let valid = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let unchanged = (*mutation_ptr).generation == mutation_generation
            && (*mutation_ptr).in_flight_claim == 0;
        if unchanged {
            output.current = *current_ptr;
            output.mutation = *mutation_ptr;
            if let Some(entry_ptr) = entry_ptr {
                if decode_entry(&*entry_ptr, key).is_some() {
                    output.entry = *entry_ptr;
                    output.entry_present = 1;
                } else {
                    bpf_spin_unlock(&mut (*lock_ptr).lock);
                    return CONTROL_RESULT_INVALID;
                }
            }
        }
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        unchanged
    };
    if !valid {
        return CONTROL_RESULT_MAP_ERROR;
    }
    // The output helper runs after the synchronized snapshot is copied.
    if ctx.store(0, &output, 0).is_err() {
        return CONTROL_RESULT_MAP_ERROR;
    }
    CONTROL_RESULT_APPLIED
}

#[inline(never)]
fn publish_retirement(
    lock_ptr: *mut LockMapValue,
    current_ptr: *mut CurrentMapValue,
    mutation_ptr: *mut MutationMapValue,
    command: ControlCommand,
) -> u32 {
    // Snapshot CURRENT and the idle mutation generation before an optional
    // terminal-entry lookup.
    let (current, mutation_generation) = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let Some(current) = decode_current(&*current_ptr) else {
            bpf_spin_unlock(&mut (*lock_ptr).lock);
            return CONTROL_RESULT_INVALID;
        };
        if (*mutation_ptr).in_flight_claim != 0 {
            bpf_spin_unlock(&mut (*lock_ptr).lock);
            return CONTROL_RESULT_MAP_ERROR;
        }
        if current.is_retirement_closed() {
            let result = if current.durable_fence_token() == command.durable_fence_token() {
                CONTROL_RESULT_APPLIED
            } else {
                CONTROL_RESULT_STATE_MISMATCH
            };
            bpf_spin_unlock(&mut (*lock_ptr).lock);
            return result;
        }
        if !current.is_lifecycle_open()
            || current.durable_fence_token().checked_add(1) != Some(command.durable_fence_token())
        {
            bpf_spin_unlock(&mut (*lock_ptr).lock);
            return CONTROL_RESULT_STATE_MISMATCH;
        }
        if current.registered_socket_cookie() == 0 {
            write_current_retirement(current_ptr, command.durable_fence_token());
            bpf_spin_unlock(&mut (*lock_ptr).lock);
            return CONTROL_RESULT_APPLIED;
        }
        let generation = (*mutation_ptr).generation;
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        (current, generation)
    };

    let key = cookie_key(
        current.registered_socket_cookie(),
        current.durable_fence_token(),
    );
    let Some(entry_ptr) = OPC_FENCE_CKS.get_ptr_mut(key) else {
        return CONTROL_RESULT_COOKIE_MISSING;
    };
    // Final CURRENT/mutation checks precede the retained hash-pointer
    // dereference. Only an exact terminal lifecycle can publish R=T+1.
    unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let current_unchanged = decode_current(&*current_ptr) == Some(current);
        let mutation_unchanged = mutation_generation_matches(&*mutation_ptr, mutation_generation);
        let result = if !current_unchanged || !mutation_unchanged {
            CONTROL_RESULT_MAP_ERROR
        } else if let Some(entry) = decode_entry(&*entry_ptr, key) {
            if matches!(entry.state(), FenceEntryState::TerminalClosed) {
                write_current_retirement(current_ptr, command.durable_fence_token());
                CONTROL_RESULT_APPLIED
            } else {
                CONTROL_RESULT_STATE_MISMATCH
            }
        } else {
            CONTROL_RESULT_INVALID
        };
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        result
    }
}

#[inline(never)]
fn register(
    lock_ptr: *mut LockMapValue,
    current_ptr: *mut CurrentMapValue,
    mutation_ptr: *mut MutationMapValue,
    command: ControlCommand,
) -> u32 {
    // Reserve the one global structural-mutation claim before any hash helper.
    // Publish and every other Register/Reclaim reject while this claim is live.
    let (precheck, generation, claim) = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let (result, generation, claim) =
            reserve_register_locked(current_ptr, mutation_ptr, command);
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        (result, generation, claim)
    };
    if precheck != CONTROL_RESULT_APPLIED {
        return precheck;
    }

    let key = cookie_key(command.socket_cookie(), command.durable_fence_token());
    let initial = CookieMapValue {
        reserved: 0,
        control: COOKIE_CONTROL_INITIAL_CLOSED,
        socket_cookie: command.socket_cookie(),
        durable_fence_token: command.durable_fence_token(),
        deadline_boot_ns: 0,
        control_epoch: EGRESS_FENCE_INITIAL_COOKIE_EPOCH,
    };
    let insert_status = match OPC_FENCE_CKS.insert(key, initial, BPF_NOEXIST as u64) {
        Ok(()) => 0,
        Err(BPF_EEXIST) => 1,
        Err(_) => 2,
    };
    let entry_ptr = OPC_FENCE_CKS.get_ptr_mut(key);

    // Phase two always commits the reserved generation and clears the claim,
    // including helper error and missing-readback paths. Entry dereference is
    // impossible until ownership of the exact claim is revalidated.
    unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let owns_claim = mutation_claim_matches(&*mutation_ptr, generation, claim);
        let result = if owns_claim {
            register_phase2_locked(current_ptr, entry_ptr, command, insert_status)
        } else {
            CONTROL_RESULT_MAP_ERROR
        };
        if owns_claim {
            commit_mutation_locked(&mut *mutation_ptr, claim);
        }
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        result
    }
}

/// Refresh an active entry through a fail-closed two-phase clock observation.
///
/// The entry is changed to RECLAIMING under the global mutation claim before
/// BOOTTIME is read. It therefore cannot authorize traffic, and no competing
/// lifecycle operation can alter it, while a contended refresh determines
/// whether the prior deadline is still live. The BOOTTIME observation is the
/// refresh linearization point.
#[inline(never)]
fn refresh(
    lock_ptr: *mut LockMapValue,
    current_ptr: *mut CurrentMapValue,
    mutation_ptr: *mut MutationMapValue,
    command: ControlCommand,
) -> u32 {
    let (precheck, generation, claim) = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let (result, generation, claim) =
            reserve_refresh_locked(current_ptr, mutation_ptr, command);
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        (result, generation, claim)
    };
    if precheck != CONTROL_RESULT_APPLIED {
        return precheck;
    }

    let key = cookie_key(command.socket_cookie(), command.durable_fence_token());
    let entry_ptr = OPC_FENCE_CKS.get_ptr_mut(key);
    let (phase_one, prior_deadline) = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let owns_claim = mutation_claim_matches(&*mutation_ptr, generation, claim);
        let (result, deadline) = if !owns_claim {
            (CONTROL_RESULT_MAP_ERROR, 0)
        } else if let Some(entry_ptr) = entry_ptr {
            prepare_refresh_locked(&mut *entry_ptr, command)
        } else {
            (CONTROL_RESULT_COOKIE_MISSING, 0)
        };
        if owns_claim && result != CONTROL_RESULT_APPLIED {
            commit_mutation_locked(&mut *mutation_ptr, claim);
        }
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        (result, deadline)
    };
    if phase_one != CONTROL_RESULT_APPLIED {
        return phase_one;
    }

    // SAFETY: scalar helper with no pointer preconditions. The entry is
    // already closed and the global mutation claim excludes every competing
    // lifecycle transition.
    let observed_at = unsafe { bpf_ktime_get_boot_ns() };
    let phase_two = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let owns_claim = mutation_claim_matches(&*mutation_ptr, generation, claim);
        let result = if !owns_claim {
            CONTROL_RESULT_MAP_ERROR
        } else if let Some(entry_ptr) = entry_ptr {
            complete_refresh_locked(
                current_ptr,
                &mut *entry_ptr,
                command,
                prior_deadline,
                observed_at,
            )
        } else {
            CONTROL_RESULT_COOKIE_MISSING
        };
        if owns_claim && result != CONTROL_RESULT_APPLIED {
            commit_mutation_locked(&mut *mutation_ptr, claim);
        }
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        result
    };
    if phase_two != CONTROL_RESULT_APPLIED {
        return phase_two;
    }

    // Read BOOTTIME again before publishing ACTIVE. The entry remains
    // RECLAIMING and the mutation claim remains live after phase two, so no
    // packet or successor control operation can observe renewed authority
    // before this completion observation proves both the prior and requested
    // deadlines are still live.
    // SAFETY: the production path is a scalar helper with no pointer
    // preconditions; the fault build additionally accesses its test-only map.
    let completed_at = unsafe { refresh_completion_observation(prior_deadline) };
    unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let owns_claim = mutation_claim_matches(&*mutation_ptr, generation, claim);
        let result = if !owns_claim {
            CONTROL_RESULT_MAP_ERROR
        } else {
            let result = finalize_refresh_locked(
                current_ptr,
                entry_ptr,
                command,
                prior_deadline,
                completed_at,
            );
            commit_mutation_locked(&mut *mutation_ptr, claim);
            result
        };
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        result
    }
}

#[inline(always)]
unsafe fn refresh_completion_observation(prior_deadline: u64) -> u64 {
    // SAFETY: scalar helper with no pointer preconditions.
    let observed_at = unsafe { bpf_ktime_get_boot_ns() };
    #[cfg(feature = "fault-inject-delete")]
    {
        // Deterministic actual-object oracle hook: slot zero forces the final
        // observation to equality with the prior deadline, independently of
        // the delete-failure hook in slot one.
        if let Some(fault) = OPC_FENCE_FLT.get_ptr_mut(0) {
            if unsafe { *fault } != 0 {
                unsafe {
                    *fault = 0;
                }
                return prior_deadline;
            }
        }
    }
    #[cfg(not(feature = "fault-inject-delete"))]
    let _ = prior_deadline;
    observed_at
}

#[inline(always)]
fn snapshot_mutation_generation(
    lock_ptr: *mut LockMapValue,
    mutation_ptr: *mut MutationMapValue,
) -> Option<u64> {
    // SAFETY: both pointers are stable array-map values. The critical section
    // contains no helper calls or map lookups.
    unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let generation = (*mutation_ptr).generation;
        let valid = (*mutation_ptr).in_flight_claim == 0;
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        if valid {
            Some(generation)
        } else {
            None
        }
    }
}

#[inline(always)]
fn mutation_generation_matches(value: &MutationMapValue, generation: u64) -> bool {
    value.generation == generation && value.in_flight_claim == 0
}

#[inline(always)]
fn mutation_claim_matches(value: &MutationMapValue, generation: u64, claim: u64) -> bool {
    generation != u64::MAX
        && claim == generation + 1
        && value.generation == generation
        && value.in_flight_claim == claim
}

#[inline(never)]
fn reclaim(
    lock_ptr: *mut LockMapValue,
    current_ptr: *mut CurrentMapValue,
    mutation_ptr: *mut MutationMapValue,
    command: ControlCommand,
) -> u32 {
    let (precheck, generation, claim) = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let (result, generation, claim) =
            reserve_reclaim_locked(current_ptr, mutation_ptr, command);
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        (result, generation, claim)
    };
    if precheck != CONTROL_RESULT_APPLIED {
        return precheck;
    }

    let key = cookie_key(command.socket_cookie(), command.durable_fence_token());
    let entry_ptr = OPC_FENCE_CKS.get_ptr_mut(key);
    let result = unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let owns_claim = mutation_claim_matches(&*mutation_ptr, generation, claim);
        let result = if !owns_claim {
            CONTROL_RESULT_MAP_ERROR
        } else if let Some(current) = decode_current(&*current_ptr) {
            if let Some(entry_ptr) = entry_ptr {
                reclaim_locked(&mut *entry_ptr, current, command)
            } else {
                CONTROL_RESULT_COOKIE_MISSING
            }
        } else {
            CONTROL_RESULT_INVALID
        };
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        result
    };

    let removal = if result == CONTROL_RESULT_APPLIED {
        remove_cookie(&key, 1)
    } else {
        Ok(())
    };
    let finalized = finish_mutation(lock_ptr, mutation_ptr, generation, claim);
    if !finalized || removal.is_err() {
        CONTROL_RESULT_MAP_ERROR
    } else {
        result
    }
}

#[inline(always)]
fn finish_mutation(
    lock_ptr: *mut LockMapValue,
    mutation_ptr: *mut MutationMapValue,
    generation: u64,
    claim: u64,
) -> bool {
    // SAFETY: stable lock/mutation array pointers and no helper inside the
    // critical section.
    unsafe {
        bpf_spin_lock(&mut (*lock_ptr).lock);
        let valid = mutation_claim_matches(&*mutation_ptr, generation, claim);
        if valid {
            commit_mutation_locked(&mut *mutation_ptr, claim);
        }
        bpf_spin_unlock(&mut (*lock_ptr).lock);
        valid
    }
}

#[inline(always)]
fn commit_mutation_locked(value: &mut MutationMapValue, claim: u64) {
    value.generation = claim;
    value.in_flight_claim = 0;
}

#[inline(always)]
fn remove_cookie(key: &CookieMapKey, fault_slot: u32) -> Result<(), i32> {
    #[cfg(feature = "fault-inject-delete")]
    {
        let Some(fault) = OPC_FENCE_FLT.get_ptr_mut(fault_slot) else {
            return Err(-1);
        };
        // SAFETY: a duplicate first failure is conservative and exercises the
        // same recoverable RECLAIMING state.
        if unsafe { *fault } == 0 {
            unsafe {
                *fault = 1;
            }
            return Err(-1);
        }
    }
    #[cfg(not(feature = "fault-inject-delete"))]
    let _ = fault_slot;
    OPC_FENCE_CKS.remove(key)
}

#[inline(always)]
unsafe fn reserve_register_locked(
    current_ptr: *mut CurrentMapValue,
    mutation_ptr: *mut MutationMapValue,
    command: ControlCommand,
) -> (u32, u64, u64) {
    let Some(current) = decode_current(unsafe { &*current_ptr }) else {
        return (CONTROL_RESULT_INVALID, 0, 0);
    };
    if !current.is_lifecycle_open()
        || command.durable_fence_token() != current.durable_fence_token()
    {
        return (CONTROL_RESULT_STALE_TOKEN, 0, 0);
    }
    if current.registered_socket_cookie() != 0
        && current.registered_socket_cookie() != command.socket_cookie()
    {
        return (CONTROL_RESULT_STATE_MISMATCH, 0, 0);
    }
    reserve_mutation_locked(unsafe { &mut *mutation_ptr })
}

#[inline(always)]
unsafe fn reserve_reclaim_locked(
    current_ptr: *mut CurrentMapValue,
    mutation_ptr: *mut MutationMapValue,
    command: ControlCommand,
) -> (u32, u64, u64) {
    let Some(current) = decode_current(unsafe { &*current_ptr }) else {
        return (CONTROL_RESULT_INVALID, 0, 0);
    };
    if current.durable_fence_token() <= command.durable_fence_token() {
        return (CONTROL_RESULT_NOT_RECLAIMABLE, 0, 0);
    }
    reserve_mutation_locked(unsafe { &mut *mutation_ptr })
}

#[inline(always)]
unsafe fn reserve_refresh_locked(
    current_ptr: *mut CurrentMapValue,
    mutation_ptr: *mut MutationMapValue,
    command: ControlCommand,
) -> (u32, u64, u64) {
    let Some(current) = decode_current(unsafe { &*current_ptr }) else {
        return (CONTROL_RESULT_INVALID, 0, 0);
    };
    if !current.is_lifecycle_open()
        || current.registered_socket_cookie() != command.socket_cookie()
        || command.durable_fence_token() != current.durable_fence_token()
    {
        return (CONTROL_RESULT_STALE_TOKEN, 0, 0);
    }
    reserve_mutation_locked(unsafe { &mut *mutation_ptr })
}

#[inline(always)]
fn reserve_mutation_locked(value: &mut MutationMapValue) -> (u32, u64, u64) {
    let generation = value.generation;
    if generation == u64::MAX || value.in_flight_claim != 0 {
        return (CONTROL_RESULT_MAP_ERROR, 0, 0);
    }
    let claim = generation + 1;
    value.in_flight_claim = claim;
    (CONTROL_RESULT_APPLIED, generation, claim)
}

#[inline(always)]
unsafe fn register_phase2_locked(
    current_ptr: *mut CurrentMapValue,
    entry_ptr: Option<*mut CookieMapValue>,
    command: ControlCommand,
    insert_status: u32,
) -> u32 {
    let Some(current) = decode_current(unsafe { &*current_ptr }) else {
        return CONTROL_RESULT_INVALID;
    };
    if !current.is_lifecycle_open()
        || command.durable_fence_token() != current.durable_fence_token()
    {
        return CONTROL_RESULT_STALE_TOKEN;
    }
    if insert_status == 2 {
        return CONTROL_RESULT_MAP_ERROR;
    }
    let Some(entry_ptr) = entry_ptr else {
        return CONTROL_RESULT_MAP_ERROR;
    };
    let entry = unsafe { &mut *entry_ptr };
    if !initial_matches(entry, command) {
        return if current.registered_socket_cookie() == command.socket_cookie() {
            CONTROL_RESULT_TERMINAL
        } else {
            CONTROL_RESULT_STATE_MISMATCH
        };
    }
    if insert_status == 0 && current.registered_socket_cookie() == command.socket_cookie() {
        // A fresh insertion beneath retained CURRENT is a delayed resurrection
        // after terminal reclaim. Preserve a non-reopenable tombstone; no
        // Register invocation deletes a hash entry.
        write_terminal(
            entry,
            command.socket_cookie(),
            command.durable_fence_token(),
            EGRESS_FENCE_INITIAL_COOKIE_EPOCH,
        );
        return CONTROL_RESULT_TERMINAL;
    }
    if current.registered_socket_cookie() == 0 {
        unsafe {
            (*current_ptr).registered_socket_cookie = command.socket_cookie();
        }
        return CONTROL_RESULT_APPLIED;
    }
    if insert_status == 1 && current.registered_socket_cookie() == command.socket_cookie() {
        // An exact retry is idempotent only after BPF_NOEXIST returned EEXIST
        // and locked readback found the exact initial value named by CURRENT.
        return CONTROL_RESULT_APPLIED;
    }
    CONTROL_RESULT_STATE_MISMATCH
}

#[inline(always)]
fn initial_matches(entry: &CookieMapValue, command: ControlCommand) -> bool {
    entry.reserved == 0
        && entry.control == COOKIE_CONTROL_INITIAL_CLOSED
        && entry.socket_cookie == command.socket_cookie()
        && entry.durable_fence_token == command.durable_fence_token()
        && entry.deadline_boot_ns == 0
        && entry.control_epoch == EGRESS_FENCE_INITIAL_COOKIE_EPOCH
}

#[inline(always)]
fn load_control_command(ctx: &TcContext, expect_inspect: bool) -> Option<ControlCommand> {
    let input_len = ctx.len() as usize;
    if input_len != EGRESS_FENCE_CONTROL_COMMAND_LEN && input_len != EGRESS_FENCE_INSPECT_BUFFER_LEN
    {
        return None;
    }
    let header = ctx.load::<u64>(0).ok()?;
    if header & CONTROL_HEADER_FIXED_MASK != CONTROL_HEADER_FIXED {
        return None;
    }
    let operation = match (header >> 48) as u8 {
        1 => ControlOperation::PublishLifecycle,
        2 => ControlOperation::Register,
        3 => ControlOperation::Activate,
        4 => ControlOperation::Refresh,
        5 => ControlOperation::Close,
        6 => ControlOperation::Reclaim,
        7 => ControlOperation::Inspect,
        8 => ControlOperation::PublishRetirement,
        _ => return None,
    };
    if matches!(operation, ControlOperation::Inspect) != expect_inspect {
        return None;
    }
    if matches!(operation, ControlOperation::Inspect) {
        if input_len != EGRESS_FENCE_INSPECT_BUFFER_LEN
            || ctx.load::<u64>(48).ok()? != 0
            || ctx.load::<u64>(56).ok()? != 0
            || ctx.load::<u64>(64).ok()? != 0
            || ctx.load::<u64>(72).ok()? != 0
            || ctx.load::<u64>(80).ok()? != 0
            || ctx.load::<u64>(88).ok()? != 0
            || ctx.load::<u64>(96).ok()? != 0
            || ctx.load::<u64>(104).ok()? != 0
            || ctx.load::<u64>(112).ok()? != 0
            || ctx.load::<u64>(120).ok()? != 0
        {
            return None;
        }
    } else if input_len != EGRESS_FENCE_CONTROL_COMMAND_LEN {
        return None;
    }
    ControlCommand::new(
        operation,
        ctx.load::<u64>(8).ok()?,
        ctx.load::<u64>(16).ok()?,
        ctx.load::<u64>(24).ok()?,
        ctx.load::<u64>(32).ok()?,
        ctx.load::<u64>(40).ok()?,
    )
}

#[inline(always)]
unsafe fn apply_control_locked(
    current_ptr: *mut CurrentMapValue,
    mutation_ptr: *mut MutationMapValue,
    entry_ptr: Option<*mut CookieMapValue>,
    command: ControlCommand,
    now_boot_ns: u64,
) -> u32 {
    let Some(current) = decode_current(unsafe { &*current_ptr }) else {
        return CONTROL_RESULT_INVALID;
    };
    match command.operation() {
        ControlOperation::PublishLifecycle => {
            if unsafe { (*mutation_ptr).in_flight_claim } != 0 {
                return CONTROL_RESULT_MAP_ERROR;
            }
            if command.durable_fence_token() < current.durable_fence_token() {
                return CONTROL_RESULT_STALE_TOKEN;
            }
            if command.durable_fence_token() == current.durable_fence_token() {
                // Exact open-lifecycle retry preserves the claimed cookie.
                return if current.is_lifecycle_open() {
                    CONTROL_RESULT_APPLIED
                } else {
                    CONTROL_RESULT_STATE_MISMATCH
                };
            }
            // A higher value is the global fencing linearization point. It
            // immediately stales the predecessor and creates one unclaimed
            // lifecycle slot for Register.
            unsafe {
                (*current_ptr).reserved = 0;
                (*current_ptr).control = CURRENT_LIFECYCLE_OPEN_CONTROL;
                (*current_ptr).durable_fence_token = command.durable_fence_token();
                (*current_ptr).registered_socket_cookie = 0;
            }
            CONTROL_RESULT_APPLIED
        }
        ControlOperation::Register
        | ControlOperation::Reclaim
        | ControlOperation::Inspect
        | ControlOperation::PublishRetirement => CONTROL_RESULT_INVALID,
        ControlOperation::Activate => {
            let Some(entry_ptr) = entry_ptr else {
                return CONTROL_RESULT_COOKIE_MISSING;
            };
            activate_locked(unsafe { &mut *entry_ptr }, current, command, now_boot_ns)
        }
        ControlOperation::Refresh => CONTROL_RESULT_INVALID,
        ControlOperation::Close => {
            let Some(entry_ptr) = entry_ptr else {
                return CONTROL_RESULT_COOKIE_MISSING;
            };
            close_locked(unsafe { &mut *entry_ptr }, command)
        }
    }
}

#[inline(always)]
fn activate_locked(
    entry: &mut CookieMapValue,
    current: CurrentFenceToken,
    command: ControlCommand,
    now_boot_ns: u64,
) -> u32 {
    let Some(decoded) = decode_entry(
        entry,
        cookie_key(command.socket_cookie(), command.durable_fence_token()),
    ) else {
        return CONTROL_RESULT_INVALID;
    };
    if decoded.control_epoch() != command.expected_epoch() {
        return CONTROL_RESULT_EPOCH_MISMATCH;
    }
    if !current.is_lifecycle_open()
        || current.registered_socket_cookie() != command.socket_cookie()
        || command.durable_fence_token() != current.durable_fence_token()
        || decoded.durable_fence_token() != current.durable_fence_token()
    {
        return CONTROL_RESULT_STALE_TOKEN;
    }
    if matches!(
        decoded.state(),
        FenceEntryState::TerminalClosed | FenceEntryState::Reclaiming
    ) {
        return CONTROL_RESULT_TERMINAL;
    }
    if !matches!(decoded.state(), FenceEntryState::InitialClosed) {
        return CONTROL_RESULT_STATE_MISMATCH;
    }
    if !deadline_within_gate_lifetime(now_boot_ns, command.deadline_boot_ns()) {
        return CONTROL_RESULT_DEADLINE_ELAPSED;
    }
    if decoded.control_epoch() > LAST_REFRESHABLE_EPOCH {
        return CONTROL_RESULT_INVALID;
    }
    let next_epoch = decoded.control_epoch() + 1;
    write_active(
        entry,
        command.socket_cookie(),
        command.durable_fence_token(),
        command.deadline_boot_ns(),
        next_epoch,
    );
    CONTROL_RESULT_APPLIED
}

#[inline(always)]
fn prepare_refresh_locked(entry: &mut CookieMapValue, command: ControlCommand) -> (u32, u64) {
    let Some(decoded) = decode_entry(
        entry,
        cookie_key(command.socket_cookie(), command.durable_fence_token()),
    ) else {
        return (CONTROL_RESULT_INVALID, 0);
    };
    if decoded.control_epoch() != command.expected_epoch() {
        return (CONTROL_RESULT_EPOCH_MISMATCH, 0);
    }
    if matches!(
        decoded.state(),
        FenceEntryState::TerminalClosed | FenceEntryState::Reclaiming
    ) {
        return (CONTROL_RESULT_TERMINAL, 0);
    }
    if !matches!(decoded.state(), FenceEntryState::Active) {
        return (CONTROL_RESULT_STATE_MISMATCH, 0);
    }
    if decoded.control_epoch() > LAST_REFRESHABLE_EPOCH {
        return (CONTROL_RESULT_INVALID, 0);
    }
    entry.control = COOKIE_CONTROL_RECLAIMING;
    entry.deadline_boot_ns = 0;
    (CONTROL_RESULT_APPLIED, decoded.deadline_boot_ns())
}

#[inline(always)]
unsafe fn complete_refresh_locked(
    current_ptr: *mut CurrentMapValue,
    entry: &mut CookieMapValue,
    command: ControlCommand,
    prior_deadline: u64,
    observed_at: u64,
) -> u32 {
    let Some(current) = decode_current(unsafe { &*current_ptr }) else {
        return CONTROL_RESULT_INVALID;
    };
    if !current.is_lifecycle_open()
        || current.registered_socket_cookie() != command.socket_cookie()
        || command.durable_fence_token() != current.durable_fence_token()
        || entry.reserved != 0
        || entry.control != COOKIE_CONTROL_RECLAIMING
        || entry.socket_cookie != command.socket_cookie()
        || entry.durable_fence_token != command.durable_fence_token()
        || entry.deadline_boot_ns != 0
        || entry.control_epoch != command.expected_epoch()
    {
        return CONTROL_RESULT_MAP_ERROR;
    }
    let next_epoch = command.expected_epoch() + 1;
    match evaluate_refresh_deadlines(observed_at, prior_deadline, command.deadline_boot_ns()) {
        // Keep the entry RECLAIMING until the post-phase BOOTTIME observation
        // has also proved that the old authorization did not expire during
        // this invocation.
        RefreshDeadlineDecision::Apply => CONTROL_RESULT_APPLIED,
        RefreshDeadlineDecision::PriorExpired => {
            write_terminal(
                entry,
                command.socket_cookie(),
                command.durable_fence_token(),
                next_epoch,
            );
            CONTROL_RESULT_DEADLINE_ELAPSED
        }
        RefreshDeadlineDecision::RequestedDeadlineInvalid => {
            write_active(
                entry,
                command.socket_cookie(),
                command.durable_fence_token(),
                prior_deadline,
                command.expected_epoch(),
            );
            CONTROL_RESULT_DEADLINE_ELAPSED
        }
        RefreshDeadlineDecision::DeadlineRegressed => {
            write_active(
                entry,
                command.socket_cookie(),
                command.durable_fence_token(),
                prior_deadline,
                command.expected_epoch(),
            );
            CONTROL_RESULT_STATE_MISMATCH
        }
    }
}

#[inline(always)]
unsafe fn finalize_refresh_locked(
    current_ptr: *mut CurrentMapValue,
    entry_ptr: Option<*mut CookieMapValue>,
    command: ControlCommand,
    prior_deadline: u64,
    completed_at: u64,
) -> u32 {
    let Some(current) = decode_current(unsafe { &*current_ptr }) else {
        return CONTROL_RESULT_INVALID;
    };
    if !current.is_lifecycle_open()
        || current.registered_socket_cookie() != command.socket_cookie()
        || command.durable_fence_token() != current.durable_fence_token()
    {
        return CONTROL_RESULT_MAP_ERROR;
    }
    let Some(entry_ptr) = entry_ptr else {
        return CONTROL_RESULT_COOKIE_MISSING;
    };
    let entry = unsafe { &mut *entry_ptr };
    if entry.reserved != 0
        || entry.control != COOKIE_CONTROL_RECLAIMING
        || entry.socket_cookie != command.socket_cookie()
        || entry.durable_fence_token != command.durable_fence_token()
        || entry.deadline_boot_ns != 0
        || entry.control_epoch != command.expected_epoch()
    {
        return CONTROL_RESULT_MAP_ERROR;
    }
    let Some(next_epoch) = command.expected_epoch().checked_add(1) else {
        return CONTROL_RESULT_INVALID;
    };
    if completed_at >= prior_deadline || completed_at >= command.deadline_boot_ns() {
        write_terminal(
            entry,
            command.socket_cookie(),
            command.durable_fence_token(),
            next_epoch,
        );
        CONTROL_RESULT_DEADLINE_ELAPSED
    } else {
        write_active(
            entry,
            command.socket_cookie(),
            command.durable_fence_token(),
            command.deadline_boot_ns(),
            next_epoch,
        );
        CONTROL_RESULT_APPLIED
    }
}

#[inline(always)]
fn close_locked(entry: &mut CookieMapValue, command: ControlCommand) -> u32 {
    let Some(decoded) = decode_entry(
        entry,
        cookie_key(command.socket_cookie(), command.durable_fence_token()),
    ) else {
        return CONTROL_RESULT_INVALID;
    };
    if decoded.control_epoch() != command.expected_epoch() {
        return CONTROL_RESULT_EPOCH_MISMATCH;
    }
    if command.durable_fence_token() == 0
        || command.durable_fence_token() != decoded.durable_fence_token()
    {
        return CONTROL_RESULT_STALE_TOKEN;
    }
    if matches!(
        decoded.state(),
        FenceEntryState::TerminalClosed | FenceEntryState::Reclaiming
    ) {
        return CONTROL_RESULT_TERMINAL;
    }
    let Some(next_epoch) = decoded.control_epoch().checked_add(1) else {
        return CONTROL_RESULT_INVALID;
    };
    write_terminal(
        entry,
        command.socket_cookie(),
        decoded.durable_fence_token(),
        next_epoch,
    );
    CONTROL_RESULT_APPLIED
}

#[inline(always)]
fn reclaim_locked(
    entry: &mut CookieMapValue,
    current: CurrentFenceToken,
    command: ControlCommand,
) -> u32 {
    let Some(decoded) = decode_entry(
        entry,
        cookie_key(command.socket_cookie(), command.durable_fence_token()),
    ) else {
        return CONTROL_RESULT_INVALID;
    };
    if decoded.control_epoch() != command.expected_epoch() {
        return CONTROL_RESULT_EPOCH_MISMATCH;
    }
    if command.durable_fence_token() != decoded.durable_fence_token() {
        return CONTROL_RESULT_STALE_TOKEN;
    }
    // An exact-CURRENT entry cannot be deleted: a classifier may already hold
    // its value pointer between composite lookup and final CURRENT
    // revalidation. Any canonical strictly higher CURRENT token is the global
    // fencing linearization point and makes this composite key permanently
    // non-authoritative, even if the old fd remains open. The global mutation
    // claim excludes concurrent publication/registration/reclaim while the
    // helper can recycle map storage.
    if current.durable_fence_token() <= command.durable_fence_token() {
        return CONTROL_RESULT_NOT_RECLAIMABLE;
    }
    // Every decoded state is canonical and fail-closed after CURRENT
    // supersession. Publish the complete retryable deletion state before
    // invoking the hash delete helper: Active must not retain its deadline,
    // and InitialClosed legitimately retains epoch one.
    entry.control = COOKIE_CONTROL_RECLAIMING;
    entry.reserved = 0;
    entry.socket_cookie = command.socket_cookie();
    entry.durable_fence_token = command.durable_fence_token();
    entry.deadline_boot_ns = 0;
    entry.control_epoch = command.expected_epoch();
    CONTROL_RESULT_APPLIED
}

#[inline(always)]
unsafe fn terminalize_exact_active(
    current_ptr: *mut CurrentMapValue,
    entry_ptr: Option<*mut CookieMapValue>,
    command: ControlCommand,
) {
    let Some(current) = decode_current(unsafe { &*current_ptr }) else {
        return;
    };
    if !current.is_lifecycle_open()
        || current.durable_fence_token() != command.durable_fence_token()
        || current.registered_socket_cookie() != command.socket_cookie()
    {
        return;
    }
    let Some(entry_ptr) = entry_ptr else {
        return;
    };
    let entry = unsafe { &mut *entry_ptr };
    let Some(decoded) = decode_entry(
        entry,
        cookie_key(command.socket_cookie(), command.durable_fence_token()),
    ) else {
        return;
    };
    if !matches!(decoded.state(), FenceEntryState::Active)
        || decoded.durable_fence_token() != command.durable_fence_token()
        || decoded.deadline_boot_ns() != command.deadline_boot_ns()
        || decoded.control_epoch() != command.expected_epoch() + 1
    {
        return;
    }
    let Some(terminal_epoch) = decoded.control_epoch().checked_add(1) else {
        return;
    };
    write_terminal(
        entry,
        command.socket_cookie(),
        decoded.durable_fence_token(),
        terminal_epoch,
    );
}

#[inline(always)]
fn write_active(
    entry: &mut CookieMapValue,
    socket_cookie: u64,
    token: u64,
    deadline: u64,
    epoch: u64,
) {
    entry.control = COOKIE_CONTROL_RECLAIMING;
    entry.reserved = 0;
    entry.socket_cookie = socket_cookie;
    entry.durable_fence_token = token;
    entry.deadline_boot_ns = deadline;
    entry.control_epoch = epoch;
    // Publish ACTIVE last: lockless observation outside the control domain can
    // see only the old state, RECLAIMING/drop, or the complete new state.
    entry.control = COOKIE_CONTROL_ACTIVE;
}

#[inline(always)]
fn write_terminal(entry: &mut CookieMapValue, socket_cookie: u64, token: u64, epoch: u64) {
    entry.control = COOKIE_CONTROL_RECLAIMING;
    entry.reserved = 0;
    entry.socket_cookie = socket_cookie;
    entry.durable_fence_token = token;
    entry.deadline_boot_ns = 0;
    entry.control_epoch = epoch;
    // Publish TERMINAL last so no partial value is ever interpreted active.
    entry.control = COOKIE_CONTROL_TERMINAL_CLOSED;
}

#[inline(always)]
unsafe fn write_current_retirement(current_ptr: *mut CurrentMapValue, token: u64) {
    unsafe {
        (*current_ptr).reserved = 0;
        (*current_ptr).control = CURRENT_RETIREMENT_CLOSED_CONTROL;
        (*current_ptr).durable_fence_token = token;
        (*current_ptr).registered_socket_cookie = 0;
    }
}

#[inline(always)]
fn load_config() -> Option<KernelConfig> {
    let ptr = OPC_FENCE_CFG.get_ptr(CONFIG_KEY)?;
    // SAFETY: the single array-map value is immutable for this invocation.
    let value = unsafe { &*ptr };
    if value.magic != u32::from_le_bytes(*b"OEF1")
        || value.version != EGRESS_FENCE_ABI_VERSION
        || value.reserved0 != 0
        || value.reserved1 != [0; 2]
        || value.root_cgroup_id == 0
        || value.capacity != EGRESS_FENCE_MAX_COOKIE_ENTRIES
    {
        return None;
    }
    let port = u16::from_be_bytes(value.port_be);
    if port == 0 {
        return None;
    }
    match value.family {
        4 => {
            if value.address[0] == 0
                && value.address[1] == 0
                && value.address[2] == 0
                && value.address[3] == 0
                || value.address[0] >= 224
                || value.address[4] != 0
                || value.address[5] != 0
                || value.address[6] != 0
                || value.address[7] != 0
                || value.address[8] != 0
                || value.address[9] != 0
                || value.address[10] != 0
                || value.address[11] != 0
                || value.address[12] != 0
                || value.address[13] != 0
                || value.address[14] != 0
                || value.address[15] != 0
            {
                return None;
            }
        }
        6 => {
            let address_is_zero = value.address[0] == 0
                && value.address[1] == 0
                && value.address[2] == 0
                && value.address[3] == 0
                && value.address[4] == 0
                && value.address[5] == 0
                && value.address[6] == 0
                && value.address[7] == 0
                && value.address[8] == 0
                && value.address[9] == 0
                && value.address[10] == 0
                && value.address[11] == 0
                && value.address[12] == 0
                && value.address[13] == 0
                && value.address[14] == 0
                && value.address[15] == 0;
            let ipv4_mapped = value.address[0] == 0
                && value.address[1] == 0
                && value.address[2] == 0
                && value.address[3] == 0
                && value.address[4] == 0
                && value.address[5] == 0
                && value.address[6] == 0
                && value.address[7] == 0
                && value.address[8] == 0
                && value.address[9] == 0
                && value.address[10] == 0xff
                && value.address[11] == 0xff;
            let link_local = value.address[0] == 0xfe && value.address[1] & 0xc0 == 0x80;
            if address_is_zero || value.address[0] == 0xff || ipv4_mapped || link_local {
                return None;
            }
        }
        _ => return None,
    }
    let endpoint = KernelEndpoint {
        family: value.family,
        address: value.address,
        port,
    };
    Some(KernelConfig {
        endpoint,
        root_cgroup_id: value.root_cgroup_id,
    })
}

#[inline(always)]
fn decode_current(value: &CurrentMapValue) -> Option<CurrentFenceToken> {
    if value.reserved != 0 {
        return None;
    }
    if value.control == 0 && value.durable_fence_token == 0 && value.registered_socket_cookie == 0 {
        return Some(CurrentFenceToken::initial());
    }
    match value.control {
        CURRENT_LIFECYCLE_OPEN_CONTROL if value.registered_socket_cookie == 0 => {
            CurrentFenceToken::lifecycle_open(value.durable_fence_token)
        }
        CURRENT_LIFECYCLE_OPEN_CONTROL => {
            CurrentFenceToken::registered(value.durable_fence_token, value.registered_socket_cookie)
        }
        CURRENT_RETIREMENT_CLOSED_CONTROL if value.registered_socket_cookie == 0 => {
            CurrentFenceToken::retirement_closed(value.durable_fence_token)
        }
        _ => None,
    }
}

#[inline(always)]
fn decode_entry(value: &CookieMapValue, expected_key: CookieMapKey) -> Option<FenceEntry> {
    if value.socket_cookie != expected_key.socket_cookie
        || value.durable_fence_token != expected_key.durable_fence_token
    {
        return None;
    }
    if value.reserved != 0 {
        return None;
    }
    match value.control {
        COOKIE_CONTROL_INITIAL_CLOSED
            if value.deadline_boot_ns == 0
                && value.control_epoch == EGRESS_FENCE_INITIAL_COOKIE_EPOCH =>
        {
            FenceEntry::initial_closed(value.durable_fence_token)
        }
        COOKIE_CONTROL_ACTIVE => FenceEntry::active(
            value.durable_fence_token,
            value.deadline_boot_ns,
            value.control_epoch,
        ),
        COOKIE_CONTROL_TERMINAL_CLOSED if value.deadline_boot_ns == 0 => {
            FenceEntry::terminal_closed(value.durable_fence_token, value.control_epoch)
        }
        COOKIE_CONTROL_RECLAIMING if value.deadline_boot_ns == 0 => {
            FenceEntry::reclaiming(value.durable_fence_token, value.control_epoch)
        }
        _ => None,
    }
}

#[inline(always)]
const fn cookie_key(socket_cookie: u64, durable_fence_token: u64) -> CookieMapKey {
    CookieMapKey {
        socket_cookie,
        durable_fence_token,
    }
}

#[inline(always)]
const fn socket_cookie_identity(cookie: u64) -> u64 {
    cookie
}

#[inline(always)]
const fn deadline_within_gate_lifetime(now_boot_ns: u64, deadline_boot_ns: u64) -> bool {
    deadline_boot_ns > now_boot_ns
        && deadline_boot_ns - now_boot_ns <= EGRESS_FENCE_MAX_GATE_LIFETIME_NS
}

#[inline(always)]
fn socket_endpoint_matches(ctx: &SkBuffContext, endpoint: KernelEndpoint) -> bool {
    // The cgroup egress hook runs after source NAT. The bound full-socket
    // identity is therefore the primary selector: a protected socket remains
    // fenced even when the packet tuple is rewritten away from its bind.
    //
    // SAFETY: `sk` is an invocation-local borrowed context pointer. The
    // fullsock helper is a non-acquiring cast; a successful result must not be
    // released with `bpf_sk_release`.
    let sk = unsafe { (*ctx.skb.skb).__bindgen_anon_2.sk };
    if sk.is_null() {
        return false;
    }
    let full = unsafe { bpf_sk_fullsock(sk) };
    if full.is_null() {
        return false;
    }
    // SAFETY: the verifier tracks the non-null full-socket pointer for this
    // invocation. All fields are scalar read-only context metadata.
    let socket = unsafe { &*full.cast::<FullSocketView>() };
    if socket.socket_type != SOCK_DGRAM
        || socket.protocol != IPPROTO_UDP
        || socket.src_port != u32::from(endpoint.port)
    {
        return false;
    }
    match endpoint.family {
        4 => {
            socket.family == AF_INET
                && socket.src_ip4
                    == network_order_word([
                        endpoint.address[0],
                        endpoint.address[1],
                        endpoint.address[2],
                        endpoint.address[3],
                    ])
        }
        6 => {
            // Volatile named loads keep LLVM from reconstructing an indexed
            // loop over the verifier's restricted socket pointer.
            let word0 = unsafe { core::ptr::read_volatile(&raw const socket.src_ip6_0) };
            let word1 = unsafe { core::ptr::read_volatile(&raw const socket.src_ip6_1) };
            let word2 = unsafe { core::ptr::read_volatile(&raw const socket.src_ip6_2) };
            let word3 = unsafe { core::ptr::read_volatile(&raw const socket.src_ip6_3) };
            socket.family == AF_INET6
                && word0
                    == network_order_word([
                        endpoint.address[0],
                        endpoint.address[1],
                        endpoint.address[2],
                        endpoint.address[3],
                    ])
                && word1
                    == network_order_word([
                        endpoint.address[4],
                        endpoint.address[5],
                        endpoint.address[6],
                        endpoint.address[7],
                    ])
                && word2
                    == network_order_word([
                        endpoint.address[8],
                        endpoint.address[9],
                        endpoint.address[10],
                        endpoint.address[11],
                    ])
                && word3
                    == network_order_word([
                        endpoint.address[12],
                        endpoint.address[13],
                        endpoint.address[14],
                        endpoint.address[15],
                    ])
        }
        _ => false,
    }
}

/// Convert network-order address bytes to the scalar representation exposed
/// by `bpf_sock` in the committed little-endian BPF object.
#[inline(always)]
const fn network_order_word(bytes: [u8; 4]) -> u32 {
    u32::from_ne_bytes(bytes)
}

#[inline(always)]
fn classify_endpoint(ctx: &SkBuffContext, endpoint: KernelEndpoint) -> PacketEndpointDisposition {
    let Ok(first) = ctx.load::<u8>(0) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    match first >> 4 {
        4 => classify_ipv4(ctx, 0, endpoint),
        6 => classify_ipv6(ctx, 0, endpoint),
        _ => PacketEndpointDisposition::Indeterminate,
    }
}

#[inline(always)]
fn classify_ipv4(
    ctx: &SkBuffContext,
    offset: usize,
    endpoint: KernelEndpoint,
) -> PacketEndpointDisposition {
    if endpoint.family != 4 {
        return PacketEndpointDisposition::Unrelated;
    }
    let protected_address = [
        endpoint.address[0],
        endpoint.address[1],
        endpoint.address[2],
        endpoint.address[3],
    ];
    let protected_port = endpoint.port;
    let Ok(header) = ctx.load::<[u8; IPV4_MIN_HEADER_LEN]>(offset) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    let version_ihl = header[0];
    let header_len = usize::from(version_ihl & 0x0f) * 4;
    if version_ihl >> 4 != 4 || header_len < IPV4_MIN_HEADER_LEN {
        return PacketEndpointDisposition::Indeterminate;
    }
    if [header[12], header[13], header[14], header[15]] != protected_address {
        return PacketEndpointDisposition::Unrelated;
    }
    let total_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let Some(packet_end) = offset.checked_add(total_len) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if header_len > total_len || packet_end > ctx.len() as usize {
        return PacketEndpointDisposition::Indeterminate;
    }
    if header[9] != IPV4_PROTOCOL_UDP {
        return PacketEndpointDisposition::Unrelated;
    }
    let fragment = u16::from_be_bytes([header[6], header[7]]);
    // DF is harmless. The reserved flag, MF, or a nonzero offset means UDP
    // cannot be classified from this skb in isolation.
    if fragment & IPV4_AMBIGUOUS_FRAGMENT_MASK != 0 {
        return PacketEndpointDisposition::Indeterminate;
    }
    let Some(udp_offset) = offset.checked_add(header_len) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if udp_offset.saturating_add(UDP_HEADER_LEN) > packet_end {
        return PacketEndpointDisposition::Indeterminate;
    }
    match load_be_u16(ctx, udp_offset) {
        Some(port) if port == protected_port => PacketEndpointDisposition::Protected,
        Some(_) => PacketEndpointDisposition::Unrelated,
        None => PacketEndpointDisposition::Indeterminate,
    }
}

#[inline(always)]
fn classify_ipv6(
    ctx: &SkBuffContext,
    offset: usize,
    endpoint: KernelEndpoint,
) -> PacketEndpointDisposition {
    if endpoint.family != 6 {
        return PacketEndpointDisposition::Unrelated;
    }
    let protected_address = endpoint.address;
    let protected_port = endpoint.port;
    let Ok(header) = ctx.load::<[u8; IPV6_HEADER_LEN]>(offset) else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if header[0] >> 4 != 6 {
        return PacketEndpointDisposition::Indeterminate;
    }
    let source = [
        header[8], header[9], header[10], header[11], header[12], header[13], header[14],
        header[15], header[16], header[17], header[18], header[19], header[20], header[21],
        header[22], header[23],
    ];
    if source != protected_address {
        return PacketEndpointDisposition::Unrelated;
    }
    let payload_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if payload_len == 0 {
        return PacketEndpointDisposition::Indeterminate;
    }
    let Some(packet_end) = offset
        .checked_add(IPV6_HEADER_LEN)
        .and_then(|base| base.checked_add(payload_len))
    else {
        return PacketEndpointDisposition::Indeterminate;
    };
    if packet_end > ctx.len() as usize {
        return PacketEndpointDisposition::Indeterminate;
    }
    let mut next_header = header[6];
    let mut cursor = offset + IPV6_HEADER_LEN;
    let mut extension_count = 0_usize;
    loop {
        match next_header {
            IPV6_NEXT_HEADER_UDP => {
                if cursor.saturating_add(UDP_HEADER_LEN) > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                return match load_be_u16(ctx, cursor) {
                    Some(port) if port == protected_port => PacketEndpointDisposition::Protected,
                    Some(_) => PacketEndpointDisposition::Unrelated,
                    None => PacketEndpointDisposition::Indeterminate,
                };
            }
            IPV6_NEXT_HEADER_NONE | IPV6_NEXT_HEADER_ESP => {
                return PacketEndpointDisposition::Unrelated;
            }
            IPV6_NEXT_HEADER_TCP | IPV6_NEXT_HEADER_ICMPV6 => {
                return PacketEndpointDisposition::Unrelated;
            }
            IPV6_NEXT_HEADER_HOP_BY_HOP
            | IPV6_NEXT_HEADER_ROUTING
            | IPV6_NEXT_HEADER_DESTINATION => {
                if extension_count >= MAX_IPV6_EXTENSION_HEADERS
                    || cursor.saturating_add(2) > packet_end
                {
                    return PacketEndpointDisposition::Indeterminate;
                }
                let Ok(prefix) = ctx.load::<[u8; 2]>(cursor) else {
                    return PacketEndpointDisposition::Indeterminate;
                };
                next_header = prefix[0];
                let header_len = (usize::from(prefix[1]) + 1) * 8;
                if header_len < 8 || cursor.saturating_add(header_len) > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                cursor += header_len;
            }
            IPV6_NEXT_HEADER_FRAGMENT => {
                if extension_count >= MAX_IPV6_EXTENSION_HEADERS
                    || cursor.saturating_add(8) > packet_end
                {
                    return PacketEndpointDisposition::Indeterminate;
                }
                let Ok(fragment) = ctx.load::<[u8; 4]>(cursor) else {
                    return PacketEndpointDisposition::Indeterminate;
                };
                next_header = fragment[0];
                // Accept only an RFC 6946 atomic fragment. A nonzero offset,
                // M flag, or reserved bit is indeterminate and fails closed.
                if u16::from_be_bytes([fragment[2], fragment[3]]) != 0 {
                    return PacketEndpointDisposition::Indeterminate;
                }
                cursor += 8;
            }
            IPV6_NEXT_HEADER_AUTHENTICATION => {
                if extension_count >= MAX_IPV6_EXTENSION_HEADERS
                    || cursor.saturating_add(2) > packet_end
                {
                    return PacketEndpointDisposition::Indeterminate;
                }
                let Ok(prefix) = ctx.load::<[u8; 2]>(cursor) else {
                    return PacketEndpointDisposition::Indeterminate;
                };
                next_header = prefix[0];
                let header_len = (usize::from(prefix[1]) + 2) * 4;
                if header_len < 8 || cursor.saturating_add(header_len) > packet_end {
                    return PacketEndpointDisposition::Indeterminate;
                }
                cursor += header_len;
            }
            _ => return PacketEndpointDisposition::Indeterminate,
        }
        extension_count += 1;
    }
}

#[inline(always)]
fn load_be_u16(ctx: &SkBuffContext, offset: usize) -> Option<u16> {
    ctx.load::<[u8; 2]>(offset).ok().map(u16::from_be_bytes)
}

#[inline(always)]
fn count_verdict(verdict: FenceVerdict) {
    if let Some(slot) = verdict.counter_slot() {
        count(slot);
    }
}

#[inline(always)]
fn count(slot: u32) {
    if let Some(counter) = OPC_FENCE_CTR.get_ptr_mut(slot) {
        // SAFETY: each map element is per-CPU, so this invocation has
        // exclusive access to its local scalar.
        unsafe { *counter += 1 };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_cookie_bits_are_never_truncated() {
        let cookie = 0xa5a5_5a5a_0102_0304;
        assert_eq!(socket_cookie_identity(cookie), cookie);
    }

    #[test]
    fn gate_lifetime_ceiling_is_overflow_safe_and_inclusive() {
        let ceiling = EGRESS_FENCE_MAX_GATE_LIFETIME_NS;
        assert!(deadline_within_gate_lifetime(10, 10 + ceiling));
        assert!(!deadline_within_gate_lifetime(10, 10 + ceiling + 1));
        assert!(!deadline_within_gate_lifetime(10, 10));
        assert!(deadline_within_gate_lifetime(u64::MAX - ceiling, u64::MAX));
        assert!(!deadline_within_gate_lifetime(u64::MAX, 1));
    }
}
