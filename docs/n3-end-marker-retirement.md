# Experimental N3 End Marker retirement

`GtpuSessionSelectorNamespaceAuthority::send_n3_end_markers(backend, retired)`
submits End Markers for an exactly retired N3 fixed-flow group. This bounded
eBPF operation advances [#790](https://github.com/openpacketcore/openpacketcore-sdk/issues/790).
The crate remains unpublished and the broad N3 capability remains `Missing`.

## Contract

Obtain `retired` from the protected coordinator's `retire` or exact
`recover_retired` operation. Await `send_n3_end_markers` to obtain
`GtpuN3EndMarkerCompletion`; `datagram_count()` reports one or two local
submissions, and `into_retired_claim()` preserves the original capability.
No caller-created tuple, generation, retired flag or drain assertion can
construct the request. Completion grants no selector reuse permission.

The namespace must remain bound to the same ledger, device, backend epoch,
pin commitment, desired graph and terminal coordinate, with no decommission
fence or consumed successor. Every entry must be N3. Any other historical
admitted group in this namespace sharing the receiving peer address and TEID
blocks submission,
including groups with different local addresses, ports, QFIs or N3 roles.

The adapter holds the exclusive namespace effect lease. It checks the full
208-byte terminal stamp, absent authority and journal, and complete absence
of each original selector key, including keys repointed to another group.
It completes the existing kernel classifier grace, then rechecks retirement,
attachment and the bounded mutation window before each send and completion.
Dropping the caller's result receiver leaves the SDK worker and namespace
permit owned until the backend settles.

## Wire profile and ordering limit

The supported profile uses IPv4 outer addresses and the original UDP source
and destination port 2152. Both inner IP families and different QFIs may share
one outgoing tunnel; that tunnel receives one marker. Distinct outgoing
tunnels receive separate markers. The existing typed codec emits message
type 254, the original peer TEID and no payload or PSC. The adapter uses the
sole managed control socket without consuming its receive queue.

The tuple and framing rules follow
[TS 29.281 V18.4.0, sections 4.4.2.6, 4.4.3.6 and 7.3.2](https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.04.00_60/ts_129281v180400p.pdf).
The special 5GS/EPS forwarding procedure that carries QFI in an End Marker
is outside this profile.

Completion establishes retirement, classifier quiescence and acceptance of
all marker datagrams by the local UDP stack. The existing qualified
`MEMBARRIER_CMD_GLOBAL` path waits for RCU readers on the supported Linux
profile; see [Linux 6.8 implementation](https://github.com/torvalds/linux/blob/v6.8/kernel/sched/membarrier.c).
It provides no qdisc/NIC drain or remote ordering/delivery receipt. Caller-owned
peer coordination and deployment qualification remain necessary. There is
no End Marker acknowledgement, automatic retry, retransmission timer, or
removal/restart authority derived from a received control message.

| Result | Meaning |
| --- | --- |
| Completion | Every distinct outgoing tunnel's marker was accepted locally; the original retired claim is retained |
| `GtpuN3EndMarkerError::Unsupported` | The whole profile was refused before any marker submission: outer IPv6, selected source port, unavailable kernel grace, or unsupported backend |
| `Namespace` / `Backend` | No completion receipt; an effect or its acknowledgement may be indeterminate, including failure to release the lease after sending |

Linux kernel-GTP, mock and unsupported-platform adapters retain the default
unsupported method. Mixed supported/unsupported groups are rejected before
any send. After an indeterminate failure, an explicit exact recovery and retry
may duplicate markers. The SDK does not infer peer receipt from prior attempts.
Value-bearing requests, receipts and completions redact `Debug`; public errors
contain no endpoint, subscriber, QFI, mark or deployment values.

## Qualification

Coordinator tests cover exact namespace/terminal coordinates, ordinary-group
refusal, shared peer tunnels, consumed successors, unsupported recovery,
detached callers, expired receipts and contained backend failures. Synthetic kernel adapter
tests cover whole-profile refusal, unavailable/failing classifier grace and
changed post-grace stamps. These tests do not establish packet forwarding.

The native `ebpf_gtpu_n3_end_marker_retirement_ordering` test installs two inner
families with QFIs 0 and 63 through the protected coordinator. An independent
UDP peer receives six real G-PDUs followed by literal eight-byte markers, with
the original addresses, port and TEIDs. It covers shared/separate peer tunnels,
backend adoption, an already-open control socket, retained incoming Echo,
post-retirement drops, every terminal-stamp byte both before and after namespace
validation, resurrected authority/journal
and original/foreign selector references, and explicit duplicate retries.

Successful native execution emits `OPC_GTPU_N3_END_MARKER_PROVEN:`. CI requires
that marker with zero ignored tests on the standard Linux and EL9 suites and
includes the test in the Linux 6.8 lane. This is synthetic local peer traffic;
it establishes no external N3IWF/UPF interoperability or full 3GPP conformance.
The PR records exact implementation revisions and local/hosted gate results.
