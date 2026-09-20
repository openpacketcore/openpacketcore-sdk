# Experimental N3 fixed-flow forwarding

This profile installs one fixed QFI per inner-family entry through the existing
protected opaque GTP-U selector namespace. It advances [#790](https://github.com/openpacketcore/openpacketcore-sdk/issues/790)
without claiming the complete N3IWF forwarding role. The crate remains unpublished.

## Public contract and authority

`GtpuSessionEntry::from_n3` projects `N3ForwardingIntent` into a grouped entry.
The received UPF TNL supplies the uplink destination and peer TEID. The local
N3IWF TNL supplies the downlink endpoint and local TEID. The caller also supplies
the inner PAA, attachment ifindex, source-port policies and optional DSCP. QFI
`0..63` and the complete bearer mark are explicit inputs. The existing `/32`
IPv4 and `/64` IPv6 PAA rules apply; outer endpoints must be concrete unicast
addresses of the same family. Neither an intent nor an entry authenticates a
peer, proves local address ownership, allocates a selector or authorizes effects.

`GtpuDataplaneBackend::n3_fixed_flow_capability(attachment)` reports `Available`
only for an eBPF attachment that passes the current grouped program, map and
attachment checks. It is not a traffic-readiness receipt. The default trait
implementation, Linux kernel-GTP, mock and unsupported adapters return `Missing`.
The wider `n3_forwarding_capability(N3iwf)` remains `Missing` everywhere.

Use `GtpuSessionSelectorNamespaceAuthority` for fresh admission, exact recovery
and retirement. Its encrypted durable desired descriptor binds the N3 profile
and QFI along with all existing forwarding fields. The elementary TEID/PAA/mark
reservations are unchanged. Changing QFI while retaining those selectors is not
fresh admission, and an old desired fingerprint cannot recover the changed
profile. Single-bearer reattach also requires the same profile and QFI.

The single 208-byte `GTPU_SESSION_GROUPS` value remains publication authority.
Index candidates select its generation and family slot; they do not authorize
forwarding independently. The existing worker fence, protected operation stamp,
complete readback and retirement tombstone apply to N3 entries. There is no new
QFI map or caller-created mutation permit.

## Encoding and compatibility

| Encoding | Ordinary GTP-U | Fixed-flow N3 |
| --- | --- | --- |
| 80-byte family entry, byte 0 | Version 1 | Version 2 |
| Entry byte 72 | Zero | Six-bit QFI, including zero |
| Entry bytes 73–79 | Zero | Zero |
| Atomic group / journal size | 208 / 464 bytes | Unchanged |
| Canonical desired codec | Version 1, unchanged bytes | Version 2, one QFI byte after each entry's DSCP; `0xff` denotes an ordinary entry in a mixed group |
| Outer IPv4 / IPv6 overhead | 36 / 56 bytes | 44 / 64 bytes |

A version-2 desired descriptor must contain an N3 entry. Both versions require
exact canonical re-encoding. An old classifier rejects version-2 entries; the
new loader's current-program checks prevent treating an older attachment as
N3-capable. This does not migrate older pinned graphs in place.

## Packet behavior

Uplink uses the exact existing inner PAA and complete mark selection. It emits
one PSC first, with type 1 and the installed QFI; the unused sequence/N-PDU bytes
are zero. Outer IPv4 total length, header checksum and PMTU include the eight
extra bytes. Outer IPv6 payload/UDP/GTP lengths and mandatory UDP checksum include
them as well. Existing source-port, DSCP, hop-count and offload rules still apply.

Downlink first validates the outer envelope and exact grouped authority. The
packet must contain exactly one supported type-0 PSC with the installed QFI.
RQI and optional PPI are metadata; they neither change the installed QFI nor
create a flow or selector. Unsupported conditional fields, missing/duplicate
PSC, wrong direction and wrong QFI fail closed. Optional unknown extensions can
be skipped within the existing four-extension bound. Unknown required extensions
still use the validated shared control handoff before tunnel lookup.

This uses the bounded PSC subset in [TS 38.415 V18.2.0, sections 5.5.2–5.5.3](https://www.etsi.org/deliver/etsi_ts/138400_138499/138415/18.02.00_60/ts_138415v180200p.pdf)
and the framing and extension-comprehension rules in
[TS 29.281 V18.4.0, sections 5.1–5.2](https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.04.00_60/ts_129281v180400p.pdf).
It adds no reflective-QoS policy, multi-QFI classifier, QFI-to-Child-SA allocation,
outer reassembly, new checksum-offload admission, in-place QFI replacement, or
End Marker retirement ordering. Those remaining contracts keep the broad N3
capability unavailable. Existing legacy GTP-U entries preserve their wire bytes.

## Qualification

`n3_entry_contract` starts from independent literal ABI bytes. It checks all 64
QFIs, version/reserved-byte boundaries and unicast endpoints. The shared layout
tests compare typed and zero-copy authorizers across single-byte mutations of
the full authority, selector reference and device configuration for both entry
versions. Selector tests bind each QFI to a distinct keyed desired fingerprint
without changing elementary atoms, and reject profile/QFI changes through the
single-bearer reattach shortcut.

`n3_fixed_flow_contract` compares the kernel helper against the independently
authored 2,604-case `tests/n3_reference.tsv` corpus; no fixture bytes change.
The privileged `ebpf_gtpu_n3_fixed_flow_live_contract` installs through the
protected selector namespace and sends real packets for all four inner/outer IP
combinations. Literal packet construction is independent of the SDK encoder.
It checks uplink PSC bytes, exact marks and wrong-mark rejection, downlink
QFI/direction and RQI/PPI behavior, optional extension placement, mandatory IPv6
UDP checksums, exact/one-byte-over MTU, atomic readback, changed-QFI refusal,
restart adoption and retirement in both directions. A successful native run emits `OPC_GTPU_N3_FIXED_FLOW_PROVEN:`.
CI requires that marker with zero ignored tests on the native and EL9 lanes,
and includes this contract in the Linux 6.8 verifier qualification.

The PR records exact revisions, parent/fix-removal detector results, native logs
and required gate outcomes. Value-bearing public objects retain redacted Debug
output; no per-session, QFI, mark or endpoint log/cardinality surface is added.
