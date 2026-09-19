# Required-extension handoff before decapsulation

The current committed eBPF object treats its receiving GTP-U role as an
endpoint. Both outer IPv4 and IPv6 parsers finish the existing strict IP,
UDP/checksum, GTP length and bounded extension-chain checks before making
an unknown-required-extension decision. They return the original packet to
the host stack before PDR/group lookup, selector checks or decapsulation.
A required first header cannot conceal a malformed later header.

[TS 29.281 V18.4.0 clause 5.2.1](https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.04.00_60/ts_129281v180400p.pdf)
assigns comprehension from extension-type bits 8 and 7. At this endpoint,
unknown identifiers with bit 8 set require comprehension. Identifiers
1–127 have no endpoint comprehension requirement and their next-header
pointer is followed. The SGW-specific 0xc0 exception does not apply to this
endpoint profile. This change does not implement an intermediate-forwarder
profile. The existing recognized PSC identifier 0x85 retains its existing
framing path; that path does not qualify installed N3 PSC/QFI forwarding.
N3 forwarding capabilities remain unchanged.

The allocation-free `gtpu_endpoint_requires_extension_control` helper is
shared by both tc parsers and `parse_gtpu_tpdu`, the host reassembly parser.
`parse_gtpu_tpdu` returns `Ok(None)` for a complete required-extension chain,
so even a caller using the legacy raw receive/consumer path cannot accidentally
decapsulate it. `GtpuReassemblyOutcome::ControlPlane` and its counter now
include this case. The original datagram must be routed to the shared control
consumer; `ControlPlane` does not authorize resource or session changes.

The existing IPv4 `GtpuControlPort` exposes the complete datagram with its
verified socket provenance and an `UnsupportedRequiredExtension` disposition.
An admitted caller can consume that event to construct a budgeted Supported
Extension Headers Notification plan. There is no automatic response or second
UDP listener. Peer admission, aggregate rate limits and the supported-type
list remain caller policy. Without a listening consumer the kernel provides
its ordinary UDP behavior; this change does not install an application.

Non-G-PDU traffic still passes before checksum completion, preserving #644.
Malformed G-PDU envelopes still drop. Fragment handling, map layouts,
selector ownership/fences, installed generations and historical BPF objects
are unchanged. Only the current source and current committed object change.

The isolated live test runs the actual committed classifier on veth traffic:

- All 127 unknown required types reach the shared IPv4 control queue without
  incrementing decapsulation, malformed or unknown-TEID counters. It checks
  exact received bytes, peer/local/ingress metadata, a 14-byte response cap and
  each notification's independently authored bytes and service-port tuple.
- The same 127 types reach an actual outer-IPv6 UDP socket unchanged before
  grouped owner lookup. This is IPv6 host-handoff evidence; it does not claim
  an IPv6 implementation of the typed shared socket port.
- All 127 optional types deliver the exact inner UDP payload to the installed
  IPv4 tunnel's UE; each increments decapsulation exactly once and leaves the
  control queue empty.
- A required first header followed by a zero-length or overrun second header
  drops in both families, with exactly four malformed-counter increments and
  no control or user delivery.

The host parser independently replays all 255 nonterminal type identifiers
and malformed suffixes. The original parser and original committed tc object
both fail their new regression at runtime. Required CI checks the exact
executed source-test count, zero skips and the new completion marker on its
full native lanes. The PR retains source guard-removal failures, an independent
wire mutation, restored passes, tool versions and exact base/head/tree.

This increment does not qualify the Linux kernel-GTP backend, backend parity,
IPv6 typed responses, End Marker ordering, PSC insertion or installed N3
selector receipts. Those remaining #341/#790 contracts stay explicit.
