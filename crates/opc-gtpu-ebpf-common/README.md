# opc-gtpu-ebpf-common

Shared GTP-U (3GPP TS 29.281) wire-format layouts for the OpenPacketCore eBPF
tc datapath and its userspace loader.

This `no_std`, dependency-free crate is the single source of truth for:

- The BPF map key/value byte layouts exchanged between
  `opc-gtpu-dataplane`'s `EbpfGtpuDataplaneBackend` and the
  `opc-gtpu-dataplane-ebpf` tc programs (`UplinkFar`, `DownlinkPdr`), plus the
  map, program, and counter-index names.
- The exact 36-byte `[outer IPv4][UDP][GTPv1-U]` uplink encapsulation
  (`build_uplink_encap`), including the outer IPv4 header checksum.
- The downlink GTPv1-U header classification (`classify_gtpu`): G-PDU vs
  echo/error-indication vs non-GTPv1, TEID extraction, and S/PN/E optional
  block and extension-header detection.

Keeping this logic in a plain Rust crate means the datapath's byte-exact
behavior is unit-tested in ordinary CI without a kernel, and the eBPF program
and its loader can never disagree about layouts.

It deliberately contains no map access, no loader logic, and no policy.
