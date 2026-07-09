# opc-ipsec-lb-ebpf

Standalone XDP eBPF program for SWu IPsec load balancing.

This crate is excluded from the host workspace and built with
`scripts/build-ipsec-lb-ebpf.sh` for `bpfel-unknown-none`. The userspace loader
uses the committed object through `opc-ipsec-lb`.
