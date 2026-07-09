# opc-ipsec-lb-ebpf-common

Shared, dependency-free map layouts for the SWu IPsec load-balancing XDP
datapath and its userspace loader.

This crate intentionally contains no IPsec key material, packet decryption, or
runtime I/O. It defines only stable byte encodings for steering keys, redirect
targets, counters, maps, and program names.
