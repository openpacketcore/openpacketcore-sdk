# opc-egress-fence-common

Dependency-free `no_std` map layouts and packet-decision rules shared by the
`opc-egress-fence` userspace loader and its root-cgroup-v2 eBPF classifier.

The separate `scope_time` module provides conservative clock conversion for a
future namespace-owned scope packet gate. It converts an immutable lease stop
time into a suspend-aware kernel deadline under an explicit prospective clock
bound. It does not authenticate leases, install a gate, or change the existing
cgroup map ABI. See the [timing contract](../../docs/lease-timed-packet-gate.md).
