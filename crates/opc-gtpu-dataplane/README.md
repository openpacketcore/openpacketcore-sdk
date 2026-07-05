# opc-gtpu-dataplane

Safe Linux GTP-U user-plane dataplane backend model, mock backend, and
redaction-safe errors for OpenPacketCore.

This crate provides:

- `GtpuDataplaneBackend`: an async trait for creating/removing Linux `gtp`
  devices and installing/removing PDP contexts.
- `MockGtpuDataplaneBackend`: a deterministic in-memory test double that
  records operations and supports injected failures.
- `LinuxGtpuDataplaneBackend`: a safe production backend that encodes SDK
  device and PDP-context requests into Linux rtnetlink/generic-netlink messages
  through `opc-linux-gtpu-sys`.
- `UnsupportedGtpuDataplaneBackend`: a backend that reports
  `UnsupportedPlatform` on all mutating operations for non-Linux or
  intentionally disabled builds.
- `GtpuError`: an error enum with payload-free labels and raw errno access safe
  for logs and support bundles.
- `GtpuProbe`: a capability probe covering route/generic netlink reachability,
  `gtp` family presence, effective `CAP_NET_ADMIN`, and UDP bind readiness.

Raw Linux socket work is intentionally kept in `opc-linux-gtpu-sys`. This crate
does not implement GTP-U packet encoding/decoding, GTP-C, PFCP, route steering,
XFRM policy, namespace management, product deployment defaults, or
traffic-readiness decisions.

## Privileged integration testing

The live Linux path is covered by the `GTP-U privileged` GitHub Actions
workflow on pull requests, pushes to `main`, and manual dispatches. That
workflow runs the ignored Rust integration test inside a fresh network
namespace after loading the Linux `gtp` module, so normal developer test runs
do not mutate host networking while CI still exercises the kernel path.

The test creates a Linux `gtp` netdevice, installs one GTPv1 PDP context,
checks that the device is visible through `ip -d link show`, removes the
context, and destroys the device.

Run it in a fresh network namespace with `CAP_NET_ADMIN` and the `gtp` module
loaded:

```sh
sudo modprobe gtp
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test linux_gtpu_privileged -- --ignored --nocapture'
```
