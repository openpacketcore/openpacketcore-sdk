<!-- SPDX-License-Identifier: Apache-2.0 -->
# ESP dummy transmission on an existing Linux SA

The SDK's `EspTfcDummySender` sends zero-filled protocol-59 packets through a
mandatory per-socket ESP policy. Stock Linux transport mode preserves 59 in
the encrypted ESP trailer. Stock tunnel mode changes it to 4 or 41, which
encapsulates an ordinary inner packet. `linux.patch` supplies the missing
tunnel capability while retaining the SA's existing sequence allocator,
crypto implementation, expiry checks and packet accounting.

This is a local kernel patch with a provisional ABI, not an upstream feature.
It must be built into the deployment kernel to enable tunnel dummies. The
SDK detects its version before opening the raw socket and refuses unsupported
kernels. The patch does not install a second SA, change a live SA's mode,
reserve counters through netlink, export keys, or implement userspace ESP.
The patch is GPL-2.0-only. The patched source files retain their existing
Linux SPDX identifiers, including GPL-2.0-or-later in `esp6.c` and
GPL-2.0 WITH Linux-syscall-note in the UAPI header. The qualification scripts
and this documentation are Apache-2.0. The patch is not a Cargo dependency;
no workspace dependency-license exception is needed.

## Supported profile and lifetime

The sender requires CAP_NET_RAW and CAP_NET_ADMIN in its selected namespace.
Its required template fixes the ESP SPI, source/destination and request ID.
Lookup uses mark zero and interface ID zero; the caller must keep that tuple
unique, including overlapping mark masks. The SA selector must admit protocol
59 and the selected inner endpoints. Both IP families, software transport and
tunnel modes, and ESP-in-UDP are qualified. Scoped IPv6 endpoints, hardware
offload, stacked transforms and GSO are outside this profile.
Opening reads the selected SA metadata with GETSA and rejects hardware offload
in both modes. The tunnel patch also enforces its transform restrictions at
send time. The SDK zeroizes the metadata buffer after the check.

The matrix covers matching inner and outer address families. Mixed-family
tunnels accepted by the API have not been qualified. Do not install NAT rules
in the sender namespace that rewrite protocol-59 flows: `nf_xfrm_me_harder`
can reroute them outside the per-socket policy. ESP-in-UDP qualification does
not qualify such local NAT rewriting.

`send(n)` supplies 1–65,495 zero filler bytes, excluding IP/ESP overhead and
configured TFC padding. The native path-MTU and SA limits still apply, so the
whole range is not guaranteed to fit. The tunnel dummy body contains the
native inner IP header and filler; RFC4303 permits arbitrary dummy content.
The encrypted ESP Next Header is 59, so the receiver discards the body instead
of delivering the inner packet. Ordinary traffic keeps its normal Next Header.

Opening installs only a private socket policy. Closing releases it; the SA
and global SPD remain caller-owned. Stop this producer under the same egress
fence as other traffic before counter recovery, relocation or SA replacement.
Recreate it against the new SA. The socket is not durable installation or SA
incarnation authority. Packet timing, rates, negotiation and scheduling belong
to the caller. Existing SDK recovery and key-custody rules continue to apply.

## Provisional OPCTFC01 ABI

`XFRM_MSG_GETSADINFO` returns SAD attribute 3 containing exactly 12 bytes:
ASCII `OPCTFC01`, followed by a native-endian `u32` family mask (bit 0: IPv4 ESP;
bit 1: IPv6 ESP). The SDK requires the magic, version, exact size and both
needed families; a flag readback alone cannot establish support because stock
kernels accept otherwise unknown policy flags. Future upstream UAPI allocation
must be reconciled with this local patch rather than silently reusing it.

Per-socket policy flag 8 opts in. The kernel accepts it only for an outbound
allow with selector protocol 59, no port selectors, and exactly one required
ESP transport/tunnel template with nonzero SPI. Global SPD installations with
this flag are rejected. Missing SAs do not trigger a key-manager ACQUIRE.
Before output, the kernel rejects offload, multiple transforms, GSO and
non-dummy IP headers. After native mode preparation it changes only the
protocol byte that ESP copies into the encrypted trailer. Normal
`xfrm_replay_overflow`, encryption, lifetime and completion paths remain intact.
The SDK uses flag zero for stock transport mode and flag 8 for tunnel mode.
Stock transport lookup retains normal key-manager ACQUIRE behavior when an
SA is absent; callers still own installation and producer fencing.

## Reproducible qualification

The CI job pins the same upstream Linux source as the whole-roster MOBIKE
profile: commit `fd73f4a6659897191fa0d40695fe370925dd3780` (7.3.0-rc3), archive
SHA-256 `1846a6d56bda7798cdff7b743d54975f1e96cbcf89cb48d5f92b2b863cdf262f`.
The patch also compiled and passed an initial IPv4 wire experiment against
Ubuntu source 7.0.0-38.38 (7.0.14); the full CI profile targets the pinned source.
Tunnel dummies are qualified only on that pinned patched kernel. Other kernels,
including vendor kernels, require their own port and qualification; their
`xfrm_state_find` and per-CPU ACQUIRE paths can differ.

On Linux, install the build and test dependencies from the `tfc-kernel` job in
`.github/workflows/ipsec-xfrm.yml`, then run:

```sh
cargo build --locked -p opc-ipsec-xfrm --example esp_tfc_dummy
python3 ci/qualify-esp-tfc.py \
  --binary target/debug/examples/esp_tfc_dummy \
  --cache /tmp/opc-tfc-cache --output /tmp/opc-tfc-evidence
```

The script verifies the source digest, applies the patch without fuzz,
compiles a small kernel, and boots a diskless QEMU guest with no external
network or host filesystem mounts. The guest builds fresh network namespaces
for each test and requires at least two online CPUs. The x86 profile enables
ACPI and PCI for CPU enumeration and poweroff. Netfilter is enabled: the IPv6
ESP-in-UDP transport reinjection
path differs when it is compiled out. `--prepare-only` exports the same
kernel/initramfs for a separate native virtualization host; it does not claim
a runtime result. `build.json` records source, patch, compiler, configuration,
binary, kernel and initramfs identities.

The 36-case matrix exercises IPv4/IPv6 and transport/tunnel with AES-GCM and
AES-CBC/HMAC-SHA256, TFC padding, UDP encapsulation, ESN rollover, non-ESN
exhaustion, hard lifetime expiry, SA deletion and missing SAs. Concurrent tests
mix four dummy-sender threads with ordinary traffic on one SA. Twelve malformed
socket-policy shapes and a global-SPD attempt are rejected. A listening
key-manager socket proves that missing tunnel SAs generate no ACQUIRE. The
receiver requires ordinary application delivery, no dummy delivery, no
plaintext protocol-59 escape, no ICMP error
response and no capture drops. Linux counts deliberate dummy discards in its
`XfrmInStateProtoError` statistic; this is not a claim of zero internal counters.

`verify-wire.py` independently authenticates and decrypts every captured packet
using Python/OpenSSL, checks sequence/IV uniqueness and rollover, exact Next
Headers, payloads, padding and IP/UDP framing, and rejects a modified tag for
every packet. Its primitives first pass published GCM, CBC and HMAC known-answer
checks. CI also runs all 18 transport cases on the stock host kernel and proves
that both tunnel families reject the absent capability.

Capture format version 1 records the configured TFC target and path MTU.
Every tunnel packet, including ordinary application traffic, must have a
decrypted body at least 256 octets long, capped by the pinned Linux
`xfrm_state_mtu` calculation. The verifier rejects missing or unknown capture
versions and its regression authenticates deliberately unpadded packets to
prove that zero-length padding cannot satisfy the length check.

Normative and reference material: [RFC4303 §2.6](https://www.rfc-editor.org/rfc/rfc4303.html#section-2.6),
[NIST SP800-38A](https://doi.org/10.6028/NIST.SP.800-38A),
[NIST SP800-38D](https://doi.org/10.6028/NIST.SP.800-38D), and
[RFC4231](https://www.rfc-editor.org/rfc/rfc4231.html).
The GCM known-answer vector is test case 2 of the
[archived original GCM specification](https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf).
