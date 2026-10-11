# Local kernel lifecycle CI job

`Privileged local kernel lifecycle` runs independently in `ci.yml`, with a
45-minute limit. The existing `Rust workspace` aggregate requires this job,
including its preflight, qualification, cleanup verification and artifact
upload. Failure, cancellation or a skipped job fails that aggregate. Both CI
and the GTP-U workflow run on every pull request, push to main and manual run;
there is no path filter. The existing privileged SCTP lane uses the same
aggregate. No new branch-protection context is needed.

The `privileged-gtpu` job, including its name `Privileged Linux GTP-U`, steps,
runner and 30-minute limit, is identical to SDK main `10e2b75ba`. The pinned
EL9 lifecycle build, complete guest manifest run and evidence upload stay in
the GTP-U workflow's `el9-514-classifier-load` job.

## Mapping

| Previous owner and work | Owner after the split |
| --- | --- |
| GTP-U host job: checkout, stable Rust and build cache | Repeated on the lifecycle job's own runner; its stable cache key is `opc-local-kernel-lifecycle`, pointing at `target/local-kernel-lifecycle` |
| GTP-U host job: kernel tooling and support preflight | Lifecycle job installs its own tools, checks GTP, WireGuard, VRF, interface stacking, private bpffs, tc and XFRM support, and checks libseccomp availability |
| GTP-U host job: `Qualify exact local kernel lifecycle` | `rust-local-kernel-lifecycle`, with the same command, manifest, features, build profile, per-case timeout, skip rejection and BPF ID restrictions |
| GTP-U host job: `Upload local kernel lifecycle evidence` | Lifecycle job, still under `always()`, with the original evidence plus cleanup snapshots; reruns overwrite the artifact |
| All existing GTP-U host tests and assertions | Original `privileged-gtpu` job, unchanged from main |
| EL9 lifecycle bundle build, guest run and evidence | Original `el9-514-classifier-load` job, unchanged from the lifecycle implementation |
| Lifecycle runner cleanup | Explicit `always()` verification after qualification, against the snapshot taken after module setup and before private namespace probes |
| Required merge result for the host lifecycle qualification | Existing `Rust workspace` aggregate, through `needs: rust-local-kernel-lifecycle` |

The complete 31-case manifest remains in
[`local-kernel-lifecycle-cases.json`](local-kernel-lifecycle-cases.json). All
four crates' exact cases run once on the host and once in the existing EL9
qualification. No case moved out of either kernel qualification, and neither
selection uses a filter. New manifest entries are included automatically.

Each native case already uses a fresh network namespace and private bpffs
mount. The new job records network/mount namespace IDs, named namespaces,
host-visible bpffs entries/mounts and interfaces after module setup and before
the private namespace probes. GRE is loaded before that snapshot because its
module setup creates kernel-owned fallback interfaces in the host namespace.
Its final check rejects surviving new namespaces and any change to the
host-visible state. Existing unrelated namespaces may disappear. The check
does not enumerate or reopen BPF program/map IDs. A missing baseline or failed
inventory command is a failure; snapshots and differences are uploaded even
after qualification or preflight failure.

## Hosted time estimate

In [run 38102132439](https://github.com/openpacketcore/openpacketcore-sdk/actions/runs/38102132439),
the GTP-U job started at 01:32:46 UTC and reached lifecycle qualification at
01:58:09, after 25m23s. That step was cancelled at 02:02:59, 4m50s later. Its
artifact shows a successful 3m45s build and three completed cases, so the
cancelled step is not a measurement of the full lifecycle suite.

Estimate **15–25 minutes cold** for the independent lifecycle job: 2–3 minutes
for setup, preflight and cache/artifact work, 9–15 minutes for a cold build of
the four test libraries and their dependencies, and 4–7 minutes for all 31
native cases. The previous GTP-U job had already compiled shared dependencies;
its partial lifecycle build cannot be used as a cold-build estimate. The
45-minute limit provides headroom without changing the original GTP-U limit.
The next hosted train must confirm the estimate and cleanup verification.
