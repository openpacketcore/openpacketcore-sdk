# Building a CNF Operator with the OpenPacketCore SDK

This guide walks downstream teams through building a Kubernetes operator for a
3GPP network function (UPF, SMF, AMF, …) using the OpenPacketCore SDK. It is
intended for teams who already have a CNF container and need to wrap it with
lifecycle management, policy admission, and observability.

---

## 1. Architecture Recap

The OpenPacketCore SDK follows a **Rust policy / Go orchestration** split:

- **Rust** (`operator-lifecycle-cli`) encodes the hard safety rules:
  contract-version enforcement, preflight validation, config-apply decisions,
  rollback logic, and redaction-safe status reporting.
- **Go** (`operator-sdk-go` + your operator) handles Kubernetes mechanics:
  reconciliation, conditions, finalizers, workload synthesis, runtime-gate and
  rollout helper evaluation, Multus/SR-IOV attachment rendering, metrics, and
  events. The packet-core helper additions are experimental mechanism helpers:
  your product operator still owns CRDs, Helm/RBAC, XFRM privileges, network
  attachment definitions, readiness policy, and carrier acceptance.

This split is deliberate: Rust gives us memory safety and auditable policy
execution, while Go gives us native Kubernetes client ergonomics.

For the full rationale see [ADR 0007](adr/0007-operator-lifecycle-rust-policy-core.md).

---

## 2. Scaffold a New Operator

You will need:

- Go 1.26+
- kubebuilder / controller-runtime
- The `operator-sdk-go` module

### 2.1 Create the module

```bash
mkdir my-nf-operator && cd my-nf-operator
go mod init openpacketcore.io/my-nf-operator
go get openpacketcore.io/operator-sdk-go@sometag
```

### 2.2 Minimal Main Entrypoint

Your main entrypoint (see `operators/sdk-reference-operator/cmd/manager/main.go` for a full example) wires controller-runtime with the SDK packages:

```go
package main

import (
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"openpacketcore.io/operator-sdk-go/bridge"
	"openpacketcore.io/operator-sdk-go/conditions"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: ":8081",
		MetricsBindAddress:     ":8080",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Wire your reconciler here …

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
```

---

## 3. Defining Your NF CRD

Define a CRD that embeds the same concepts as
`SdkManagedNetworkFunction`. The exact schema is up to your product team, but
these fields are required for SDK integration:

- `runtimeMode` (`production` | `dev` | `lab` | `conformance` | `perf`)
- `version` — the NF software version being deployed
- `resourceProfile` — CPU, memory, hugepages, SR-IOV, BPF artifacts
- `configBackend` / `sessionBackend` — determines HA posture
- `adminAuthRef` — secret holding the admin auth token for the NF

See the reference CRD for the complete schema:
[operators/sdk-reference-operator/api/v1beta1/sdkmanagednetworkfunction_types.go](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/operators/sdk-reference-operator/api/v1beta1/sdkmanagednetworkfunction_types.go)

---

## 4. Wiring SDK Packages

### 4.1 Bridge — Policy Handshake

The `bridge.Client` talks to the Rust `operator-lifecycle-cli`. It performs a
contract-version handshake on first use and returns typed errors so you can
distinguish terminal mismatches from transient failures.

Excerpt from the reference controller:
[operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go)

```go
client, err := bridge.NewClient("/usr/local/bin/operator-lifecycle-cli")
if err != nil {
    return err
}
```

### 4.2 Conditions — RFC 009 Lifecycle Semantics

`conditions.ConditionManager` enforces monotonic `observedGeneration` and
`LastTransitionTime` rules. Use it instead of hand-rolling condition updates.

Excerpt from the reference controller:
[operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go)

```go
cm := conditions.NewConditionManager(crd.Status.ObservedGeneration)
cm.LoadConditions(crd.Status.Conditions)
_ = cm.Set(conditions.Ready, metav1.ConditionTrue, "ConfigApplied", "…", crd.Generation)
cm.SyncToStatus(
    func(c []metav1.Condition) { crd.Status.Conditions = c },
    func(g int64) { crd.Status.ObservedGeneration = g },
)
```

### 4.3 Drain — Graceful Shutdown

Add the `lifecycle.openpacketcore.io/drain` finalizer. On deletion, call
`drain.Orchestrator.Start()` and poll `Status()` before removing the finalizer.

Excerpt from the reference controller:
[operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go)

```go
const drainFinalizer = "lifecycle.openpacketcore.io/drain"

// In Reconcile:
if !crd.DeletionTimestamp.IsZero() {
    if r.Drainer != nil && containsString(crd.Finalizers, drainFinalizer) {
        if err := r.runDrain(ctx, crd, cm); err != nil {
            logger.Error(err, "Drain during deletion failed")
        }
    }
    crd.Finalizers = removeString(crd.Finalizers, drainFinalizer)
    if err := r.Client.Update(ctx, crd); err != nil {
        return ctrl.Result{}, err
    }
    return ctrl.Result{}, nil
}
```

### 4.4 Workload — Manifest Synthesis

`workload.RenderDeployment` turns your CR into a Kubernetes `Deployment` with
correct resources, capabilities, hugepage volumes, extra UDP/SCTP/TCP ports,
Multus/SR-IOV annotations, and probes.

Excerpt from the reference controller:
[operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go)

```go
wSpec := workload.NetworkFunctionSpec{
    Name:        crd.Name,
    Namespace:   crd.Namespace,
    Version:     crd.Spec.Version,
    RuntimeMode: crd.Spec.RuntimeMode,
}
if crd.Spec.ResourceProfile != nil {
    // map profile fields …
}
opts := workload.DefaultRenderOptions()
dep, err := workload.RenderDeployment(wSpec, opts)
```

### 4.5 Metrics — RFC 009 Instrumentation

Import `openpacketcore.io/operator-sdk-go/opmetrics` and instrument your
reconciler. All collectors are pre-registered on controller-runtime's registry.

Excerpt from the reference controller:
[operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go)

```go
start := time.Now()
outcome := "success"
defer func() {
    opmetrics.ReconcileDuration.WithLabelValues("SdkManagedNetworkFunction", outcome).Observe(time.Since(start).Seconds())
    opmetrics.ReconcileTotal.WithLabelValues("SdkManagedNetworkFunction", outcome).Inc()
}()
```

---

### 4.6 Runtime Gates, CNI, and Rollout Helpers

The `conditions`, `gates`, `cni`, and `rollout` packages contain generic helper
surfaces for named runtime gates, Deployment/Pod endpoint lineage, Multus
network annotations, SR-IOV resource aggregation, and RFC 009 rollout-strategy
checks. These helpers are experimental for packet-core workloads: pass
product-specific CRD fields through your own adapter layer instead of adding
product policy to `operator-sdk-go`.

---

## 5. Packaging with Helm

Use the reference Helm chart as a template:
[operators/helm/sdk-reference-operator/](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/operators/helm/sdk-reference-operator/)

Key files to copy and adapt:

- `operators/helm/sdk-reference-operator/Chart.yaml` — update name, version, appVersion
- `operators/helm/sdk-reference-operator/values.yaml` — your image repo, resource defaults, feature flags
- `operators/helm/sdk-reference-operator/templates/deployment.yaml` — operator container spec
- `operators/helm/sdk-reference-operator/templates/rbac.yaml` — ClusterRole + Role for leader election
- `operators/helm/sdk-reference-operator/templates/webhook.yaml` — ValidatingWebhookConfiguration
- `operators/helm/sdk-reference-operator/templates/certificate.yaml` — cert-manager Certificate (optional)
- `operators/helm/sdk-reference-operator/crds/` — copy your CRDs from `config/crd/bases/`

Run the acceptance checks locally before committing:

```bash
helm lint operators/helm/my-nf-operator/
helm template my-nf operators/helm/my-nf-operator/ | kubectl apply --dry-run=client -f -
helm template my-nf operators/helm/my-nf-operator/ \
  --set webhook.certMode=manual --set webhook.secretName=my-secret \
  | kubectl apply --dry-run=client -f -
```

---

## 6. What the SDK Does NOT Do

The SDK is intentionally narrow. You must bring your own:

- **Traffic-shift implementation and product rollout policy** — the Go helpers
  can evaluate RFC 009 strategy choices and render conservative Deployment
  strategies, but your operator owns Service routing, canary percentages,
  approvals, and product safety thresholds.
- **Multi-cluster federation** — the reconciler is single-cluster.
- **Backup / restore** — etcd-level snapshots are outside scope.
- **NF-specific protocol codecs** — PFCP, NAS-5GS, GTP-U, the experimental
  Diameter base/application dictionaries, GTPv2-C S2b subset, and IKEv2
  header/payload-chain scaffold are separate crates (`opc-proto-pfcp`,
  `opc-proto-nas`, `opc-proto-gtpu`, `opc-proto-diameter`,
  `opc-proto-gtpv2c`, `opc-proto-ikev2`), not `opc-sdk` default facade exports.
- **Custom resource conversion webhooks** — if you version your CRD, you must
  write and deploy conversion logic yourself.

For the current SDK gap register and accepted boundaries, see
[`docs/implementation-status.md`](implementation-status.md). EPC and
untrusted-access additions are intentionally mechanism-only per
[ADR 0018](adr/0018-epc-untrusted-access-sdk-boundary.md); downstream product
operators own their own CRDs, Helm/RBAC policy, network attachments, XFRM/IPsec
privileges, readiness thresholds, traffic-shift rules, and carrier-acceptance
evidence.

---

## 7. Testing Strategy

### 7.1 Controller Tests (envtest + fake client)

Use controller-runtime's `envtest` or `fake.NewClientBuilder()` to test
reconciliation without a real cluster:

- Verify conditions transition monotonically.
- Verify finalizers are added and removed.
- Verify Deployment spec fields match the CR resource profile.
- Verify metrics counters increment.
- Verify events are emitted via `record.NewFakeRecorder()`.

Example from the reference operator:
[operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller_test.go](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller_test.go)

### 7.2 NF Side Tests (opc-testbed)

For the Rust policy side, use `opc-testbed` to spin up a temporary runtime and
exercise the lifecycle CLI directly:

```rust
use opc_testbed::TestRuntime;

#[test]
fn test_preflight_rejects_missing_bpf() {
    let rt = TestRuntime::new();
    // …
}
```

See the existing test suites in:
[crates/operator-lifecycle-cli/tests/integration_tests.rs](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/crates/operator-lifecycle-cli/tests/integration_tests.rs)

---

## Quick Reference — File Index

| Purpose | Reference File |
|---|---|
| CRD types | `operators/sdk-reference-operator/api/v1beta1/sdkmanagednetworkfunction_types.go` |
| Reconciler | `operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller.go` |
| Controller tests | `operators/sdk-reference-operator/internal/controller/sdkmanagednetworkfunction_controller_test.go` |
| Bridge client | `operators/operator-sdk-go/bridge/client.go` |
| Conditions | `operators/operator-sdk-go/conditions/conditions.go` |
| Drain | `operators/operator-sdk-go/drain/drain.go` |
| Workload | `operators/operator-sdk-go/workload/workload.go` |
| Metrics | `operators/operator-sdk-go/opmetrics/opmetrics.go` |
| Helm chart | `operators/helm/sdk-reference-operator/` |
| ADR 0007 | `docs/adr/0007-operator-lifecycle-rust-policy-core.md` |
| RFC 009 | `docs/rfc/009-operator-lifecycle-upgrade.md` |
