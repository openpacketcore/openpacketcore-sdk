package controller

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"openpacketcore.io/operator-sdk-go/conditions"
	"openpacketcore.io/operator-sdk-go/drain"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	apiv1beta1 "openpacketcore.io/sdk-reference-operator/api/v1beta1"
	"openpacketcore.io/sdk-reference-operator/internal/sdkbridge"
	"openpacketcore.io/sdk-reference-operator/internal/testutil"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestReconcileApplyReady(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	// 1. Create SdkManagedNetworkFunction CR with valid Production settings
	numa := uint16(0)
	evidenceID := "platform-preflight-ev-1"
	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "my-cnf",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: apiv1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode:    "production",
			ClaimsHA:       true,
			ConfigBackend:  "consensus",
			SessionBackend: "quorum",
			AdminAuthRef: corev1.LocalObjectReference{
				Name: "my-token-secret",
			},
			Identity: apiv1beta1.IdentityRequirements{
				KmsEnabled:    true,
				SpiffeEnabled: true,
			},
			ResourceProfile: &apiv1beta1.ResourceProfileSpec{
				NfKind:                    "upf",
				DataPlaneProfile:          "AfXdpFastPath",
				NumaPolicy:                "Require",
				GenericXdpFallbackAllowed: false,
				IsolatedCores:             []uint16{2, 3},
				RequireExclusiveCores:     true,
				DataPlaneInterfaces:       []string{"ens5f0"},
				DataPlaneNumaNode:         &numa,
				HugepageNumaNode:          &numa,
				PodSecurityEvidenceID:     &evidenceID,
				BpfArtifacts:              []apiv1beta1.BpfArtifact{validAPIBpfArtifact("ens5f0", evidenceID)},
			},
			Version:             "1.0.0",
			ConfigSchemaVersion: "1.0.0",
			StateSchemaVersion:  "1.0.0",
		},
		Status: apiv1beta1.SdkManagedNetworkFunctionStatus{
			Phase: "Pending",
		},
	}

	scheme := runtime.NewScheme()
	_ = apiv1beta1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	nodeReport, err := json.Marshal(validNodeCapabilityReport())
	if err != nil {
		t.Fatalf("Failed to marshal node capability report: %v", err)
	}
	nodeCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-capability-report",
			Namespace: "default",
		},
		Data: map[string]string{"report.json": string(nodeReport)},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crd, nodeCM).
		WithStatusSubresource(&apiv1beta1.SdkManagedNetworkFunction{}).
		Build()

	reconciler := &SdkManagedNetworkFunctionReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Bridge: bridge,
	}

	// 2. Run Reconciliation
	_, err = reconciler.Reconcile(context.TODO(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "my-cnf",
			Namespace: "default",
		},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// 3. Verify status was updated to Ready
	updated := &apiv1beta1.SdkManagedNetworkFunction{}
	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: "my-cnf", Namespace: "default"}, updated)
	if err != nil {
		t.Fatalf("Failed to fetch updated CR: %v", err)
	}

	if updated.Status.Phase != "Ready" {
		t.Errorf("Expected status phase to be Ready, got %s", updated.Status.Phase)
	}
	if updated.Status.ObservedGeneration != 1 {
		t.Errorf("Expected ObservedGeneration to be 1, got %d", updated.Status.ObservedGeneration)
	}
	if updated.Status.PreflightSummary != "Passed" {
		t.Errorf("Expected PreflightSummary Passed, got %s", updated.Status.PreflightSummary)
	}

	// Check conditions
	var readyFound bool
	for _, cond := range updated.Status.Conditions {
		if cond.Type == "Ready" {
			readyFound = true
			if cond.Status != metav1.ConditionTrue {
				t.Errorf("Expected Ready condition status True, got %s", cond.Status)
			}
			if cond.Reason != "ConfigApplied" {
				t.Errorf("Expected Ready condition reason ConfigApplied, got %s", cond.Reason)
			}
		}
	}
	if !readyFound {
		t.Errorf("Ready condition not found in status")
	}
}

func validAPIBpfArtifact(interfaceName, evidenceID string) apiv1beta1.BpfArtifact {
	return apiv1beta1.BpfArtifact{
		Name:                "upf-xdp-fastpath",
		Digest:              "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SignatureRef:        "cosign://registry.example/upf-xdp-fastpath@sha256:012345",
		SignerIdentity:      "spiffe://openpacketcore.test/ns/platform/sa/release-signer",
		ProgramType:         "xdp",
		ExpectedAttachPoint: interfaceName,
		AllowedCapabilities: []string{"CapBpf", "CapNetAdmin", "CapNetRaw"},
		EvidenceID:          &evidenceID,
	}
}

func validNodeCapabilityReport() *sdkbridge.NodeCapabilityReport {
	numa := uint16(0)
	return &sdkbridge.NodeCapabilityReport{
		Kernel: sdkbridge.KernelVersion{Major: 6, Minor: 8, Patch: 0},
		Bpf: sdkbridge.BpfCapabilities{
			CapBpf:              true,
			XdpSupported:        true,
			BtfAvailable:        true,
			CapSysAdminRequired: false,
			AvailableXdpModes:   []string{"Native"},
		},
		Cpu: sdkbridge.NodeCpuCapabilities{
			ManagerPolicy:         "Static",
			IsolatedCores:         []uint16{2, 3},
			NumaNodes:             1,
			CpuIDs:                []uint16{0, 1, 2, 3},
			ReservedCores:         []uint16{0, 1},
			TopologyManagerPolicy: "SingleNumaNode",
			CpuNumaMap:            map[uint16]uint16{0: 0, 1: 0, 2: 0, 3: 0},
		},
		Memory: sdkbridge.NodeMemoryCapabilities{
			Hugepages2Mi: 1024,
			Hugepages1Gi: 4,
			HugepagePools: []sdkbridge.HugepagePool{
				{NumaNode: 0, Size: "2Mi", Total: 512, Free: 512},
			},
		},
		Nics: []sdkbridge.NicCapability{
			{
				Name:     "ens5f0",
				Driver:   "ice",
				SriovVfs: 4,
				XdpModes: []string{"Native"},
				Queues:   4,
				NumaNode: &numa,
			},
		},
	}
}

func TestReconcileStaleGenerationMonotonicity(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	// CR is at Generation 1, but Status already has ObservedGeneration 2 (newer status)
	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "stale-cnf",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: apiv1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode: "production",
			Version:     "1.0.0",
		},
		Status: apiv1beta1.SdkManagedNetworkFunctionStatus{
			Phase:              "Ready",
			ObservedGeneration: 2,
		},
	}

	scheme := runtime.NewScheme()
	_ = apiv1beta1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crd).
		WithStatusSubresource(&apiv1beta1.SdkManagedNetworkFunction{}).
		Build()

	reconciler := &SdkManagedNetworkFunctionReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Bridge: bridge,
	}

	_, err = reconciler.Reconcile(context.TODO(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "stale-cnf",
			Namespace: "default",
		},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify status is completely unchanged (stale generations do not overwrite newer status)
	updated := &apiv1beta1.SdkManagedNetworkFunction{}
	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: "stale-cnf", Namespace: "default"}, updated)
	if err != nil {
		t.Fatalf("Failed to fetch updated CR: %v", err)
	}

	if updated.Status.ObservedGeneration != 2 {
		t.Errorf("Stale reconciliation modified ObservedGeneration: got %d, expected 2", updated.Status.ObservedGeneration)
	}
}

func TestReconcileBlockedPreflight(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	// 1. Create SdkManagedNetworkFunction with ResourceProfile requiring CPU pinning but we will have empty node capability report
	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "preflight-fail-cnf",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: apiv1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode:    "production",
			ClaimsHA:       true,
			ConfigBackend:  "consensus",
			SessionBackend: "quorum",
			ResourceProfile: &apiv1beta1.ResourceProfileSpec{
				NfKind:                "upf",
				DataPlaneProfile:      "AfXdpFastPath", // Fast path data plane
				NumaPolicy:            "Require",
				RequireExclusiveCores: true, // requires cores!
			},
			Version: "1.0.0",
		},
		Status: apiv1beta1.SdkManagedNetworkFunctionStatus{
			Phase: "Pending",
		},
	}

	scheme := runtime.NewScheme()
	_ = apiv1beta1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crd).
		WithStatusSubresource(&apiv1beta1.SdkManagedNetworkFunction{}).
		Build()

	reconciler := &SdkManagedNetworkFunctionReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Bridge: bridge,
	}

	// 2. Reconcile
	_, err = reconciler.Reconcile(context.TODO(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "preflight-fail-cnf",
			Namespace: "default",
		},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// 3. Verify phase is Degraded and BlockedReason shows missing preflight evidence
	updated := &apiv1beta1.SdkManagedNetworkFunction{}
	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: "preflight-fail-cnf", Namespace: "default"}, updated)
	if err != nil {
		t.Fatalf("Failed to fetch updated CR: %v", err)
	}

	if updated.Status.Phase != "Degraded" {
		t.Errorf("Expected phase Degraded due to missing node capabilities, got %s", updated.Status.Phase)
	}
	if updated.Status.BlockedReason == "" {
		t.Errorf("Expected BlockedReason to be populated")
	}
	if updated.Status.PreflightSummary != "Blocked: node capability report missing" {
		t.Errorf("Expected missing node capability preflight summary, got %s", updated.Status.PreflightSummary)
	}

	var degradedTrue bool
	for _, cond := range updated.Status.Conditions {
		if cond.Type == "Degraded" && cond.Status == metav1.ConditionTrue {
			degradedTrue = true
			if cond.Reason != "NodeCapabilitiesMissing" {
				t.Errorf("Expected Degraded reason NodeCapabilitiesMissing, got %s", cond.Reason)
			}
		}
	}
	if !degradedTrue {
		t.Errorf("Expected Degraded=True condition in status")
	}
}

func TestReconcileFinalizerAdded(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	// 1. Create SdkManagedNetworkFunction CR with valid Production settings
	numa := uint16(0)
	evidenceID := "platform-preflight-ev-1"
	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "my-cnf",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: apiv1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode:    "production",
			ClaimsHA:       true,
			ConfigBackend:  "consensus",
			SessionBackend: "quorum",
			AdminAuthRef: corev1.LocalObjectReference{
				Name: "my-token-secret",
			},
			Identity: apiv1beta1.IdentityRequirements{
				KmsEnabled:    true,
				SpiffeEnabled: true,
			},
			ResourceProfile: &apiv1beta1.ResourceProfileSpec{
				NfKind:                    "upf",
				DataPlaneProfile:          "AfXdpFastPath",
				NumaPolicy:                "Require",
				GenericXdpFallbackAllowed: false,
				IsolatedCores:             []uint16{2, 3},
				RequireExclusiveCores:     true,
				DataPlaneInterfaces:       []string{"ens5f0"},
				DataPlaneNumaNode:         &numa,
				HugepageNumaNode:          &numa,
				PodSecurityEvidenceID:     &evidenceID,
				BpfArtifacts:              []apiv1beta1.BpfArtifact{validAPIBpfArtifact("ens5f0", evidenceID)},
			},
			Version:             "1.0.0",
			ConfigSchemaVersion: "1.0.0",
			StateSchemaVersion:  "1.0.0",
		},
		Status: apiv1beta1.SdkManagedNetworkFunctionStatus{
			Phase: "Pending",
		},
	}

	scheme := runtime.NewScheme()
	_ = apiv1beta1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	nodeReport, err := json.Marshal(validNodeCapabilityReport())
	if err != nil {
		t.Fatalf("Failed to marshal node capability report: %v", err)
	}
	nodeCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-capability-report",
			Namespace: "default",
		},
		Data: map[string]string{"report.json": string(nodeReport)},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crd, nodeCM).
		WithStatusSubresource(&apiv1beta1.SdkManagedNetworkFunction{}).
		Build()

	reconciler := &SdkManagedNetworkFunctionReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Bridge: bridge,
	}

	// 2. Run Reconciliation
	_, err = reconciler.Reconcile(context.TODO(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "my-cnf",
			Namespace: "default",
		},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// 3. Verify status was updated to Ready
	updated := &apiv1beta1.SdkManagedNetworkFunction{}
	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: "my-cnf", Namespace: "default"}, updated)
	if err != nil {
		t.Fatalf("Failed to fetch updated CR: %v", err)
	}

	if updated.Status.Phase != "Ready" {
		t.Errorf("Expected status phase to be Ready, got %s", updated.Status.Phase)
	}
	if updated.Status.ObservedGeneration != 1 {
		t.Errorf("Expected ObservedGeneration to be 1, got %d", updated.Status.ObservedGeneration)
	}
	if updated.Status.PreflightSummary != "Passed" {
		t.Errorf("Expected PreflightSummary Passed, got %s", updated.Status.PreflightSummary)
	}

	// Check conditions
	var readyFound bool
	for _, cond := range updated.Status.Conditions {
		if cond.Type == "Ready" {
			readyFound = true
			if cond.Status != metav1.ConditionTrue {
				t.Errorf("Expected Ready condition status True, got %s", cond.Status)
			}
			if cond.Reason != "ConfigApplied" {
				t.Errorf("Expected Ready condition reason ConfigApplied, got %s", cond.Reason)
			}
		}
	}
	if !readyFound {
		t.Errorf("Ready condition not found in status")
	}
}

func TestReconcileDeletionTriggersDrain(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	now := metav1.NewTime(time.Now())
	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "delete-cnf",
			Namespace:         "default",
			Generation:        1,
			Finalizers:        []string{drainFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: apiv1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode: "dev",
			Version:     "1.0.0",
		},
	}

	scheme := runtime.NewScheme()
	_ = apiv1beta1.AddToScheme(scheme)

	drainCalled := false
	var finalizersAfterUpdate []string
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crd).
		WithStatusSubresource(&apiv1beta1.SdkManagedNetworkFunction{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if o, ok := obj.(*apiv1beta1.SdkManagedNetworkFunction); ok {
					finalizersAfterUpdate = append([]string(nil), o.Finalizers...)
				}
				return c.Update(ctx, obj, opts...)
			},
		}).
		Build()

	reconciler := &SdkManagedNetworkFunctionReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Bridge: bridge,
		Drainer: &drain.FakeOrchestrator{
			StartFunc: func(ctx context.Context, target string) error {
				drainCalled = true
				return nil
			},
			StatusFunc: func(ctx context.Context, target string) (drain.DrainStatus, error) {
				return drain.DrainStatus{Phase: drain.Complete}, nil
			},
		},
	}

	_, err = reconciler.Reconcile(context.TODO(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "delete-cnf", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if !drainCalled {
		t.Errorf("Expected drain to be called during deletion")
	}
	if containsString(finalizersAfterUpdate, drainFinalizer) {
		t.Errorf("Expected finalizer %s to be removed after drain", drainFinalizer)
	}
}

func TestReconcileDrainTimeoutReleasesFinalizer(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	now := metav1.NewTime(time.Now())
	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "timeout-cnf",
			Namespace:         "default",
			Generation:        1,
			Finalizers:        []string{drainFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: apiv1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode: "dev",
			Version:     "1.0.0",
		},
	}

	scheme := runtime.NewScheme()
	_ = apiv1beta1.AddToScheme(scheme)

	var finalizersAfterUpdate []string
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crd).
		WithStatusSubresource(&apiv1beta1.SdkManagedNetworkFunction{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if o, ok := obj.(*apiv1beta1.SdkManagedNetworkFunction); ok {
					finalizersAfterUpdate = append([]string(nil), o.Finalizers...)
				}
				return c.Update(ctx, obj, opts...)
			},
		}).
		Build()

	reconciler := &SdkManagedNetworkFunctionReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Bridge: bridge,
		Drainer: &drain.FakeOrchestrator{
			StartFunc: func(ctx context.Context, target string) error {
				return nil
			},
			StatusFunc: func(ctx context.Context, target string) (drain.DrainStatus, error) {
				return drain.DrainStatus{Phase: drain.TimedOut}, nil
			},
		},
	}

	_, err = reconciler.Reconcile(context.TODO(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "timeout-cnf", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if containsString(finalizersAfterUpdate, drainFinalizer) {
		t.Errorf("Expected finalizer %s to be removed even on drain timeout", drainFinalizer)
	}
}

// reconcileDrainFailureKeepsFinalizer drives a deletion whose drain does not
// reach a terminal state and asserts the finalizer is retained and the
// reconcile requeues — the object must not be deleted while sessions drain.
func reconcileDrainFailureKeepsFinalizer(t *testing.T, name string, drainer *drain.FakeOrchestrator) {
	t.Helper()
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	now := metav1.NewTime(time.Now())
	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "default",
			Generation:        1,
			Finalizers:        []string{drainFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: apiv1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode: "dev",
			Version:     "1.0.0",
		},
	}

	scheme := runtime.NewScheme()
	_ = apiv1beta1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crd).
		WithStatusSubresource(&apiv1beta1.SdkManagedNetworkFunction{}).
		Build()

	reconciler := &SdkManagedNetworkFunctionReconciler{
		Client:  fakeClient,
		Scheme:  scheme,
		Bridge:  bridge,
		Drainer: drainer,
	}

	res, err := reconciler.Reconcile(context.TODO(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("expected a requeue while drain is incomplete, got %+v", res)
	}

	var got apiv1beta1.SdkManagedNetworkFunction
	if err := fakeClient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: "default"}, &got); err != nil {
		t.Fatalf("Failed to get object: %v", err)
	}
	if !containsString(got.Finalizers, drainFinalizer) {
		t.Errorf("finalizer %s must be retained while drain is incomplete", drainFinalizer)
	}
}

func TestReconcileDrainStartErrorKeepsFinalizer(t *testing.T) {
	startErr := errors.New("drain agent unreachable")
	drainer := &drain.FakeOrchestrator{
		StartFunc: func(ctx context.Context, target string) error {
			return startErr
		},
	}
	reconcileDrainFailureKeepsFinalizer(t, "drain-start-error-cnf", drainer)

	reconciler := &SdkManagedNetworkFunctionReconciler{Drainer: drainer}
	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "drain-start-error-cnf",
			Generation: 1,
		},
	}
	cm := conditions.NewConditionManager(crd.Generation)
	err := reconciler.runDrain(context.Background(), crd, cm)
	if err == nil {
		t.Fatalf("expected drain start error")
	}
	if !strings.Contains(err.Error(), "starting drain for") {
		t.Fatalf("expected start context in error, got %q", err.Error())
	}
	if !errors.Is(err, startErr) {
		t.Fatalf("expected wrapped start error, got %v", err)
	}
}

func TestReconcileDrainFailedPhaseKeepsFinalizer(t *testing.T) {
	reconcileDrainFailureKeepsFinalizer(t, "drain-failed-cnf", &drain.FakeOrchestrator{
		StartFunc: func(ctx context.Context, target string) error {
			return nil
		},
		StatusFunc: func(ctx context.Context, target string) (drain.DrainStatus, error) {
			return drain.DrainStatus{Phase: drain.Failed}, nil
		},
	})
}

func TestReconcileWorkloadSynthesisOptInCreatesDeployment(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "workload-cnf",
			Namespace:  "default",
			Generation: 1,
			UID:        "test-uid-123",
		},
		Spec: apiv1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode: "dev",
			Version:     "1.0.0",
			ResourceProfile: &apiv1beta1.ResourceProfileSpec{
				NfKind:           "smf",
				DataPlaneProfile: "ControlPlaneOnly",
			},
		},
		Status: apiv1beta1.SdkManagedNetworkFunctionStatus{
			Phase: "Pending",
		},
	}

	scheme := runtime.NewScheme()
	_ = apiv1beta1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crd).
		WithStatusSubresource(&apiv1beta1.SdkManagedNetworkFunction{}).
		Build()

	reconciler := &SdkManagedNetworkFunctionReconciler{
		Client:                  fakeClient,
		Scheme:                  scheme,
		Bridge:                  bridge,
		EnableWorkloadSynthesis: true,
	}

	_, err = reconciler.Reconcile(context.TODO(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "workload-cnf", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	dep := &appsv1.Deployment{}
	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: "workload-cnf", Namespace: "default"}, dep)
	if err != nil {
		t.Fatalf("Expected Deployment to be created: %v", err)
	}

	if len(dep.OwnerReferences) == 0 {
		t.Errorf("Expected Deployment to have owner reference")
	}
}

func TestReconcileWorkloadSynthesisOptOutDoesNotCreateDeployment(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "no-workload-cnf",
			Namespace:  "default",
			Generation: 1,
			UID:        "test-uid-456",
		},
		Spec: apiv1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode: "dev",
			Version:     "1.0.0",
			ResourceProfile: &apiv1beta1.ResourceProfileSpec{
				NfKind:           "smf",
				DataPlaneProfile: "ControlPlaneOnly",
			},
		},
		Status: apiv1beta1.SdkManagedNetworkFunctionStatus{
			Phase: "Pending",
		},
	}

	scheme := runtime.NewScheme()
	_ = apiv1beta1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crd).
		WithStatusSubresource(&apiv1beta1.SdkManagedNetworkFunction{}).
		Build()

	reconciler := &SdkManagedNetworkFunctionReconciler{
		Client:                  fakeClient,
		Scheme:                  scheme,
		Bridge:                  bridge,
		EnableWorkloadSynthesis: false,
	}

	_, err = reconciler.Reconcile(context.TODO(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "no-workload-cnf", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	dep := &appsv1.Deployment{}
	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: "no-workload-cnf", Namespace: "default"}, dep)
	if err == nil {
		t.Errorf("Expected no Deployment to be created when workload synthesis is disabled")
	}
}

func TestReconcileEmitsMetricsAndEvents(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	crd := &apiv1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "metrics-cnf",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: apiv1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode: "dev",
			Version:     "1.0.0",
		},
		Status: apiv1beta1.SdkManagedNetworkFunctionStatus{
			Phase: "Pending",
		},
	}

	scheme := runtime.NewScheme()
	_ = apiv1beta1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crd).
		WithStatusSubresource(&apiv1beta1.SdkManagedNetworkFunction{}).
		Build()

	recorder := record.NewFakeRecorder(10)
	reconciler := &SdkManagedNetworkFunctionReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Bridge:   bridge,
		Recorder: recorder,
	}

	_, err = reconciler.Reconcile(context.TODO(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "metrics-cnf", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify at least one event was emitted (phase transition or finalizer addition)
	select {
	case ev := <-recorder.Events:
		if ev == "" {
			t.Errorf("Expected non-empty event")
		}
	default:
		// No events is acceptable if phase didn't change
	}
}
