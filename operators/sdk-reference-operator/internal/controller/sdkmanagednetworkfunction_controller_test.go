package controller

import (
	"context"
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	apiv1beta1 "openpacketcore.io/sdk-reference-operator/api/v1beta1"
	"openpacketcore.io/sdk-reference-operator/internal/sdkbridge"
	"openpacketcore.io/sdk-reference-operator/internal/testutil"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
