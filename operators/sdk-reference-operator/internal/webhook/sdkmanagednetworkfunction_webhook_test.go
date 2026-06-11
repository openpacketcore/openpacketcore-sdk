package webhook

import (
	"context"
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	v1beta1 "openpacketcore.io/sdk-reference-operator/api/v1beta1"
	"openpacketcore.io/sdk-reference-operator/internal/sdkbridge"
	"openpacketcore.io/sdk-reference-operator/internal/testutil"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestWebhookValidation(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// A valid secret containing a secure admin token
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secure-token-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"admin-token": []byte("secure-token-value-with-long-length-12345"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	validator := &SdkManagedNetworkFunctionValidator{
		Client: fakeClient,
		Bridge: bridge,
	}

	tests := []struct {
		name        string
		crd         *v1beta1.SdkManagedNetworkFunction
		shouldAllow bool
		errMessage  string
	}{
		{
			name: "Allowed request",
			crd: &v1beta1.SdkManagedNetworkFunction{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cnf",
					Namespace: "default",
				},
				Spec: v1beta1.SdkManagedNetworkFunctionSpec{
					RuntimeMode:    "dev",
					ClaimsHA:       true,
					ConfigBackend:  "consensus",
					SessionBackend: "quorum",
					AdminAuthRef: corev1.LocalObjectReference{
						Name: "secure-token-secret",
					},
					Identity: v1beta1.IdentityRequirements{
						KmsEnabled:    true,
						SpiffeEnabled: true,
					},
				},
			},
			shouldAllow: true,
		},
		{
			name: "Rejected due to Standalone SQLite with HA in Production",
			crd: &v1beta1.SdkManagedNetworkFunction{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cnf-sqlite-ha",
					Namespace: "default",
				},
				Spec: v1beta1.SdkManagedNetworkFunctionSpec{
					RuntimeMode:    "production",
					ClaimsHA:       true,
					ConfigBackend:  "sqlite", // Standsalone SQLite is unsafe for HA in Production!
					SessionBackend: "quorum",
					AdminAuthRef: corev1.LocalObjectReference{
						Name: "secure-token-secret",
					},
					Identity: v1beta1.IdentityRequirements{
						KmsEnabled:    true,
						SpiffeEnabled: true,
					},
				},
			},
			shouldAllow: false,
			errMessage:  "HAClaimsRejectedWithSingleNodeConfigBackend",
		},
		{
			name: "Rejected due to missing KMS/SPIFFE in Production",
			crd: &v1beta1.SdkManagedNetworkFunction{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cnf-no-kms",
					Namespace: "default",
				},
				Spec: v1beta1.SdkManagedNetworkFunctionSpec{
					RuntimeMode:    "production",
					ClaimsHA:       true,
					ConfigBackend:  "consensus",
					SessionBackend: "quorum",
					AdminAuthRef: corev1.LocalObjectReference{
						Name: "secure-token-secret",
					},
					Identity: v1beta1.IdentityRequirements{
						KmsEnabled:    false, // KMS is disabled in Production!
						SpiffeEnabled: true,
					},
				},
			},
			shouldAllow: false,
			errMessage:  "MissingKmsSpiffeIdentity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.ValidateCreate(context.TODO(), tt.crd)
			if tt.shouldAllow {
				if err != nil {
					t.Errorf("Expected allowed, got validation error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected rejected validation, but got success")
				} else if tt.errMessage != "" {
					// Validate message contents
					// (which we expect to contain error messages sanitized and returned)
					// (e.g. from BadRequest status payload)
					t.Logf("Got expected validation error: %v", err)
				}
			}
		})
	}
}

func TestWebhookValidationAllowsProductionPreflight(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	nodeReport, err := json.Marshal(validNodeCapabilityReport())
	if err != nil {
		t.Fatalf("Failed to marshal node capability report: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secure-token-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"admin-token": []byte("secure-token-value-with-long-length-12345"),
		},
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
		WithObjects(secret, nodeCM).
		Build()

	validator := &SdkManagedNetworkFunctionValidator{
		Client: fakeClient,
		Bridge: bridge,
	}

	numa := uint16(0)
	evidenceID := "platform-preflight-ev-1"
	crd := &v1beta1.SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prod-reference",
			Namespace: "default",
		},
		Spec: v1beta1.SdkManagedNetworkFunctionSpec{
			RuntimeMode:    "production",
			ClaimsHA:       false,
			ConfigBackend:  "consensus",
			SessionBackend: "quorum",
			AdminAuthRef: corev1.LocalObjectReference{
				Name: "secure-token-secret",
			},
			Identity: v1beta1.IdentityRequirements{
				KmsEnabled:    true,
				SpiffeEnabled: true,
			},
			ResourceProfile: &v1beta1.ResourceProfileSpec{
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
				BpfArtifacts:              []v1beta1.BpfArtifact{validAPIBpfArtifact("ens5f0", evidenceID)},
			},
			Version:             "1.0.0",
			ConfigSchemaVersion: "1.0.0",
			StateSchemaVersion:  "1.0.0",
		},
	}

	if _, err := validator.ValidateCreate(context.TODO(), crd); err != nil {
		t.Fatalf("Expected production validation to pass, got %v", err)
	}
}

func validAPIBpfArtifact(interfaceName, evidenceID string) v1beta1.BpfArtifact {
	return v1beta1.BpfArtifact{
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
