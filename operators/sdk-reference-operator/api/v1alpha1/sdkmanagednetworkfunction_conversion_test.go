package v1alpha1

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"openpacketcore.io/sdk-reference-operator/api/v1beta1"
)

func TestConversionRoundTrip(t *testing.T) {
	hugepageNuma := uint16(1)
	podSecurityEvidence := "pod-sec-ev-1"
	sriovResName := "intel.com/ice_sriov"
	bpfEvidence := "bpf-ev-1"
	staticIP := "10.0.0.10"
	attachmentMTU := uint16(1500)

	src := &SdkManagedNetworkFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cnf",
			Namespace: "default",
		},
		Spec: SdkManagedNetworkFunctionSpec{
			RuntimeMode:    "production",
			ClaimsHA:       true,
			ConfigBackend:  "consensus",
			SessionBackend: "quorum",
			AdminAuthRef: corev1.SecretReference{
				Name:      "admin-token-secret",
				Namespace: "default",
			},
			Identity: IdentityRequirements{
				KmsEnabled:    true,
				SpiffeEnabled: true,
			},
			ResourceProfile: &ResourceProfileSpec{
				NfKind:                    "upf",
				DataPlaneProfile:          "AfXdpFastPath",
				NumaPolicy:                "Require",
				GenericXdpFallbackAllowed: false,
				IsolatedCores:             []uint16{1, 2, 3},
				RequireExclusiveCores:     true,
				DataPlaneInterfaces:       []string{"eth1"},
				HugepageNumaNode:          &hugepageNuma,
				PodSecurityEvidenceID:     &podSecurityEvidence,
				SriovResourceName:         &sriovResName,
				SriovAllowedDeviceDrivers: []string{"ice"},
				IpsecNetworkAttachments: []IpsecNetworkAttachmentSpec{
					{
						InterfaceName: "eth1",
						Plane:         "untrusted-access",
						CniType:       "macvlan",
						StaticIP:      &staticIP,
						MTU:           &attachmentMTU,
					},
				},
				BpfArtifacts: []BpfArtifact{
					{
						Name:                "upf-bpf",
						Digest:              "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
						SignatureRef:        "cosign://registry.example/upf-bpf@sha256:012345",
						SignerIdentity:      "spiffe://openpacketcore.test/ns/platform/sa/release-signer",
						ProgramType:         "xdp",
						ExpectedAttachPoint: "eth1",
						AllowedCapabilities: []string{"CapBpf", "CapNetAdmin", "CapNetRaw"},
						EvidenceID:          &bpfEvidence,
					},
				},
			},
			CompatibilityRef: &corev1.LocalObjectReference{
				Name: "compat-matrix",
			},
			NodeSelector: map[string]string{
				"kubernetes.io/hostname": "worker-node-1",
			},
			Version:             "v1.0.0",
			ConfigSchemaVersion: "1.0.0",
			StateSchemaVersion:  "1.0.0",
		},
		Status: SdkManagedNetworkFunctionStatus{
			ObservedGeneration:    1,
			Phase:                 "Ready",
			CompatibilityDecision: "Allowed",
			PreflightSummary:      "Passed",
			LastAdmittedVersion:   "v1.0.0",
			BlockedReason:         "",
			EvidenceIDs:           []string{"ev-123"},
			Conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Succeeded",
					Message:            "Reconciliation complete",
					ObservedGeneration: 1,
				},
			},
		},
	}

	// 1. Convert v1alpha1 -> v1beta1
	var hub v1beta1.SdkManagedNetworkFunction
	if err := src.ConvertTo(&hub); err != nil {
		t.Fatalf("ConvertTo failed: %v", err)
	}

	// Verify specific evolved field mappings
	if hub.Spec.AdminAuthRef.Name != "admin-token-secret" {
		t.Errorf("Expected hub.Spec.AdminAuthRef.Name to be 'admin-token-secret', got '%s'", hub.Spec.AdminAuthRef.Name)
	}
	if got := hub.Spec.ResourceProfile.BpfArtifacts[0].Digest; got == "" {
		t.Errorf("Expected BPF artifact digest to be preserved")
	}
	if got := hub.Spec.ResourceProfile.BpfArtifacts[0].ExpectedAttachPoint; got != "eth1" {
		t.Errorf("Expected BPF attach point eth1, got %q", got)
	}
	if got := hub.Spec.ResourceProfile.IpsecNetworkAttachments[0].InterfaceName; got != "eth1" {
		t.Errorf("Expected IPsec attachment interface eth1, got %q", got)
	}

	// 2. Convert v1beta1 -> v1alpha1
	var roundtrip SdkManagedNetworkFunction
	if err := roundtrip.ConvertFrom(&hub); err != nil {
		t.Fatalf("ConvertFrom failed: %v", err)
	}

	// 3. Assert deep equality
	if !reflect.DeepEqual(src.Spec.ResourceProfile, roundtrip.Spec.ResourceProfile) {
		t.Errorf("ResourceProfile changed during conversion round-trip")
	}
	if !reflect.DeepEqual(src.Spec.Identity, roundtrip.Spec.Identity) {
		t.Errorf("Identity changed during conversion round-trip")
	}
	if !reflect.DeepEqual(src.Status, roundtrip.Status) {
		t.Errorf("Status changed during conversion round-trip")
	}

	// The namespace field on SecretReference gets populated back as the namespace of the object
	if roundtrip.Spec.AdminAuthRef.Namespace != "default" {
		t.Errorf("Expected AdminAuthRef.Namespace to be 'default', got '%s'", roundtrip.Spec.AdminAuthRef.Namespace)
	}
}
