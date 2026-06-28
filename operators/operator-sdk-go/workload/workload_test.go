package workload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openpacketcore.io/operator-sdk-go/cni"
	"openpacketcore.io/operator-sdk-go/rollout"

	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
)

// updateGolden controls whether to overwrite golden files. Set to true to regenerate.
const updateGolden = false

func TestRenderDeploymentControlPlaneOnly(t *testing.T) {
	spec := NetworkFunctionSpec{
		Name:        "test-smf",
		Namespace:   "default",
		Version:     "1.2.3",
		RuntimeMode: "production",
		ResourceProfile: &ResourceProfile{
			NfKind:           "smf",
			DataPlaneProfile: "ControlPlaneOnly",
		},
	}
	opts := DefaultRenderOptions()
	opts.Image = "openpacketcore/smf:1.2.3"

	dep, err := RenderDeployment(spec, opts)
	if err != nil {
		t.Fatalf("RenderDeployment failed: %v", err)
	}

	assertGolden(t, "control-plane-only.golden.yaml", dep)
}

func TestRenderDeploymentAfXdpFastPath(t *testing.T) {
	spec := NetworkFunctionSpec{
		Name:        "test-upf",
		Namespace:   "default",
		Version:     "2.0.0",
		RuntimeMode: "production",
		ResourceProfile: &ResourceProfile{
			NfKind:                "upf",
			DataPlaneProfile:      "AfXdpFastPath",
			RequireExclusiveCores: true,
			IsolatedCores:         []uint16{2, 3},
			HugepageNumaNode:      ptrUint16(0),
			BpfArtifacts: []BpfArtifact{
				{
					Name:                "upf-xdp-fastpath",
					Digest:              "sha256:abc123",
					AllowedCapabilities: []string{"CAP_BPF", "CAP_NET_ADMIN", "CAP_NET_RAW"},
				},
			},
		},
	}
	opts := DefaultRenderOptions()
	opts.Image = "openpacketcore/upf:2.0.0"

	dep, err := RenderDeployment(spec, opts)
	if err != nil {
		t.Fatalf("RenderDeployment failed: %v", err)
	}

	assertGolden(t, "afxdp-fastpath.golden.yaml", dep)
}

func TestRenderDeploymentSriovFastPath(t *testing.T) {
	sriovRes := "intel.com/ice_sriov"
	spec := NetworkFunctionSpec{
		Name:        "test-upf",
		Namespace:   "default",
		Version:     "2.1.0",
		RuntimeMode: "production",
		ResourceProfile: &ResourceProfile{
			NfKind:                "upf",
			DataPlaneProfile:      "SriovFastPath",
			RequireExclusiveCores: true,
			IsolatedCores:         []uint16{4, 5},
			SriovResourceName:     &sriovRes,
		},
	}
	opts := DefaultRenderOptions()
	opts.Image = "openpacketcore/upf:2.1.0"

	dep, err := RenderDeployment(spec, opts)
	if err != nil {
		t.Fatalf("RenderDeployment failed: %v", err)
	}

	assertGolden(t, "sriov-fastpath.golden.yaml", dep)
}

func TestNeedsHostNetwork(t *testing.T) {
	tests := []struct {
		name     string
		profile  *ResourceProfile
		expected bool
	}{
		{"nil profile", nil, false},
		{"control plane", &ResourceProfile{DataPlaneProfile: "ControlPlaneOnly"}, false},
		{"afxdp", &ResourceProfile{DataPlaneProfile: "AfXdpFastPath"}, true},
		{"sriov without evidence", &ResourceProfile{DataPlaneProfile: "SriovFastPath"}, false},
		{"sriov with evidence", &ResourceProfile{DataPlaneProfile: "SriovFastPath", PodSecurityEvidenceID: ptrString("ev-123")}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NeedsHostNetwork(tc.profile)
			if got != tc.expected {
				t.Errorf("NeedsHostNetwork() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestDeterministicOutput(t *testing.T) {
	spec := NetworkFunctionSpec{
		Name:        "det-cnf",
		Namespace:   "ns",
		Version:     "1.0.0",
		RuntimeMode: "dev",
		ResourceProfile: &ResourceProfile{
			NfKind:           "amf",
			DataPlaneProfile: "ControlPlaneOnly",
		},
	}
	opts := DefaultRenderOptions()

	dep1, err := RenderDeployment(spec, opts)
	if err != nil {
		t.Fatalf("first render failed: %v", err)
	}
	dep2, err := RenderDeployment(spec, opts)
	if err != nil {
		t.Fatalf("second render failed: %v", err)
	}

	y1, _ := yaml.Marshal(dep1)
	y2, _ := yaml.Marshal(dep2)
	if string(y1) != string(y2) {
		t.Errorf("rendered output is non-deterministic")
	}
}

func assertGolden(t *testing.T, filename string, dep interface{}) {
	t.Helper()
	got, err := yaml.Marshal(dep)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	path := filepath.Join("testdata", filename)
	if updateGolden {
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", filename, err)
	}

	want := strings.TrimSpace(string(wantBytes))
	gotStr := strings.TrimSpace(string(got))
	if want != gotStr {
		t.Errorf("golden mismatch for %s\n---want---\n%s\n---got---\n%s", filename, want, gotStr)
	}
}

func TestBuildContainerPortsWithAdditionalPorts(t *testing.T) {
	spec := NetworkFunctionSpec{
		Name:      "test-nf",
		Namespace: "default",
		Version:   "1.0.0",
		AdditionalPorts: []PortSpec{
			{Name: "diameter", Port: 3868, Protocol: "tcp"},
			{Name: "gtpu", Port: 2152, Protocol: "udp"},
			{Name: "s1mme", Port: 36412, Protocol: "SCTP"},
		},
	}

	ports := BuildContainerPorts(spec, 8080)
	if len(ports) != 4 {
		t.Fatalf("expected 4 ports, got %d", len(ports))
	}

	byName := make(map[string]corev1.ContainerPort)
	for _, p := range ports {
		byName[p.Name] = p
	}
	if byName["gtpu"].Protocol != corev1.ProtocolUDP {
		t.Errorf("expected gtpu protocol UDP, got %v", byName["gtpu"].Protocol)
	}
	if byName["s1mme"].Protocol != corev1.ProtocolSCTP {
		t.Errorf("expected s1mme protocol SCTP, got %v", byName["s1mme"].Protocol)
	}
	if byName["diameter"].Protocol != corev1.ProtocolTCP {
		t.Errorf("expected diameter protocol TCP, got %v", byName["diameter"].Protocol)
	}
}

func TestParsePortProtocol(t *testing.T) {
	cases := []struct {
		input string
		want  corev1.Protocol
	}{
		{"tcp", corev1.ProtocolTCP},
		{"TCP", corev1.ProtocolTCP},
		{"Udp", corev1.ProtocolUDP},
		{"UDP", corev1.ProtocolUDP},
		{"sctp", corev1.ProtocolSCTP},
		{"SCTP", corev1.ProtocolSCTP},
		{"", corev1.ProtocolTCP},
		{"unknown", corev1.ProtocolTCP},
	}
	for _, tc := range cases {
		got := ParsePortProtocol(tc.input)
		if got != tc.want {
			t.Errorf("ParsePortProtocol(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestRenderDeploymentWithMultusAttachments(t *testing.T) {
	spec := NetworkFunctionSpec{
		Name:      "test-nf",
		Namespace: "default",
		Version:   "1.0.0",
	}
	opts := DefaultRenderOptions()
	opts.MultusAttachments = []cni.Attachment{
		{Name: "net0", NetworkName: "nad-a", InterfaceName: "net0"},
	}

	dep, err := RenderDeployment(spec, opts)
	if err != nil {
		t.Fatalf("RenderDeployment failed: %v", err)
	}

	if _, ok := dep.Spec.Template.Annotations[cni.MultusNetworkAnnotationKey]; !ok {
		t.Fatalf("expected multus annotation to be set")
	}
}

func TestValidateImageTag(t *testing.T) {
	cases := []struct {
		name    string
		spec    NetworkFunctionSpec
		opts    RenderOptions
		wantErr bool
	}{
		{
			name: "no immutable tag required",
			spec: NetworkFunctionSpec{ImageTag: ""},
			opts: RenderOptions{Image: "openpacketcore/nf:latest"},
		},
		{
			name: "matching immutable tag",
			spec: NetworkFunctionSpec{ImageTag: "1.2.3"},
			opts: RenderOptions{Image: "openpacketcore/nf:1.2.3"},
		},
		{
			name:    "mismatched immutable tag",
			spec:    NetworkFunctionSpec{ImageTag: "1.2.3"},
			opts:    RenderOptions{Image: "openpacketcore/nf:1.2.4"},
			wantErr: true,
		},
		{
			name:    "missing image tag",
			spec:    NetworkFunctionSpec{ImageTag: "1.2.3"},
			opts:    RenderOptions{Image: "openpacketcore/nf"},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateImageTag(tc.spec, tc.opts)
			if tc.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfigPushObservedGenerationOK(t *testing.T) {
	if !ConfigPushObservedGenerationOK(NetworkFunctionSpec{ConfigPushObservedGeneration: 0}) {
		t.Error("expected generation 0 to be observed")
	}
	if !ConfigPushObservedGenerationOK(NetworkFunctionSpec{ConfigPushObservedGeneration: 5}) {
		t.Error("expected generation 5 to be observed")
	}
	if ConfigPushObservedGenerationOK(NetworkFunctionSpec{ConfigPushObservedGeneration: -1}) {
		t.Error("expected generation -1 to not be observed")
	}
}

func TestRenderDeploymentRolloutStrategy(t *testing.T) {
	spec := NetworkFunctionSpec{
		Name:        "test-amf",
		Namespace:   "default",
		Version:     "1.0.0",
		RuntimeMode: "production",
		ResourceProfile: &ResourceProfile{
			NfKind:           "amf",
			DataPlaneProfile: "ControlPlaneOnly",
		},
	}

	tests := []struct {
		name        string
		strategy    rollout.Strategy
		wantType    string
		wantSurge   string
		wantUnavail string
	}{
		{"rolling", rollout.StrategyRolling, "RollingUpdate", "25%", "25%"},
		{"canary", rollout.StrategyCanary, "RollingUpdate", "1", "0"},
		{"blue-green", rollout.StrategyBlueGreen, "Recreate", "", ""},
		{"manual", rollout.StrategyManual, "RollingUpdate", "0", "1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := DefaultRenderOptions()
			opts.RolloutParams = &rollout.Params{Strategy: tc.strategy}

			dep, err := RenderDeployment(spec, opts)
			if err != nil {
				t.Fatalf("RenderDeployment failed: %v", err)
			}

			if string(dep.Spec.Strategy.Type) != tc.wantType {
				t.Errorf("Strategy.Type = %v, want %v", dep.Spec.Strategy.Type, tc.wantType)
			}
			if dep.Spec.Strategy.RollingUpdate != nil {
				if tc.wantSurge != "" && dep.Spec.Strategy.RollingUpdate.MaxSurge.String() != tc.wantSurge {
					t.Errorf("MaxSurge = %v, want %v", dep.Spec.Strategy.RollingUpdate.MaxSurge.String(), tc.wantSurge)
				}
				if tc.wantUnavail != "" && dep.Spec.Strategy.RollingUpdate.MaxUnavailable.String() != tc.wantUnavail {
					t.Errorf("MaxUnavailable = %v, want %v", dep.Spec.Strategy.RollingUpdate.MaxUnavailable.String(), tc.wantUnavail)
				}
			}
		})
	}
}

func ptrUint16(v uint16) *uint16 { return &v }
func ptrString(v string) *string { return &v }
