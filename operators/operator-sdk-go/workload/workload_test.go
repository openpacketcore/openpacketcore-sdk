package workload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openpacketcore.io/operator-sdk-go/rollout"

	"gopkg.in/yaml.v2"
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
