package controller

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"openpacketcore.io/operator-sdk-go/rollout"
	"openpacketcore.io/operator-sdk-go/workload"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// envtestBinaries returns the path to envtest binaries managed by
// setup-envtest, or the empty string if none are found.
func envtestBinaries() string {
	// KUBEBUILDER_ASSETS takes precedence.
	if env := os.Getenv("KUBEBUILDER_ASSETS"); env != "" {
		return env
	}

	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".kubebuilder", "bin"),
		filepath.Join(home, ".local", "share", "kubebuilder-envtest"),
		filepath.Join(home, "Library", "Application Support", "io.kubebuilder.envtest"),
	}

	for _, c := range candidates {
		// Direct layout: binaries at root.
		if hasBinaries(c) {
			return c
		}
		// Nested layout: setup-envtest stores under k8s/<version>-<os>-<arch>/
		entries, err := os.ReadDir(c)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || e.Name() != "k8s" {
				continue
			}
			k8sDir := filepath.Join(c, e.Name())
			versions, err := os.ReadDir(k8sDir)
			if err != nil {
				continue
			}
			for _, v := range versions {
				if !v.IsDir() {
					continue
				}
				sub := filepath.Join(k8sDir, v.Name())
				if hasBinaries(sub) {
					return sub
				}
			}
		}
	}
	return ""
}

func hasBinaries(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "etcd")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "kube-apiserver")); err != nil {
		return false
	}
	return true
}

func setupEnvTest(t *testing.T) (*envtest.Environment, client.Client) {
	t.Helper()

	binPath := envtestBinaries()
	if binPath == "" {
		t.Skip("envtest binaries not found; run 'setup-envtest use 1.30' to install")
	}

	testEnv := &envtest.Environment{
		BinaryAssetsDirectory: binPath,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("starting envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := testEnv.Stop(); err != nil {
			t.Logf("envtest stop: %v", err)
		}
	})

	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}

	return testEnv, c
}

func TestRolloutStrategyAppliedToDeployment(t *testing.T) {
	_, c := setupEnvTest(t)
	ctx := context.Background()
	ns := "test-rollout-" + strings.ToLower(t.Name())

	// Create namespace
	if err := c.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	spec := workload.NetworkFunctionSpec{
		Name:        "amf-rollout",
		Namespace:   ns,
		Version:     "1.0.0",
		RuntimeMode: "production",
		ResourceProfile: &workload.ResourceProfile{
			NfKind:           "amf",
			DataPlaneProfile: "ControlPlaneOnly",
		},
	}

	tests := []struct {
		name        string
		strategy    rollout.Strategy
		wantType    appsv1.DeploymentStrategyType
		wantSurge   string
		wantUnavail string
	}{
		{
			name:        "rolling",
			strategy:    rollout.StrategyRolling,
			wantType:    appsv1.RollingUpdateDeploymentStrategyType,
			wantSurge:   "25%",
			wantUnavail: "25%",
		},
		{
			name:        "canary",
			strategy:    rollout.StrategyCanary,
			wantType:    appsv1.RollingUpdateDeploymentStrategyType,
			wantSurge:   "1",
			wantUnavail: "0",
		},
		{
			name:     "blue-green",
			strategy: rollout.StrategyBlueGreen,
			wantType: appsv1.RecreateDeploymentStrategyType,
		},
		{
			name:        "manual",
			strategy:    rollout.StrategyManual,
			wantType:    appsv1.RollingUpdateDeploymentStrategyType,
			wantSurge:   "0",
			wantUnavail: "1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := workload.DefaultRenderOptions()
			opts.RolloutParams = &rollout.Params{Strategy: tc.strategy}

			dep, err := workload.RenderDeployment(spec, opts)
			if err != nil {
				t.Fatalf("RenderDeployment: %v", err)
			}

			if err := c.Create(ctx, dep); err != nil {
				t.Fatalf("create deployment: %v", err)
			}
			t.Cleanup(func() {
				_ = c.Delete(ctx, dep)
			})

			var got appsv1.Deployment
			if err := c.Get(ctx, types.NamespacedName{Name: dep.Name, Namespace: dep.Namespace}, &got); err != nil {
				t.Fatalf("get deployment: %v", err)
			}

			if got.Spec.Strategy.Type != tc.wantType {
				t.Errorf("Strategy.Type = %v, want %v", got.Spec.Strategy.Type, tc.wantType)
			}

			if tc.wantType == appsv1.RollingUpdateDeploymentStrategyType && got.Spec.Strategy.RollingUpdate != nil {
				if got.Spec.Strategy.RollingUpdate.MaxSurge.String() != tc.wantSurge {
					t.Errorf("MaxSurge = %v, want %v", got.Spec.Strategy.RollingUpdate.MaxSurge.String(), tc.wantSurge)
				}
				if got.Spec.Strategy.RollingUpdate.MaxUnavailable.String() != tc.wantUnavail {
					t.Errorf("MaxUnavailable = %v, want %v", got.Spec.Strategy.RollingUpdate.MaxUnavailable.String(), tc.wantUnavail)
				}
			}
		})
	}
}

func TestRolloutPolicyEvaluationBlocksForbiddenStrategy(t *testing.T) {
	// A stateful, non-drainable NF must not be allowed to use rolling
	// strategy per RFC 009 §12.
	chars := rollout.NfCharacteristics{
		Stateful:        true,
		SafelyDrainable: false,
	}

	if err := rollout.Evaluate(chars, rollout.StrategyRolling); err == nil {
		t.Error("expected rolling strategy to be forbidden for stateful non-drainable NF")
	}

	if err := rollout.Evaluate(chars, rollout.StrategyPartitioned); err != nil {
		t.Errorf("expected partitioned strategy to be allowed for stateful NF: %v", err)
	}
}

func TestMain(m *testing.M) {
	// Ensure setup-envtest binaries are discoverable on macOS where the
	// default cache path includes spaces.
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		cache := filepath.Join(home, "Library", "Application Support", "io.kubebuilder.envtest", "cache")
		if _, err := os.Stat(cache); err == nil {
			// Find the newest version directory.
			entries, _ := os.ReadDir(cache)
			var latest string
			for _, e := range entries {
				if e.IsDir() && strings.HasPrefix(e.Name(), "k8s-") {
					if e.Name() > latest {
						latest = e.Name()
					}
				}
			}
			if latest != "" {
				bin := filepath.Join(cache, latest)
				if cur := os.Getenv("KUBEBUILDER_ASSETS"); cur == "" {
					_ = os.Setenv("KUBEBUILDER_ASSETS", bin)
				}
			}
		}
	}
	os.Exit(m.Run())
}
