package rollout

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
)

func TestAllowedStrategies(t *testing.T) {
	tests := []struct {
		name     string
		chars    NfCharacteristics
		expected []Strategy
	}{
		{
			name:     "stateless drainable",
			chars:    NfCharacteristics{Stateful: false, SafelyDrainable: true},
			expected: []Strategy{StrategyRolling, StrategyManual},
		},
		{
			name:     "stateful not drainable",
			chars:    NfCharacteristics{Stateful: true, SafelyDrainable: false},
			expected: []Strategy{StrategyPartitioned, StrategyManual},
		},
		{
			name:     "stateful but drainable gets rolling too",
			chars:    NfCharacteristics{Stateful: true, SafelyDrainable: true},
			expected: []Strategy{StrategyRolling, StrategyPartitioned, StrategyManual},
		},
		{
			name:     "high risk adds canary",
			chars:    NfCharacteristics{Stateful: false, SafelyDrainable: true, HighRisk: true},
			expected: []Strategy{StrategyRolling, StrategyCanary, StrategyManual},
		},
		{
			name:     "major upgrade adds blue-green",
			chars:    NfCharacteristics{Stateful: false, SafelyDrainable: true, MajorUpgrade: true},
			expected: []Strategy{StrategyRolling, StrategyBlueGreen, StrategyManual},
		},
		{
			name:     "incompatible change adds blue-green",
			chars:    NfCharacteristics{Stateful: true, IncompatibleChange: true},
			expected: []Strategy{StrategyPartitioned, StrategyBlueGreen, StrategyManual},
		},
		{
			name:     "everything",
			chars:    NfCharacteristics{Stateful: true, SafelyDrainable: true, HighRisk: true, MajorUpgrade: true, IncompatibleChange: true},
			expected: []Strategy{StrategyRolling, StrategyPartitioned, StrategyCanary, StrategyBlueGreen, StrategyManual},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AllowedStrategies(tc.chars)
			if !slicesEqual(got, tc.expected) {
				t.Errorf("AllowedStrategies() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	chars := NfCharacteristics{Stateful: true, SafelyDrainable: false}

	if err := Evaluate(chars, StrategyPartitioned); err != nil {
		t.Errorf("Evaluate(partitioned) should succeed for stateful NF: %v", err)
	}
	if err := Evaluate(chars, StrategyRolling); err == nil {
		t.Error("Evaluate(rolling) should fail for non-drainable stateful NF")
	}
	if err := Evaluate(chars, StrategyManual); err != nil {
		t.Errorf("Evaluate(manual) should always succeed: %v", err)
	}
}

func TestBuildDeploymentStrategy(t *testing.T) {
	tests := []struct {
		name             string
		params           Params
		wantType         appsv1.DeploymentStrategyType
		wantMaxSurge     string
		wantMaxUnavail   string
	}{
		{
			name:           "rolling defaults",
			params:         Params{Strategy: StrategyRolling},
			wantType:       appsv1.RollingUpdateDeploymentStrategyType,
			wantMaxSurge:   "25%",
			wantMaxUnavail: "25%",
		},
		{
			name:           "partitioned defaults",
			params:         Params{Strategy: StrategyPartitioned},
			wantType:       appsv1.RollingUpdateDeploymentStrategyType,
			wantMaxSurge:   "0",
			wantMaxUnavail: "1",
		},
		{
			name:           "canary defaults",
			params:         Params{Strategy: StrategyCanary},
			wantType:       appsv1.RollingUpdateDeploymentStrategyType,
			wantMaxSurge:   "1",
			wantMaxUnavail: "0",
		},
		{
			name:     "blue-green",
			params:   Params{Strategy: StrategyBlueGreen},
			wantType: appsv1.RecreateDeploymentStrategyType,
		},
		{
			name:           "manual conservative replacement",
			params:         Params{Strategy: StrategyManual},
			wantType:       appsv1.RollingUpdateDeploymentStrategyType,
			wantMaxSurge:   "0",
			wantMaxUnavail: "1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildDeploymentStrategy(tc.params)
			if got.Type != tc.wantType {
				t.Errorf("Type = %v, want %v", got.Type, tc.wantType)
			}
			if tc.wantType == appsv1.RollingUpdateDeploymentStrategyType && got.RollingUpdate != nil {
				if got.RollingUpdate.MaxSurge != nil && got.RollingUpdate.MaxSurge.String() != tc.wantMaxSurge {
					t.Errorf("MaxSurge = %v, want %v", got.RollingUpdate.MaxSurge.String(), tc.wantMaxSurge)
				}
				if got.RollingUpdate.MaxUnavailable != nil && got.RollingUpdate.MaxUnavailable.String() != tc.wantMaxUnavail {
					t.Errorf("MaxUnavailable = %v, want %v", got.RollingUpdate.MaxUnavailable.String(), tc.wantMaxUnavail)
				}
			}
		})
	}
}

func TestBuildDeploymentStrategyPanicsOnUnknown(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for unknown strategy")
		}
	}()
	BuildDeploymentStrategy(Params{Strategy: "unknown"})
}

func slicesEqual(a, b []Strategy) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
