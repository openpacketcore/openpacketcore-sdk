package sdkbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"openpacketcore.io/sdk-reference-operator/internal/testutil"
)

func TestBridgeAdmission(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	// 1. Unsafe token should fail closed in Production
	adminToken := "short"
	req := &AdmissionRequest{
		Uid:            "test-uid-1",
		RuntimeMode:    RuntimeModeProduction,
		ClaimsHA:       true,
		ConfigBackend:  "consensus",
		SessionBackend: "quorum",
		AdminAuth: AdminAuthSpec{
			TokenEnabled: true,
			AdminToken:   &adminToken,
		},
		Identity: IdentitySpec{
			KmsEnabled:    true,
			SpiffeEnabled: true,
		},
	}

	resp, err := bridge.EvaluateAdmission(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateAdmission failed: %v", err)
	}

	if resp.Uid != "test-uid-1" {
		t.Errorf("Expected uid test-uid-1, got %s", resp.Uid)
	}
	if resp.Allowed {
		t.Errorf("Expected allowed=false for insecure admin token in Production mode")
	}
	if resp.Status == nil {
		t.Fatalf("Expected status to be populated for denied admission")
	}
	if resp.Status.Code != 400 {
		t.Errorf("Expected status code 400, got %d", resp.Status.Code)
	}
	if resp.Status.Reason != "AdminTokenUnsafe" {
		t.Errorf("Expected status reason AdminTokenUnsafe, got %s", resp.Status.Reason)
	}
	if resp.Status.Message == "" {
		t.Errorf("Expected status message to be populated")
	}
}

func TestBridgeProductionAdmissionWithPreflight(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	adminToken := "secure-token-value-with-long-length-12345"
	evidenceID := "platform-preflight-ev-1"
	numa := uint16(0)
	req := &AdmissionRequest{
		Uid:            "test-uid-preflight",
		RuntimeMode:    RuntimeModeProduction,
		ClaimsHA:       false,
		ConfigBackend:  "consensus",
		SessionBackend: "quorum",
		AdminAuth: AdminAuthSpec{
			TokenEnabled: true,
			AdminToken:   &adminToken,
		},
		Identity: IdentitySpec{
			KmsEnabled:    true,
			SpiffeEnabled: true,
		},
		ResourceProfile: &ResourceProfileSpec{
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
			BpfArtifacts:              []BpfArtifact{validBpfArtifact("ens5f0", evidenceID)},
		},
		NodeCapabilities: validNodeCapabilityReport(),
	}

	resp, err := bridge.EvaluateAdmission(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateAdmission failed: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("Expected production admission to pass, got status %#v", resp.Status)
	}
}

func TestBridgeConfigApply(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	// Test config apply evaluate with a simple RecoveryRequired state blocking rollout
	req := &ConfigApplyRequest{
		DesiredGeneration:         2,
		CurrentObservedGeneration: 1,
		CurrentVersion:            1,
		CurrentDigest:             "0000000000000000000000000000000000000000000000000000000000000000",
		LifecycleStatus: LifecycleStatus{
			Phase:              "RecoveryRequired",
			Conditions:         []LifecycleCondition{},
			ObservedGeneration: 1,
		},
		ActiveAlarms: []Alarm{},
	}

	resp, err := bridge.EvaluateConfigApply(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateConfigApply failed: %v", err)
	}

	if resp.Type != "RecoveryRequired" {
		t.Errorf("Expected RecoveryRequired decision, got %s", resp.Type)
	}
	if resp.RecoveryReason == "" {
		t.Errorf("Expected recovery reason to be populated")
	}
}

func TestBridgeConfigApplyExpiredPendingRollsBack(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	currentTime := "2026-06-08T00:02:00Z"
	req := &ConfigApplyRequest{
		DesiredGeneration:         2,
		CurrentObservedGeneration: 1,
		CurrentVersion:            2,
		CurrentDigest:             "0000000000000000000000000000000000000000000000000000000000000000",
		LifecycleStatus: LifecycleStatus{
			Phase:              "Ready",
			Conditions:         []LifecycleCondition{},
			ObservedGeneration: 1,
		},
		ActiveAlarms: []Alarm{},
		PendingConfirmation: &PendingConfirmationState{
			Version:                  2,
			PreviousConfirmedVersion: 1,
			AppliedAt:                "2026-06-08T00:00:00Z",
			TimeoutSecs:              60,
		},
		CurrentTime: &currentTime,
	}

	resp, err := bridge.EvaluateConfigApply(context.Background(), req)
	if err != nil {
		t.Fatalf("EvaluateConfigApply failed: %v", err)
	}
	if resp.Type != "Rollback" {
		t.Fatalf("Expected Rollback decision, got %s", resp.Type)
	}
	if resp.RollbackTarget != 1 {
		t.Fatalf("Expected rollback target 1, got %d", resp.RollbackTarget)
	}
}

func TestBridgeExecutionErrorDoesNotLeakCliPath(t *testing.T) {
	bridge := &Bridge{CliPath: "/tmp/very/secret/operator-lifecycle-cli"}
	var resp AdmissionResponse
	err := bridge.CallCLI(context.Background(), "admission", AdmissionRequest{}, &resp)
	if err == nil {
		t.Fatalf("Expected missing CLI to fail")
	}
	if got := err.Error(); got != "SDK policy CLI execution failed" {
		t.Fatalf("Expected sanitized execution error, got %q", got)
	}
}

func TestBridgePreflightRejectsMissingBpfArtifact(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	numa := uint16(0)
	resp, err := bridge.EvaluatePreflight(context.Background(), &PreflightRequest{
		ResourceProfile: ResourceProfileSpec{
			NfKind:                "upf",
			DataPlaneProfile:      "AfXdpFastPath",
			NumaPolicy:            "Require",
			IsolatedCores:         []uint16{2, 3},
			RequireExclusiveCores: true,
			DataPlaneInterfaces:   []string{"ens5f0"},
			DataPlaneNumaNode:     &numa,
			HugepageNumaNode:      &numa,
		},
		NodeCapabilities: *validNodeCapabilityReport(),
	})
	if err != nil {
		t.Fatalf("EvaluatePreflight failed: %v", err)
	}
	if resp.Passed {
		t.Fatalf("Expected missing governed BPF artifact to fail preflight")
	}
}

func TestBridgeContractMismatch(t *testing.T) {
	// Create a mock CLI that returns a response with an unexpected contract version.
	mockScript := `#!/bin/sh
cat > /dev/null
echo '{"contractVersion": 999, "uid": "test", "allowed": true, "status": null}'
`
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "mock-lifecycle-cli")
	if err := os.WriteFile(mockPath, []byte(mockScript), 0o755); err != nil {
		t.Fatalf("failed to write mock CLI: %v", err)
	}

	bridge := &Bridge{CliPath: mockPath}
	_, err := bridge.EvaluateAdmission(context.Background(), &AdmissionRequest{Uid: "test"})
	if err == nil {
		t.Fatalf("expected error for contract mismatch, got nil")
	}
	if !errors.Is(err, ErrContractMismatch) {
		t.Fatalf("expected ErrContractMismatch, got %v", err)
	}
}

func TestBridgeBackwardCompatNoContractVersion(t *testing.T) {
	// Create a mock CLI that returns the old format without contractVersion.
	mockScript := `#!/bin/sh
if [ "$1" = "version" ]; then
  echo '{"contractVersion":1,"crateVersion":"0.1.0"}'
  exit 0
fi
cat > /dev/null
echo '{"uid": "test-uid", "allowed": true}'
`
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "mock-lifecycle-cli")
	if err := os.WriteFile(mockPath, []byte(mockScript), 0o755); err != nil {
		t.Fatalf("failed to write mock CLI: %v", err)
	}

	bridge := &Bridge{CliPath: mockPath}
	resp, err := bridge.EvaluateAdmission(context.Background(), &AdmissionRequest{Uid: "test-uid"})
	if err != nil {
		t.Fatalf("expected no error for backward compat, got %v", err)
	}
	if resp.Uid != "test-uid" {
		t.Fatalf("expected uid test-uid, got %s", resp.Uid)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true")
	}
}

func TestBridgeContractMismatchFromCLIExitCode(t *testing.T) {
	testutil.BuildOperatorLifecycleCLI(t)

	bridge, err := NewBridge()
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}

	adminToken := "secure-token-value-with-long-length-12345"
	req := &AdmissionRequest{
		Uid:            "test-uid",
		RuntimeMode:    RuntimeModeProduction,
		ClaimsHA:       false,
		ConfigBackend:  "consensus",
		SessionBackend: "quorum",
		AdminAuth: AdminAuthSpec{
			TokenEnabled: true,
			AdminToken:   &adminToken,
		},
		Identity: IdentitySpec{
			KmsEnabled:    true,
			SpiffeEnabled: true,
		},
	}

	// Wrap request with wrong expectedContractVersion directly via CallCLI.
	inputBytes, _ := json.Marshal(req)
	var wrapped map[string]interface{}
	json.Unmarshal(inputBytes, &wrapped)
	wrapped["expectedContractVersion"] = 999
	wrongBytes, _ := json.Marshal(wrapped)

	cmd := exec.Command(bridge.CliPath, "admission")
	cmd.Stdin = bytes.NewReader(wrongBytes)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err == nil {
		t.Fatalf("Expected CLI to fail with wrong contract version")
	}

	var errResp struct {
		Error           string `json:"error"`
		ContractVersion uint32 `json:"contractVersion"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &errResp); err != nil {
		t.Fatalf("Expected valid error JSON: %v", err)
	}
	if errResp.ContractVersion != ExpectedContractVersion {
		t.Fatalf("Expected contract version %d in error response, got %d", ExpectedContractVersion, errResp.ContractVersion)
	}
	if errResp.Error == "" {
		t.Fatalf("Expected error message in response")
	}
}

func validBpfArtifact(interfaceName, evidenceID string) BpfArtifact {
	return BpfArtifact{
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

func validNodeCapabilityReport() *NodeCapabilityReport {
	numa := uint16(0)
	return &NodeCapabilityReport{
		Kernel: KernelVersion{Major: 6, Minor: 8, Patch: 0},
		Bpf: BpfCapabilities{
			CapBpf:              true,
			XdpSupported:        true,
			BtfAvailable:        true,
			CapSysAdminRequired: false,
			AvailableXdpModes:   []string{"Native"},
		},
		Cpu: NodeCpuCapabilities{
			ManagerPolicy:         "Static",
			IsolatedCores:         []uint16{2, 3},
			NumaNodes:             1,
			CpuIDs:                []uint16{0, 1, 2, 3},
			ReservedCores:         []uint16{0, 1},
			TopologyManagerPolicy: "SingleNumaNode",
			CpuNumaMap:            map[uint16]uint16{0: 0, 1: 0, 2: 0, 3: 0},
		},
		Memory: NodeMemoryCapabilities{
			Hugepages2Mi: 1024,
			Hugepages1Gi: 4,
			HugepagePools: []HugepagePool{
				{NumaNode: 0, Size: "2Mi", Total: 512, Free: 512},
			},
		},
		Nics: []NicCapability{
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
