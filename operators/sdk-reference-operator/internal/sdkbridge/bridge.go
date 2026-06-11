package sdkbridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Bridge handles execution of the operator-lifecycle-cli binary.
type Bridge struct {
	CliPath string
}

func NewBridge() (*Bridge, error) {
	// 1. Check env var
	cliPath := os.Getenv("OPERATOR_LIFECYCLE_CLI_PATH")
	if cliPath != "" {
		return &Bridge{CliPath: cliPath}, nil
	}

	// 2. Look in relative paths (e.g. from tests or runtime)
	candidates := []string{
		"operator-lifecycle-cli",
		"../../target/debug/operator-lifecycle-cli",
		"../../../target/debug/operator-lifecycle-cli",
		"../../../../target/debug/operator-lifecycle-cli",
		"target/debug/operator-lifecycle-cli",
	}

	for _, cand := range candidates {
		path := cand
		if cand != "operator-lifecycle-cli" {
			if abs, err := filepath.Abs(path); err == nil {
				path = abs
			}
		}
		if _, err := exec.LookPath(path); err == nil {
			return &Bridge{CliPath: path}, nil
		}
	}

	// Default fallback
	return &Bridge{CliPath: "operator-lifecycle-cli"}, nil
}

// CallCLI executes the Rust CLI for a given subcommand, feeding input and reading output.
func (b *Bridge) CallCLI(subcommand string, input interface{}, output interface{}) error {
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal CLI input: %w", err)
	}

	cmd := exec.Command(b.CliPath, subcommand)
	cmd.Stdin = bytes.NewReader(inputBytes)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		// Attempt to parse sanitized error from stdout if possible
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(stdout.Bytes(), &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("SDK policy CLI error: %s", errResp.Error)
		}
		return fmt.Errorf("SDK policy CLI execution failed")
	}

	if err := json.Unmarshal(stdout.Bytes(), output); err != nil {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(stdout.Bytes(), &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("SDK policy CLI error: %s", errResp.Error)
		}
		return fmt.Errorf("SDK policy CLI returned invalid JSON")
	}

	return nil
}

func (b *Bridge) EvaluateAdmission(req *AdmissionRequest) (*AdmissionResponse, error) {
	var resp AdmissionResponse
	if err := b.CallCLI("admission", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (b *Bridge) EvaluateCompatibility(req *CompatibilityRequest) (*CompatibilityDecision, error) {
	var resp CompatibilityDecision
	if err := b.CallCLI("compatibility", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (b *Bridge) EvaluateConfigApply(req *ConfigApplyRequest) (*ConfigApplyDecision, error) {
	var resp ConfigApplyDecision
	if err := b.CallCLI("config-apply", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (b *Bridge) EvaluatePreflight(req *PreflightRequest) (*DataPlanePreflightReport, error) {
	var resp DataPlanePreflightReport
	if err := b.CallCLI("preflight", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
