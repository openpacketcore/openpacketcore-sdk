package sdkbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"openpacketcore.io/operator-sdk-go/bridge"
)

// Bridge handles execution of the operator-lifecycle-cli binary.
// It is a thin wrapper over bridge.Client that preserves the type signatures
// used by the reference controller.
type Bridge struct {
	CliPath string
	client  *bridge.Client
}

// NewBridge creates a Bridge, resolving the CLI path from the environment
// or common relative paths.
func NewBridge() (*Bridge, error) {
	cliPath := os.Getenv("OPERATOR_LIFECYCLE_CLI_PATH")
	if cliPath == "" {
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
				cliPath = path
				break
			}
		}
	}
	if cliPath == "" {
		return nil, bridge.ErrContractMismatch
	}

	c, err := bridge.NewClient(cliPath)
	if err != nil {
		return nil, err
	}
	return &Bridge{CliPath: cliPath, client: c}, nil
}

// CallCLI executes the Rust CLI for a given subcommand, feeding input and reading output.
// It wraps bridge.Client.Call and preserves backward-compatible error behavior.
// The caller's context bounds the subprocess (in addition to the client's
// default timeout), so reconcile/webhook cancellation propagates to the CLI.
func (b *Bridge) CallCLI(ctx context.Context, subcommand string, input interface{}, output interface{}) error {
	if b.client == nil {
		c, err := bridge.NewClient(b.CliPath)
		if err != nil {
			var berr *bridge.Error
			if errors.As(err, &berr) && berr.Kind == bridge.ErrKindBinaryMissing {
				return fmt.Errorf("SDK policy CLI execution failed")
			}
			return err
		}
		b.client = c
	}
	err := b.client.Call(ctx, subcommand, input, output)
	if err == nil {
		return nil
	}
	var berr *bridge.Error
	if errors.As(err, &berr) {
		switch berr.Kind {
		case bridge.ErrKindContractMismatch:
			return ErrContractMismatch
		case bridge.ErrKindBinaryMissing:
			return fmt.Errorf("SDK policy CLI execution failed")
		case bridge.ErrKindTimeout:
			return fmt.Errorf("SDK policy CLI call timed out")
		case bridge.ErrKindCLIError:
			return fmt.Errorf("SDK policy CLI error: %s", berr.Message)
		case bridge.ErrKindMalformedJSON:
			return fmt.Errorf("SDK policy CLI returned invalid JSON")
		default:
			return fmt.Errorf("SDK policy CLI execution failed")
		}
	}
	return fmt.Errorf("SDK policy CLI execution failed")
}

func (b *Bridge) EvaluateAdmission(ctx context.Context, req *AdmissionRequest) (*AdmissionResponse, error) {
	var resp AdmissionResponse
	if err := b.CallCLI(ctx, "admission", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (b *Bridge) EvaluateCompatibility(ctx context.Context, req *CompatibilityRequest) (*CompatibilityDecision, error) {
	var resp CompatibilityDecision
	if err := b.CallCLI(ctx, "compatibility", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (b *Bridge) EvaluateConfigApply(ctx context.Context, req *ConfigApplyRequest) (*ConfigApplyDecision, error) {
	var resp ConfigApplyDecision
	if err := b.CallCLI(ctx, "config-apply", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (b *Bridge) EvaluatePreflight(ctx context.Context, req *PreflightRequest) (*DataPlanePreflightReport, error) {
	var resp DataPlanePreflightReport
	if err := b.CallCLI(ctx, "preflight", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// validateAndStripContractVersion is retained for backward compatibility with
// direct stdout consumers, but is no longer the primary parsing path.
func validateAndStripContractVersion(data []byte) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return data, nil
	}

	if raw, ok := envelope["contractVersion"]; ok {
		var cv uint32
		if err := json.Unmarshal(raw, &cv); err != nil {
			return nil, fmt.Errorf("SDK policy CLI returned invalid contract version: %w", err)
		}
		if cv != ExpectedContractVersion {
			return nil, ErrContractMismatch
		}
	}

	delete(envelope, "contractVersion")
	stripped, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal response after stripping contract version: %w", err)
	}
	return stripped, nil
}

// Legacy helper for tests that need to wrap input manually.
func WrapInputWithContractVersion(input []byte) ([]byte, error) {
	var wrapped map[string]interface{}
	if err := json.Unmarshal(input, &wrapped); err != nil {
		return nil, err
	}
	wrapped["expectedContractVersion"] = ExpectedContractVersion
	return json.Marshal(wrapped)
}

// Legacy direct command execution helper for tests.
func BuildCommand(cliPath string, subcommand string, input []byte) *exec.Cmd {
	cmd := exec.Command(cliPath, subcommand)
	cmd.Stdin = bytes.NewReader(input)
	return cmd
}
