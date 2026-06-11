package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// ExpectedContractVersion is the major contract version the Go side expects
// from the Rust lifecycle CLI. It must match operator_lifecycle::CONTRACT_VERSION.
const ExpectedContractVersion uint32 = 1

// ErrorKind classifies bridge errors so callers can decide retry vs terminal.
type ErrorKind int

const (
	// ErrKindBinaryMissing means the CLI binary could not be found or executed.
	ErrKindBinaryMissing ErrorKind = iota
	// ErrKindContractMismatch means the Rust CLI contract version does not match.
	ErrKindContractMismatch
	// ErrKindTimeout means the CLI call exceeded its deadline.
	ErrKindTimeout
	// ErrKindCLIError means the CLI exited non-zero and returned a structured error.
	ErrKindCLIError
	// ErrKindMalformedJSON means the CLI output could not be parsed.
	ErrKindMalformedJSON
	// ErrKindUnknown is a catch-all for unexpected failures.
	ErrKindUnknown
)

// Error is a typed bridge error. Use errors.As to inspect the Kind.
type Error struct {
	Kind    ErrorKind
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

// IsTerminal reports whether this error should set the RecoveryRequired
// condition rather than trigger a requeue.
func (e *Error) IsTerminal() bool {
	switch e.Kind {
	case ErrKindBinaryMissing, ErrKindContractMismatch, ErrKindCLIError, ErrKindMalformedJSON:
		return true
	default:
		return false
	}
}

// IsTransient reports whether this error should trigger a requeue with backoff.
func (e *Error) IsTransient() bool {
	return e.Kind == ErrKindTimeout
}

// Client is a hardened subprocess client for the Rust lifecycle CLI.
type Client struct {
	binaryPath     string
	defaultTimeout time.Duration

	handshakeOnce sync.Once
	handshakeErr  error
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithDefaultTimeout sets the per-call default timeout (default 10s).
func WithDefaultTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.defaultTimeout = d
	}
}

// NewClient creates a bridge client. If binaryPath is empty, it falls back to
// the OPERATOR_LIFECYCLE_CLI_PATH environment variable, then to common
// relative search paths.
func NewClient(binaryPath string, opts ...ClientOption) (*Client, error) {
	if binaryPath == "" {
		binaryPath = os.Getenv("OPERATOR_LIFECYCLE_CLI_PATH")
	}
	if binaryPath == "" {
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
				binaryPath = path
				break
			}
		}
	}
	if binaryPath == "" {
		return nil, &Error{Kind: ErrKindBinaryMissing, Message: "operator-lifecycle-cli binary not found"}
	}

	c := &Client{
		binaryPath:     binaryPath,
		defaultTimeout: 10 * time.Second,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// BinaryPath returns the resolved CLI binary path.
func (c *Client) BinaryPath() string {
	return c.binaryPath
}

// Call executes a CLI subcommand with the given context. If ctx has no
// deadline, the client's defaultTimeout is applied. Input is JSON-marshalled
// and wrapped with expectedContractVersion; output is unmarshalled after
// stripping the response contractVersion envelope.
func (c *Client) Call(ctx context.Context, subcommand string, input, output interface{}) error {
	// Contract handshake on first use.
	c.handshakeOnce.Do(func() {
		c.handshakeErr = c.runHandshake(ctx)
	})
	if c.handshakeErr != nil {
		return c.handshakeErr
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.defaultTimeout)
		defer cancel()
	}

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return &Error{Kind: ErrKindMalformedJSON, Message: fmt.Sprintf("marshal input: %v", err)}
	}

	var wrapped map[string]interface{}
	if err := json.Unmarshal(inputBytes, &wrapped); err != nil {
		return &Error{Kind: ErrKindMalformedJSON, Message: fmt.Sprintf("unmarshal input for wrapping: %v", err)}
	}
	wrapped["expectedContractVersion"] = ExpectedContractVersion
	wrappedBytes, err := json.Marshal(wrapped)
	if err != nil {
		return &Error{Kind: ErrKindMalformedJSON, Message: fmt.Sprintf("marshal wrapped input: %v", err)}
	}

	cmd := exec.CommandContext(ctx, c.binaryPath, subcommand)
	cmd.Stdin = bytes.NewReader(wrappedBytes)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return &Error{Kind: ErrKindTimeout, Message: fmt.Sprintf("cli %s timed out", subcommand)}
	}
	if err != nil {
		// Attempt structured error from stdout.
		var errResp struct {
			Error           string `json:"error"`
			ContractVersion uint32 `json:"contractVersion"`
		}
		if json.Unmarshal(stdout.Bytes(), &errResp) == nil && errResp.Error != "" {
			if errResp.ContractVersion != 0 && errResp.ContractVersion != ExpectedContractVersion {
				return &Error{Kind: ErrKindContractMismatch, Message: fmt.Sprintf("contract version mismatch: expected %d, got %d", ExpectedContractVersion, errResp.ContractVersion)}
			}
			return &Error{Kind: ErrKindCLIError, Message: fmt.Sprintf("SDK policy CLI error: %s", errResp.Error)}
		}
		stderrStr := stderr.String()
		if len(stderrStr) > 1024 {
			stderrStr = stderrStr[:1024] + "... [truncated]"
		}
		if stderrStr != "" {
			return &Error{Kind: ErrKindUnknown, Message: fmt.Sprintf("SDK policy CLI execution failed: %s", stderrStr)}
		}
		return &Error{Kind: ErrKindUnknown, Message: "SDK policy CLI execution failed"}
	}

	payloadBytes, err := validateAndStripContractVersion(stdout.Bytes())
	if err != nil {
		return err
	}

	if err := json.Unmarshal(payloadBytes, output); err != nil {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(payloadBytes, &errResp) == nil && errResp.Error != "" {
			return &Error{Kind: ErrKindCLIError, Message: fmt.Sprintf("SDK policy CLI error: %s", errResp.Error)}
		}
		return &Error{Kind: ErrKindMalformedJSON, Message: fmt.Sprintf("SDK policy CLI returned invalid JSON: %v", err)}
	}

	return nil
}

func (c *Client) runHandshake(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.defaultTimeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, c.binaryPath, "version")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return &Error{Kind: ErrKindTimeout, Message: "version handshake timed out"}
		}
		return &Error{Kind: ErrKindBinaryMissing, Message: fmt.Sprintf("version handshake failed: %v", err)}
	}

	var resp struct {
		ContractVersion uint32 `json:"contractVersion"`
		CrateVersion    string `json:"crateVersion"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return &Error{Kind: ErrKindMalformedJSON, Message: fmt.Sprintf("version handshake returned invalid JSON: %v", err)}
	}
	if resp.ContractVersion != ExpectedContractVersion {
		return &Error{Kind: ErrKindContractMismatch, Message: fmt.Sprintf("contract version mismatch: expected %d, got %d", ExpectedContractVersion, resp.ContractVersion)}
	}
	return nil
}

func validateAndStripContractVersion(data []byte) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		// Not a JSON object: could be an old-format string response. Return as-is for backward compat.
		return data, nil
	}

	if raw, ok := envelope["contractVersion"]; ok {
		var cv uint32
		if err := json.Unmarshal(raw, &cv); err != nil {
			return nil, &Error{Kind: ErrKindMalformedJSON, Message: fmt.Sprintf("invalid contract version: %v", err)}
		}
		if cv != ExpectedContractVersion {
			return nil, &Error{Kind: ErrKindContractMismatch, Message: fmt.Sprintf("contract version mismatch: expected %d, got %d", ExpectedContractVersion, cv)}
		}
	}

	delete(envelope, "contractVersion")
	stripped, err := json.Marshal(envelope)
	if err != nil {
		return nil, &Error{Kind: ErrKindMalformedJSON, Message: fmt.Sprintf("re-marshal after stripping contract version: %v", err)}
	}
	return stripped, nil
}

// ErrContractMismatch is a sentinel error for contract version mismatches.
// It is kept for backward compatibility with code that uses errors.Is.
var ErrContractMismatch = errors.New("contract version mismatch between Go SDK and Rust lifecycle CLI")
