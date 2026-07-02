package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}
	return p
}

func TestNewClientMissingBinary(t *testing.T) {
	// Ensure no candidates match by running from a temp directory.
	t.Setenv("OPERATOR_LIFECYCLE_CLI_PATH", "")
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(origWd); err != nil {
			t.Fatalf("failed to restore working directory: %v", err)
		}
	}()
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to switch to temp directory: %v", err)
	}

	_, err = NewClient("")
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
	var berr *Error
	if !errors.As(err, &berr) || berr.Kind != ErrKindBinaryMissing {
		t.Fatalf("expected ErrKindBinaryMissing, got %v", err)
	}
}

func TestClientCallSuccess(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "cli", `#!/bin/sh
# echo version on handshake, config-apply on call
if [ "$1" = "version" ]; then
  echo '{"contractVersion":1,"crateVersion":"0.1.0"}'
  exit 0
fi
cat > /dev/null
echo '{"contractVersion":1,"type":"Apply"}'
`)

	c, err := NewClient(script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out struct {
		Type string `json:"type"`
	}
	if err := c.Call(context.Background(), "config-apply", map[string]string{}, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Type != "Apply" {
		t.Errorf("unexpected type: %s", out.Type)
	}
}

func TestClientCallTimeout(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "cli", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo '{"contractVersion":1,"crateVersion":"0.1.0"}'
  exit 0
fi
sleep 5
echo '{"contractVersion":1}'
`)

	c, err := NewClient(script, WithDefaultTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var out map[string]interface{}
	err = c.Call(ctx, "config-apply", map[string]string{}, &out)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var berr *Error
	if !errors.As(err, &berr) || berr.Kind != ErrKindTimeout {
		t.Fatalf("expected ErrKindTimeout, got %v", err)
	}
	if !berr.IsTransient() {
		t.Error("expected timeout to be transient")
	}
}

func TestClientContractMismatchFromHandshake(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "cli", `#!/bin/sh
echo '{"contractVersion":999,"crateVersion":"0.1.0"}'
`)

	c, err := NewClient(script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out map[string]interface{}
	err = c.Call(context.Background(), "config-apply", map[string]string{}, &out)
	if err == nil {
		t.Fatal("expected contract mismatch")
	}
	var berr *Error
	if !errors.As(err, &berr) || berr.Kind != ErrKindContractMismatch {
		t.Fatalf("expected ErrKindContractMismatch, got %v", err)
	}
	if !berr.IsTerminal() {
		t.Error("expected contract mismatch to be terminal")
	}
}

func TestClientContractMismatchFromResponse(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "cli", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo '{"contractVersion":1,"crateVersion":"0.1.0"}'
  exit 0
fi
cat > /dev/null
echo '{"contractVersion":999,"uid":"x"}'
`)

	c, err := NewClient(script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out map[string]interface{}
	err = c.Call(context.Background(), "admission", map[string]string{}, &out)
	if err == nil {
		t.Fatal("expected contract mismatch")
	}
	var berr *Error
	if !errors.As(err, &berr) || berr.Kind != ErrKindContractMismatch {
		t.Fatalf("expected ErrKindContractMismatch, got %v", err)
	}
}

func TestClientBinaryMissing(t *testing.T) {
	c, err := NewClient("/nonexistent/path/operator-lifecycle-cli")
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	var out map[string]interface{}
	err = c.Call(context.Background(), "version", map[string]string{}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	var berr *Error
	if !errors.As(err, &berr) || berr.Kind != ErrKindBinaryMissing {
		t.Fatalf("expected ErrKindBinaryMissing, got %v", err)
	}
}

func TestClientCLIError(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "cli", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo '{"contractVersion":1,"crateVersion":"0.1.0"}'
  exit 0
fi
cat > /dev/null
echo '{"error":"bad request","contractVersion":1}'
exit 1
`)

	c, err := NewClient(script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out map[string]interface{}
	err = c.Call(context.Background(), "admission", map[string]string{}, &out)
	if err == nil {
		t.Fatal("expected CLI error")
	}
	var berr *Error
	if !errors.As(err, &berr) || berr.Kind != ErrKindCLIError {
		t.Fatalf("expected ErrKindCLIError, got %v", err)
	}
}

func TestClientMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "cli", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo '{"contractVersion":1,"crateVersion":"0.1.0"}'
  exit 0
fi
cat > /dev/null
echo 'not-json-at-all'
exit 0
`)

	c, err := NewClient(script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out map[string]interface{}
	err = c.Call(context.Background(), "admission", map[string]string{}, &out)
	if err == nil {
		t.Fatal("expected malformed JSON error")
	}
	var berr *Error
	if !errors.As(err, &berr) || berr.Kind != ErrKindMalformedJSON {
		t.Fatalf("expected ErrKindMalformedJSON, got %v", err)
	}
}

func TestClientStderrCapture(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "cli", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo '{"contractVersion":1,"crateVersion":"0.1.0"}'
  exit 0
fi
cat > /dev/null
echo 'something bad' >&2
exit 1
`)

	c, err := NewClient(script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out map[string]interface{}
	err = c.Call(context.Background(), "admission", map[string]string{}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	var berr *Error
	if !errors.As(err, &berr) || berr.Kind != ErrKindUnknown {
		t.Fatalf("expected ErrKindUnknown, got %v", err)
	}
	if !strings.Contains(berr.Message, "something bad") {
		t.Errorf("expected stderr in message, got %s", berr.Message)
	}
}

func TestClientBackwardCompatNoContractVersion(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "cli", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo '{"contractVersion":1,"crateVersion":"0.1.0"}'
  exit 0
fi
cat > /dev/null
echo '{"uid":"test-uid","allowed":true}'
`)

	c, err := NewClient(script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out struct {
		UID     string `json:"uid"`
		Allowed bool   `json:"allowed"`
	}
	if err := c.Call(context.Background(), "admission", map[string]string{}, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.UID != "test-uid" {
		t.Errorf("unexpected uid: %s", out.UID)
	}
}

func TestClientExpectedContractVersionInjected(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "cli", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo '{"contractVersion":1,"crateVersion":"0.1.0"}'
  exit 0
fi
# read stdin and echo it back so we can inspect the input
INPUT=$(cat)
echo "{\"contractVersion\":1,\"input\":$INPUT}"
`)

	c, err := NewClient(script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out struct {
		Input json.RawMessage `json:"input"`
	}
	if err := c.Call(context.Background(), "admission", map[string]string{"hello": "world"}, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(out.Input, &payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if payload["expectedContractVersion"] == nil {
		t.Fatal("expected expectedContractVersion to be injected")
	}
	if payload["expectedContractVersion"] != float64(ExpectedContractVersion) {
		t.Errorf("unexpected contract version: %v", payload["expectedContractVersion"])
	}
}
