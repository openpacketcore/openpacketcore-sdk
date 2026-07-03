package testutil

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func BuildOperatorLifecycleCLI(t *testing.T) string {
	t.Helper()

	root := findRepoRoot(t)
	cmd := exec.Command("cargo", "build", "-p", "operator-lifecycle-cli")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build operator-lifecycle-cli: %v\n%s", err, string(out))
	}

	targetDir := cargoTargetDir(t, root)
	path := filepath.Join(targetDir, "debug", "operator-lifecycle-cli")
	if !fileExists(path) {
		t.Fatalf("operator-lifecycle-cli was built but not found at %s", path)
	}
	t.Setenv("OPERATOR_LIFECYCLE_CLI_PATH", path)
	return path
}

func cargoTargetDir(t *testing.T, root string) string {
	t.Helper()

	if targetDir := os.Getenv("CARGO_TARGET_DIR"); targetDir != "" {
		if filepath.IsAbs(targetDir) {
			return targetDir
		}
		return filepath.Join(root, targetDir)
	}

	cmd := exec.Command("cargo", "metadata", "--format-version=1", "--no-deps")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to resolve Cargo target directory: %v", err)
	}

	var metadata struct {
		TargetDirectory string `json:"target_directory"`
	}
	if err := json.Unmarshal(out, &metadata); err != nil {
		t.Fatalf("failed to parse cargo metadata: %v", err)
	}
	if metadata.TargetDirectory == "" {
		t.Fatalf("cargo metadata did not include target_directory")
	}
	return metadata.TargetDirectory
}

func findRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	for dir := wd; ; dir = filepath.Dir(dir) {
		if fileExists(filepath.Join(dir, "Cargo.toml")) &&
			fileExists(filepath.Join(dir, "crates", "operator-lifecycle-cli", "Cargo.toml")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("failed to find repository root from %s", wd)
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
