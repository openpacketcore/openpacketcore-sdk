package testutil

import (
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

	path := filepath.Join(root, "target", "debug", "operator-lifecycle-cli")
	t.Setenv("OPERATOR_LIFECYCLE_CLI_PATH", path)
	return path
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
