package guards_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNoMCPRuntimeDependencyStrings(t *testing.T) {
	root := repoRoot(t)
	forbidden := []string{
		absoluteMCPRuntimePath(),
		mcpRuntimeModuleName(),
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkip(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body := string(data)
		for _, needle := range forbidden {
			if needle != "" && strings.Contains(body, needle) {
				t.Fatalf("forbidden reference %q found in %s", needle, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan repo: %v", err)
	}
}

func TestGoModHasNoMCPRuntimeDependency(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{"go.mod", "go.sum"} {
		path := filepath.Join(root, rel)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		body := string(data)
		for _, needle := range []string{absoluteMCPRuntimePath(), mcpRuntimeModuleName()} {
			if needle != "" && strings.Contains(body, needle) {
				t.Fatalf("forbidden reference %q found in %s", needle, rel)
			}
		}
		if strings.Contains(body, "replace") && strings.Contains(body, mcpRuntimeModuleName()) {
			t.Fatalf("forbidden replace directive found in %s", rel)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtimeCaller()
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func runtimeCaller() (uintptr, string, int, bool) {
	return runtime.Caller(0)
}

func shouldSkip(path string) bool {
	base := filepath.Base(path)
	switch {
	case strings.HasSuffix(base, ".out"),
		strings.HasSuffix(base, ".png"),
		strings.HasSuffix(base, ".jpg"),
		strings.HasSuffix(base, ".jpeg"),
		strings.HasSuffix(base, ".gif"),
		strings.HasSuffix(base, ".exe"),
		strings.HasSuffix(base, ".bin"):
		return true
	default:
		return false
	}
}

func absoluteMCPRuntimePath() string {
	return filepath.Join(string(os.PathSeparator)+"home", "jm", mcpRuntimeModuleName())
}

func mcpRuntimeModuleName() string {
	return strings.Join([]string{"mcp", "runtime", "go"}, "-")
}
