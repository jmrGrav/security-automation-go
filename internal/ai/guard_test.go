package ai

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInternalAIScaffoldingHasNoDangerousImports(t *testing.T) {
	forbidden := []string{
		"os/exec",
		"syscall",
		"internal/execution",
		"internal/rollback",
		"internal/crowdsec",
		"internal/cloudflare/mutator",
		"internal/storage/sqlite",
	}

	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || !strings.Contains(path, string(filepath.Separator)+"internal"+string(filepath.Separator)+"ai"+string(filepath.Separator)) {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.HasPrefix(importPath, bad) {
					t.Fatalf("forbidden import %q in %s", importPath, path)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
