package opa

import (
	"os"
	"path/filepath"
)

// BundleLoader loads Rego policies from disk.
type BundleLoader struct {
	regoDir string
}

func NewBundleLoader(dir string) *BundleLoader {
	return &BundleLoader{regoDir: dir}
}

func (l *BundleLoader) LoadDefault() (string, error) {
	path := filepath.Join(l.regoDir, "admission.rego")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
