package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/jm/security-automation-go/internal/apperr"
)

type Store interface {
	Load(ctx context.Context, name string, dst any) error
	Save(ctx context.Context, name string, src any) error
}

type JSONStore struct {
	baseDir string
}

func NewJSONStore(baseDir string) *JSONStore {
	return &JSONStore{baseDir: baseDir}
}

func (s *JSONStore) Load(ctx context.Context, name string, dst any) error {
	const op = "state.JSONStore.Load"

	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(op, err)
	}

	path := filepath.Join(s.baseDir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return apperr.Wrapf(op, err, "read %s", path)
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return apperr.Wrapf(op, err, "unmarshal %s", path)
	}
	return nil
}

func (s *JSONStore) Save(ctx context.Context, name string, src any) error {
	const op = "state.JSONStore.Save"

	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(op, err)
	}

	if err := os.MkdirAll(s.baseDir, 0o750); err != nil {
		return apperr.Wrapf(op, err, "mkdir %s", s.baseDir)
	}

	data, err := json.MarshalIndent(src, "", "  ")
	if err != nil {
		return apperr.Wrap(op, err)
	}

	path := filepath.Join(s.baseDir, name)
	tmpFile, err := os.CreateTemp(s.baseDir, filepath.Base(name)+".*.tmp")
	if err != nil {
		return apperr.Wrapf(op, err, "create temp file in %s", s.baseDir)
	}

	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return apperr.Wrapf(op, err, "write temp file %s", tmpPath)
	}
	if err := tmpFile.Close(); err != nil {
		return apperr.Wrapf(op, err, "close temp file %s", tmpPath)
	}
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		return apperr.Wrapf(op, err, "chmod temp file %s", tmpPath)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return apperr.Wrapf(op, err, "rename %s to %s", tmpPath, path)
	}
	return nil
}
