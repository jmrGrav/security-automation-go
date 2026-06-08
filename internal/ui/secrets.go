package ui

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type SecretProvider interface {
	Lookup(key string) (string, bool)
	Set(key, value string) error
	Ensure(key string) (string, error)
	Masked(key string) string
}

type FileSecretProvider struct {
	path string
	mu   sync.Mutex
	data map[string]string
	once sync.Once
	err  error
}

func NewFileSecretProvider(path string) *FileSecretProvider {
	return &FileSecretProvider{path: path}
}

// WriteSecretFile is retained for UI bootstrap/session-secret handling only.
// It is not a source for operator credentials.
func WriteSecretFile(path string, secrets map[string]string) error {
	if path == "" {
		return errors.New("secret file path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create secret dir: %w", err)
	}
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		if strings.TrimSpace(k) == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open temp secret file: %w", err)
	}
	w := bufio.NewWriter(f)
	for _, k := range keys {
		if _, err := fmt.Fprintf(w, "%s=%s\n", k, secrets[k]); err != nil {
			f.Close()
			return fmt.Errorf("write temp secret file: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return fmt.Errorf("flush temp secret file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp secret file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace secret file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod secret file: %w", err)
	}
	return nil
}

func (p *FileSecretProvider) Lookup(key string) (string, bool) {
	if v := os.Getenv(key); v != "" {
		return v, true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.loadLocked(); err != nil {
		return "", false
	}
	v, ok := p.data[key]
	return v, ok && v != ""
}

func (p *FileSecretProvider) Set(key, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.loadLocked(); err != nil {
		return err
	}
	if p.data == nil {
		p.data = make(map[string]string)
	}
	p.data[key] = value
	return WriteSecretFile(p.path, p.data)
}

func (p *FileSecretProvider) Ensure(key string) (string, error) {
	if v, ok := p.Lookup(key); ok {
		return v, nil
	}
	secret, err := randomSecret()
	if err != nil {
		return "", err
	}
	if err := p.Set(key, secret); err != nil {
		return "", err
	}
	return secret, nil
}

func (p *FileSecretProvider) Masked(key string) string {
	if v, ok := p.Lookup(key); ok {
		return redactValue(v)
	}
	return "missing"
}

func (p *FileSecretProvider) loadLocked() error {
	p.once.Do(func() {
		p.data = make(map[string]string)
		if p.path == "" {
			return
		}
		raw, err := os.ReadFile(p.path)
		if err != nil {
			if os.IsNotExist(err) {
				return
			}
			p.err = err
			return
		}
		lines := strings.Split(string(raw), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			p.data[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	})
	return p.err
}

func randomSecret() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
