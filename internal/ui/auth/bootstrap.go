package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jm/security-automation-go/internal/ui"
)

// InitializeBootstrapPassword generates and persists the bootstrap password once.
// If the secret file already exists, returns the existing password without regenerating.
func InitializeBootstrapPassword(secretFile string) (string, error) {
	dir := filepath.Dir(secretFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create secret dir: %w", err)
	}

	// Check if file already exists
	if _, err := os.Stat(secretFile); err == nil {
		// File exists — read and return stored password
		state, err := GetBootstrapState(secretFile)
		if err != nil {
			return "", fmt.Errorf("read existing state: %w", err)
		}
		return state.Password, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat secret file: %w", err)
	}

	// Generate new password
	password := GenerateBootstrapPassword()
	hash, err := HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}

	state := ui.BootstrapState{
		IsBootstrap:  true,
		Password:     password,
		PasswordHash: hash,
	}

	data, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("marshal state: %w", err)
	}

	if err := os.WriteFile(secretFile, data, 0o600); err != nil {
		return "", fmt.Errorf("write secret file: %w", err)
	}

	// Return password once; it is NEVER printed, logged, or returned after this
	return password, nil
}

// GetBootstrapState loads the bootstrap state from the secret file.
func GetBootstrapState(secretFile string) (ui.BootstrapState, error) {
	data, err := os.ReadFile(secretFile)
	if err != nil {
		return ui.BootstrapState{}, fmt.Errorf("read secret file: %w", err)
	}

	var state ui.BootstrapState
	if err := json.Unmarshal(data, &state); err != nil {
		return ui.BootstrapState{}, fmt.Errorf("unmarshal state: %w", err)
	}

	return state, nil
}

// ClearBootstrapState marks the bootstrap password as no longer active.
func ClearBootstrapState(secretFile string) error {
	state, err := GetBootstrapState(secretFile)
	if err != nil {
		return err
	}

	state.IsBootstrap = false
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	if err := os.WriteFile(secretFile, data, 0o600); err != nil {
		return fmt.Errorf("write secret file: %w", err)
	}

	return nil
}
