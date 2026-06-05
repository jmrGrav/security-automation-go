package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

	state := BootstrapState{
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

// InitializeFromPassword writes a bootstrap state file using the supplied
// plaintext password. If the secret file already exists the call is a no-op.
// Returns an error if the password is empty and no credential file exists yet.
func InitializeFromPassword(secretFile, password string) error {
	if _, err := os.Stat(secretFile); err == nil {
		return nil // already bootstrapped
	}
	if password == "" {
		return fmt.Errorf("SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD is empty and no admin credential exists at %s", secretFile)
	}
	dir := filepath.Dir(secretFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create secret dir: %w", err)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash initial password: %w", err)
	}
	state := BootstrapState{IsBootstrap: true, PasswordHash: hash}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal bootstrap state: %w", err)
	}
	return os.WriteFile(secretFile, data, 0o600)
}

// GetBootstrapState loads the bootstrap state from the secret file.
func GetBootstrapState(secretFile string) (BootstrapState, error) {
	data, err := os.ReadFile(secretFile)
	if err != nil {
		return BootstrapState{}, fmt.Errorf("read secret file: %w", err)
	}

	var state BootstrapState
	if err := json.Unmarshal(data, &state); err != nil {
		return BootstrapState{}, fmt.Errorf("unmarshal state: %w", err)
	}

	return state, nil
}

// SaveBootstrapState persists the bootstrap state to the secret file.
func SaveBootstrapState(secretFile string, state BootstrapState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	if err := os.WriteFile(secretFile, data, 0o600); err != nil {
		return fmt.Errorf("write secret file: %w", err)
	}

	return nil
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
