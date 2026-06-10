package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/ui"
	"github.com/jm/security-automation-go/internal/ui/auth"
)

const adminRecoveryKeyBytes = 32

// runAdminCLI handles `cf-sync -mode admin <subcommand> [args...]`.
// Opens only the SQLite database — does not start the full orchestrator.
// Root is required for all admin operations.
func runAdminCLI(ctx context.Context, stateDir string, args []string) {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "Error: admin commands require root (sudo cf-sync -mode admin ...)")
		os.Exit(1)
	}

	if len(args) == 0 {
		printAdminUsage()
		os.Exit(1)
	}

	db, err := sqlite.New(stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	store := sqlite.NewSetupStore(db)

	auditSink, err := ui.NewFileAuditSink(filepath.Join(stateDir, "ui-audit.log"))
	if err != nil {
		// Non-fatal: proceed without audit if the log cannot be opened.
		auditSink = nil
	}

	switch args[0] {
	case "reset-password":
		adminResetPassword(ctx, store, auditSink)
	case "recovery-key":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: cf-sync -mode admin recovery-key <create|rotate>")
			os.Exit(1)
		}
		switch args[1] {
		case "create":
			adminRecoveryKeyCreate(ctx, store, auditSink)
		case "rotate":
			adminRecoveryKeyRotate(ctx, store, auditSink)
		default:
			fmt.Fprintf(os.Stderr, "Unknown recovery-key subcommand: %q\n", args[1])
			fmt.Fprintln(os.Stderr, "Usage: cf-sync -mode admin recovery-key <create|rotate>")
			os.Exit(1)
		}
	case "recover":
		adminRecover(ctx, store, auditSink)
	default:
		fmt.Fprintf(os.Stderr, "Unknown admin subcommand: %q\n", args[0])
		printAdminUsage()
		os.Exit(1)
	}
}

// adminResetPassword generates a temporary password, stores its bcrypt hash,
// sets password_change_required=true, and invalidates all sessions via auth_epoch.
// The temporary password is printed to stdout exactly once.
func adminResetPassword(ctx context.Context, store *sqlite.SetupStore, audit ui.AuditSink) {
	tempPwd := auth.GenerateBootstrapPassword()

	hash, err := auth.HashPassword(tempPwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: hash password: %v\n", err)
		os.Exit(1)
	}

	if err := store.SetSetting(ctx, "admin_password_hash", hash); err != nil {
		fmt.Fprintf(os.Stderr, "Error: save password hash: %v\n", err)
		os.Exit(1)
	}
	if err := store.SetPasswordChangeRequired(ctx, true); err != nil {
		fmt.Fprintf(os.Stderr, "Error: set password_change_required: %v\n", err)
		os.Exit(1)
	}
	if _, err := store.IncrementAuthEpoch(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: increment auth epoch: %v\n", err)
	}

	if audit != nil {
		audit.Record("admin_password_reset", map[string]string{"actor": "cli", "source": "admin_cli"})
	}

	fmt.Println()
	fmt.Println("=== TEMPORARY PASSWORD (shown once) ===")
	fmt.Println(tempPwd)
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("The UI server will require a password change on next login.")
	fmt.Println("If the UI server is running, existing sessions are now invalid.")
}

// adminRecoveryKeyCreate generates and stores a new recovery key.
// Fails if a recovery key already exists — use 'rotate' to replace it.
func adminRecoveryKeyCreate(ctx context.Context, store *sqlite.SetupStore, audit ui.AuditSink) {
	_, exists, err := store.GetRecoveryKeyHash(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: check existing recovery key: %v\n", err)
		os.Exit(1)
	}
	if exists {
		fmt.Fprintln(os.Stderr, "Error: recovery key already exists. Use 'recovery-key rotate' to replace it.")
		os.Exit(1)
	}
	key := generateAndStoreRecoveryKey(ctx, store)
	if audit != nil {
		audit.Record("admin_recovery_key_created", map[string]string{"actor": "cli", "source": "admin_cli"})
	}
	printRecoveryKey(key, false)
}

// adminRecoveryKeyRotate replaces the existing recovery key with a new one.
func adminRecoveryKeyRotate(ctx context.Context, store *sqlite.SetupStore, audit ui.AuditSink) {
	key := generateAndStoreRecoveryKey(ctx, store)
	if audit != nil {
		audit.Record("admin_recovery_key_rotated", map[string]string{"actor": "cli", "source": "admin_cli"})
	}
	printRecoveryKey(key, true)
}

// adminRecover uses the recovery key to reset the admin password.
// Reads the recovery key from stdin (masked), verifies it, then resets.
func adminRecover(ctx context.Context, store *sqlite.SetupStore, audit ui.AuditSink) {
	storedHash, ok, err := store.GetRecoveryKeyHash(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: read recovery key: %v\n", err)
		os.Exit(1)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "Error: no recovery key configured. Create one with: sudo cf-sync -mode admin recovery-key create")
		os.Exit(1)
	}

	fmt.Fprint(os.Stderr, "Enter recovery key: ")
	var input []byte
	if term.IsTerminal(int(os.Stdin.Fd())) {
		input, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
	} else {
		// Non-TTY: read from stdin (no masking)
		buf := make([]byte, 256)
		n, readErr := os.Stdin.Read(buf)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "Error: read stdin: %v\n", readErr)
			os.Exit(1)
		}
		input = []byte(strings.TrimRight(string(buf[:n]), "\r\n"))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: read recovery key: %v\n", err)
		os.Exit(1)
	}

	// Decode and verify using constant-time SHA-256 comparison.
	ok, verifyErr := verifyRecoveryKey(string(input), storedHash)
	if verifyErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", verifyErr)
		os.Exit(1)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "Error: recovery key is incorrect")
		os.Exit(1)
	}

	// Record the use
	_ = store.UpdateRecoveryKeyLastUsed(ctx)
	if audit != nil {
		audit.Record("admin_recovery_used", map[string]string{"actor": "cli", "source": "admin_cli"})
	}

	// Reset password
	adminResetPassword(ctx, store, audit)
}

func generateAndStoreRecoveryKey(ctx context.Context, store *sqlite.SetupStore) []byte {
	key := make([]byte, adminRecoveryKeyBytes)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintf(os.Stderr, "Error: generate recovery key: %v\n", err)
		os.Exit(1)
	}
	hash := hex.EncodeToString(sha256sum(key))
	if err := store.SetRecoveryKeyHash(ctx, hash); err != nil {
		fmt.Fprintf(os.Stderr, "Error: store recovery key hash: %v\n", err)
		os.Exit(1)
	}
	return key
}

// verifyRecoveryKey checks whether the base64-encoded candidate matches storedHexHash.
// Returns true only when the constant-time SHA-256 comparison succeeds.
func verifyRecoveryKey(candidate string, storedHexHash string) (bool, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(candidate))
	if err != nil {
		return false, fmt.Errorf("invalid recovery key format")
	}
	inputHash := sha256sum(raw)
	storedBytes, err := hex.DecodeString(storedHexHash)
	if err != nil {
		return false, fmt.Errorf("internal key format error")
	}
	return subtle.ConstantTimeCompare(inputHash, storedBytes) == 1, nil
}

func printRecoveryKey(key []byte, rotated bool) {
	encoded := base64.RawURLEncoding.EncodeToString(key)
	action := "created"
	if rotated {
		action = "rotated"
	}
	fmt.Println()
	fmt.Printf("=== RECOVERY KEY %s (shown once) ===\n", strings.ToUpper(action))
	fmt.Println(encoded)
	fmt.Println("=======================================")
	fmt.Println()
	fmt.Println("Store this key in a secure location (password manager, safe).")
	fmt.Println("It cannot be recovered from the database — only its hash is stored.")
	fmt.Println("Use: sudo cf-sync -mode admin recover")
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func printAdminUsage() {
	fmt.Fprintln(os.Stderr, `Usage: sudo cf-sync -mode admin <subcommand>

Subcommands:
  reset-password          Generate a temporary password (forces change on next login)
  recovery-key create     Create a recovery key (fails if one already exists)
  recovery-key rotate     Replace the existing recovery key with a new one
  recover                 Use the recovery key to reset the admin password

All admin commands require root.`)
}
