package startuplog

import (
	"fmt"
	"os"
)

const (
	DefaultLegacyRoot    = "/etc/security-automation"
	DefaultCanonicalRoot = "/etc/security-automation-go"
)

// LayoutStatus describes the on-disk relationship between the legacy and canonical config roots.
type LayoutStatus int

const (
	LayoutOK     LayoutStatus = iota // canonical exists, or neither exists — no action needed
	LayoutBoth                       // both legacy root and canonical secrets dir exist — migration in progress
	LayoutLegacy                     // only legacy root exists — canonical secrets dir absent, secrets will not load
)

// CheckLayout reports the on-disk layout state by checking whether legacyRoot and
// canonicalSecretsDir exist. It never reads or copies any file content.
func CheckLayout(legacyRoot, canonicalSecretsDir string) LayoutStatus {
	_, legacyErr := os.Stat(legacyRoot)
	_, canonicalErr := os.Stat(canonicalSecretsDir)
	legacyExists := legacyErr == nil
	canonicalExists := canonicalErr == nil

	switch {
	case legacyExists && canonicalExists:
		return LayoutBoth
	case legacyExists && !canonicalExists:
		return LayoutLegacy
	default:
		return LayoutOK
	}
}

// WriteLayoutWarning appends a layout warning line to startup.log when the legacy
// config directory is detected. It never logs secret values — only directory paths.
// No-op when status is LayoutOK or when l is nil.
func (l *Logger) WriteLayoutWarning(status LayoutStatus, legacyRoot, canonicalSecretsDir string) {
	if l == nil || status == LayoutOK {
		return
	}
	switch status {
	case LayoutBoth:
		fmt.Fprintf(l.startup, "%s layout_warning status=BOTH_EXIST legacy=%s canonical_secrets=%s action=\"migrate secrets to canonical path; see docs/INSTALL_LAYOUT.md\"\n",
			ts(), legacyRoot, canonicalSecretsDir)
	case LayoutLegacy:
		fmt.Fprintf(l.startup, "%s layout_warning status=LEGACY_ONLY legacy=%s canonical_secrets=%s action=\"URGENT: create canonical secrets dir and migrate secrets; see docs/INSTALL_LAYOUT.md\"\n",
			ts(), legacyRoot, canonicalSecretsDir)
	}
}
