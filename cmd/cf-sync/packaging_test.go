package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPostinst_CrowdsecLuaGroupGrant guards the /run/crowdsec-lua permission
// fix (see docs/operations/RUNBOOK.md, "/run/crowdsec-lua permissions —
// restart required after group changes"). cf-sync needs write+rename access
// to that directory to read events.jsonl/waf_refs.jsonl written by the
// OpenResty Lua bouncer (running as www-data). The fix must add
// security-automation to the existing www-data group — least privilege,
// scoped to exactly the one shared directory — and must never widen the
// directory's own permissions (e.g. chmod 777), which would let any local
// user read/write CrowdSec ban state.
func TestPostinst_CrowdsecLuaGroupGrant(t *testing.T) {
	path := filepath.Join("..", "..", "packaging", "deb", "DEBIAN", "postinst")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read postinst: %v", err)
	}
	body := string(data)

	if !strings.Contains(body, "usermod -aG www-data security-automation") {
		t.Fatal("postinst must add security-automation to the www-data group " +
			"so cf-sync can rename files in /run/crowdsec-lua (root:www-data 0775)")
	}

	// The grant must be guarded so installs without nginx/openresty (no
	// www-data group) don't fail the package install.
	if !strings.Contains(body, "getent group www-data") {
		t.Fatal("www-data group grant must be guarded with a getent check " +
			"for hosts without nginx/openresty installed")
	}

	for _, forbidden := range []string{"chmod 777", "chmod -R 777", "chmod 0777", "chmod a+rwx"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("postinst must not widen permissions via %q — use group membership instead", forbidden)
		}
	}
}
