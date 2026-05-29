package python36

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyProjection(t *testing.T) {
	base := filepath.Join("testdata")
	envData, err := os.ReadFile(filepath.Join(base, "python36.env"))
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	nginxData, err := os.ReadFile(filepath.Join(base, "crowdsec_cf_sync_generated.conf"))
	if err != nil {
		t.Fatalf("read nginx: %v", err)
	}
	luaData, err := os.ReadFile(filepath.Join(base, "init.lua"))
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}

	envMap, err := ParseEnvFile(envData)
	if err != nil {
		t.Fatalf("parse env: %v", err)
	}
	openrestyCfg, warnings, err := ProjectOpenRestyContract(envMap, nginxData)
	if err != nil {
		t.Fatalf("project openresty: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected openresty warnings: %v", warnings)
	}
	if len(openrestyCfg.SharedDicts) != 3 {
		t.Fatalf("unexpected shared dict count: %d", len(openrestyCfg.SharedDicts))
	}

	luaCfg, warnings, err := ProjectLuaContract(envMap, luaData)
	if err != nil {
		t.Fatalf("project lua: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected lua warnings: %v", warnings)
	}
	if luaCfg.SyncDir != "/run/crowdsec-lua" {
		t.Fatalf("unexpected lua sync dir: %s", luaCfg.SyncDir)
	}
}
