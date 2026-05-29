package openresty

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAndRuntimeEvents(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "contract.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	now := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	evs := RuntimeEvents(context.Background(), cfg, "scope-a", "corr-1", now)
	if len(evs) != 2 {
		t.Fatalf("unexpected event count: %d", len(evs))
	}
	if evs[0].Type != "openresty_contract_loaded" {
		t.Fatalf("unexpected first event type: %s", evs[0].Type)
	}
	if !evs[0].Timestamp.Equal(now) {
		t.Fatalf("unexpected timestamp: %s", evs[0].Timestamp)
	}
}

func TestRenderDryRun(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "contract.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rendered, err := RenderDryRun(cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(rendered.GeneratedConf, "lua_shared_dict cscf_verdicts 50m;") {
		t.Fatalf("unexpected generated conf:\n%s", rendered.GeneratedConf)
	}
	if !strings.Contains(rendered.AccessSnippet, `require("crowdsec.access").check()`) {
		t.Fatalf("unexpected access snippet:\n%s", rendered.AccessSnippet)
	}
}

func TestValidateRejectsDuplicateSharedDict(t *testing.T) {
	cfg := Contract{
		SchemaVersion:  SchemaVersion,
		ServiceName:    "edge",
		LuaPackagePath: "/etc/openresty/lua/?.lua;;",
		SharedDicts: []SharedDict{
			{Name: "crowdsec", SizeBytes: 1},
			{Name: "crowdsec", SizeBytes: 2},
		},
		StatusEndpoint: "http://127.0.0.1/status",
	}

	if err := Validate(cfg); err == nil {
		t.Fatal("expected duplicate shared_dict validation error")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	data := []byte(`{
		"schema_version":"v1",
		"service_name":"edge",
		"lua_package_path":"/etc/openresty/lua/?.lua;;",
		"shared_dicts":[{"name":"crowdsec","size_bytes":1}],
		"init_modules":[],
		"worker_sync_enabled":true,
		"status_endpoint":"http://127.0.0.1/status",
		"unexpected":true
	}`)

	if _, err := Parse(data); err == nil {
		t.Fatal("expected unknown field error")
	}
}
