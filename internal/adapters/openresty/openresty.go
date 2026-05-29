// Package openresty defines a narrow adapter boundary for OpenResty-facing
// configuration. This package is intentionally limited to contract parsing,
// validation, and event projection so the central runtime does not absorb
// nginx/OpenResty-specific semantics.
package openresty

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
)

const SchemaVersion = "v1"

type SharedDict struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
}

type Contract struct {
	SchemaVersion     string       `json:"schema_version"`
	ServiceName       string       `json:"service_name"`
	LuaPackagePath    string       `json:"lua_package_path"`
	SharedDicts       []SharedDict `json:"shared_dicts"`
	InitModules       []string     `json:"init_modules"`
	WorkerSyncEnabled bool         `json:"worker_sync_enabled"`
	StatusEndpoint    string       `json:"status_endpoint"`
	Includes          []string     `json:"includes"`
}

type Summary struct {
	SharedDictCount int    `json:"shared_dict_count"`
	ModuleCount     int    `json:"module_count"`
	StatusEndpoint  string `json:"status_endpoint"`
}

type RenderedBundle struct {
	GeneratedConf string `json:"generated_conf"`
	AccessSnippet string `json:"access_snippet"`
	StatusSnippet string `json:"status_snippet"`
}

func Parse(data []byte) (Contract, error) {
	var cfg Contract

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Contract{}, fmt.Errorf("decode openresty contract: %w", err)
	}
	if dec.More() {
		return Contract{}, errors.New("decode openresty contract: trailing JSON content")
	}
	if err := Validate(cfg); err != nil {
		return Contract{}, err
	}
	return cfg, nil
}

func Validate(cfg Contract) error {
	if cfg.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported openresty schema version %q", cfg.SchemaVersion)
	}
	if strings.TrimSpace(cfg.ServiceName) == "" {
		return errors.New("openresty service_name is required")
	}
	if strings.TrimSpace(cfg.LuaPackagePath) == "" {
		return errors.New("openresty lua_package_path is required")
	}
	if len(cfg.SharedDicts) == 0 {
		return errors.New("openresty shared_dicts must not be empty")
	}
	seenDicts := make(map[string]struct{}, len(cfg.SharedDicts))
	for _, dict := range cfg.SharedDicts {
		name := strings.TrimSpace(dict.Name)
		if name == "" {
			return errors.New("openresty shared_dicts name is required")
		}
		if dict.SizeBytes <= 0 {
			return fmt.Errorf("openresty shared_dict %q size_bytes must be positive", name)
		}
		if _, ok := seenDicts[name]; ok {
			return fmt.Errorf("openresty shared_dict %q is duplicated", name)
		}
		seenDicts[name] = struct{}{}
	}
	seenModules := make(map[string]struct{}, len(cfg.InitModules))
	for _, module := range cfg.InitModules {
		module = strings.TrimSpace(module)
		if module == "" {
			return errors.New("openresty init_modules contains an empty module")
		}
		if _, ok := seenModules[module]; ok {
			return fmt.Errorf("openresty init module %q is duplicated", module)
		}
		seenModules[module] = struct{}{}
	}
	if strings.TrimSpace(cfg.StatusEndpoint) == "" {
		return errors.New("openresty status_endpoint is required")
	}
	if _, err := url.ParseRequestURI(cfg.StatusEndpoint); err != nil {
		return fmt.Errorf("openresty status_endpoint is invalid: %w", err)
	}
	for _, include := range cfg.Includes {
		if strings.TrimSpace(include) == "" {
			return errors.New("openresty includes contains an empty path")
		}
	}
	return nil
}

func Summarize(cfg Contract) Summary {
	return Summary{
		SharedDictCount: len(cfg.SharedDicts),
		ModuleCount:     len(cfg.InitModules),
		StatusEndpoint:  cfg.StatusEndpoint,
	}
}

func RuntimeEvents(_ context.Context, cfg Contract, scopeID, correlationID string, now time.Time) []events.PublishRequest {
	ts := now.UTC()
	summary := Summarize(cfg)

	meta := map[string]any{
		"adapter":         "openresty",
		"schema_version":  cfg.SchemaVersion,
		"service_name":    cfg.ServiceName,
		"worker_sync":     cfg.WorkerSyncEnabled,
		"shared_dicts":    summary.SharedDictCount,
		"init_modules":    summary.ModuleCount,
		"status_endpoint": summary.StatusEndpoint,
	}

	return []events.PublishRequest{
		{
			Timestamp:     ts,
			Category:      events.CategorySecurity,
			Type:          "openresty_contract_loaded",
			CorrelationID: correlationID,
			Actor:         "adapter/openresty",
			ScopeID:       scopeID,
			Payload: map[string]any{
				"service_name":        cfg.ServiceName,
				"lua_package_path":    cfg.LuaPackagePath,
				"worker_sync_enabled": cfg.WorkerSyncEnabled,
			},
			Metadata: meta,
		},
		{
			Timestamp:     ts,
			Category:      events.CategorySecurity,
			Type:          "openresty_shared_dicts_declared",
			CorrelationID: correlationID,
			Actor:         "adapter/openresty",
			ScopeID:       scopeID,
			Payload: map[string]any{
				"shared_dicts": cfg.SharedDicts,
			},
			Metadata: meta,
		},
	}
}

func RenderDryRun(cfg Contract) (RenderedBundle, error) {
	if err := Validate(cfg); err != nil {
		return RenderedBundle{}, err
	}

	var conf strings.Builder
	conf.WriteString("# crowdsec-openresty dry-run generated configuration\n")
	for _, dict := range cfg.SharedDicts {
		conf.WriteString("lua_shared_dict ")
		conf.WriteString(dict.Name)
		conf.WriteString(" ")
		conf.WriteString(formatNginxSize(dict.SizeBytes))
		conf.WriteString(";\n")
	}
	conf.WriteString("\n")
	conf.WriteString("lua_package_path ")
	conf.WriteString(strconv.Quote(cfg.LuaPackagePath))
	conf.WriteString(";\n\n")
	conf.WriteString("init_by_lua_block {\n")
	for _, module := range cfg.InitModules {
		conf.WriteString("    require ")
		conf.WriteString(strconv.Quote(module))
		conf.WriteString("\n")
	}
	conf.WriteString("}\n")
	if cfg.WorkerSyncEnabled {
		conf.WriteString("\ninit_worker_by_lua_block {\n")
		conf.WriteString("    require(\"crowdsec.sync\").start()\n")
		conf.WriteString("}\n")
	}

	statusPath := "/crowdsec-status"
	if u, err := url.Parse(cfg.StatusEndpoint); err == nil && strings.TrimSpace(u.Path) != "" {
		statusPath = u.Path
	}
	metricsPath := strings.TrimSuffix(statusPath, "-status") + "-metrics"
	if metricsPath == statusPath {
		metricsPath = "/crowdsec-metrics"
	}

	return RenderedBundle{
		GeneratedConf: conf.String(),
		AccessSnippet: "access_by_lua_block {\n    require(\"crowdsec.access\").check()\n}\n",
		StatusSnippet: "location = " + statusPath + " {\n" +
			"    allow 127.0.0.1;\n" +
			"    deny  all;\n" +
			"    access_log off;\n" +
			"    content_by_lua_block {\n" +
			"        require(\"crowdsec.metrics\").handle()\n" +
			"    }\n" +
			"}\n\n" +
			"location = " + metricsPath + " {\n" +
			"    allow 127.0.0.1;\n" +
			"    deny  all;\n" +
			"    access_log off;\n" +
			"    content_by_lua_block {\n" +
			"        require(\"crowdsec.metrics\").handle_prometheus()\n" +
			"    }\n" +
			"}\n",
	}, nil
}

func formatNginxSize(sizeBytes int64) string {
	switch {
	case sizeBytes%(1024*1024*1024) == 0:
		return strconv.FormatInt(sizeBytes/(1024*1024*1024), 10) + "g"
	case sizeBytes%(1024*1024) == 0:
		return strconv.FormatInt(sizeBytes/(1024*1024), 10) + "m"
	case sizeBytes%1024 == 0:
		return strconv.FormatInt(sizeBytes/1024, 10) + "k"
	default:
		return strconv.FormatInt(sizeBytes, 10)
	}
}
