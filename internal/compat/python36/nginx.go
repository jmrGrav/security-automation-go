package python36

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	openrestyadapter "github.com/jm/security-automation-go/internal/adapters/openresty"
)

var (
	legacySharedDictPattern  = regexp.MustCompile(`(?m)^\s*lua_shared_dict\s+([A-Za-z0-9_]+)\s+([0-9]+[kKmMgG]?)\s*;`)
	legacyPackagePathPattern = regexp.MustCompile(`(?m)^\s*lua_package_path\s+"([^"]+)"\s*;`)
	legacyRequirePattern     = regexp.MustCompile(`(?m)^\s*require\s+"([^"]+)"`)
)

func ProjectOpenRestyContract(env map[string]string, generatedConf []byte) (openrestyadapter.Contract, []string, error) {
	dictMatches := legacySharedDictPattern.FindAllSubmatch(generatedConf, -1)
	if len(dictMatches) == 0 {
		return openrestyadapter.Contract{}, nil, fmt.Errorf("project openresty contract: no lua_shared_dict found")
	}

	sharedDicts := make([]openrestyadapter.SharedDict, 0, len(dictMatches))
	for _, match := range dictMatches {
		sizeBytes, err := parseNginxSize(string(match[2]))
		if err != nil {
			return openrestyadapter.Contract{}, nil, err
		}
		sharedDicts = append(sharedDicts, openrestyadapter.SharedDict{
			Name:      string(match[1]),
			SizeBytes: sizeBytes,
		})
	}

	pathMatch := legacyPackagePathPattern.FindSubmatch(generatedConf)
	if pathMatch == nil {
		return openrestyadapter.Contract{}, nil, fmt.Errorf("project openresty contract: lua_package_path not found")
	}

	moduleMatches := legacyRequirePattern.FindAllSubmatch(generatedConf, -1)
	modules := make([]string, 0, len(moduleMatches))
	seen := make(map[string]struct{}, len(moduleMatches))
	for _, match := range moduleMatches {
		mod := string(match[1])
		if _, ok := seen[mod]; ok {
			continue
		}
		seen[mod] = struct{}{}
		modules = append(modules, mod)
	}

	statusURL := env["LUA_STATUS_URL"]
	warnings := []string{}
	if strings.TrimSpace(statusURL) == "" {
		statusURL = "http://127.0.0.1:8091/crowdsec-status"
		warnings = append(warnings, "LUA_STATUS_URL missing; using Python default")
	}

	cfg := openrestyadapter.Contract{
		SchemaVersion:     openrestyadapter.SchemaVersion,
		ServiceName:       "crowdsec-openresty",
		LuaPackagePath:    string(pathMatch[1]),
		SharedDicts:       sharedDicts,
		InitModules:       modules,
		WorkerSyncEnabled: strings.Contains(string(generatedConf), `require("crowdsec.sync").start()`),
		StatusEndpoint:    statusURL,
		Includes: []string{
			"/etc/nginx/snippets/crowdsec_access.conf",
			"/etc/nginx/snippets/crowdsec_status.conf",
		},
	}

	if err := openrestyadapter.Validate(cfg); err != nil {
		return openrestyadapter.Contract{}, nil, err
	}
	return cfg, warnings, nil
}

func parseNginxSize(raw string) (int64, error) {
	if raw == "" {
		return 0, fmt.Errorf("invalid nginx size: empty")
	}

	multiplier := int64(1)
	value := raw
	switch suffix := raw[len(raw)-1]; suffix {
	case 'k', 'K':
		multiplier = 1024
		value = raw[:len(raw)-1]
	case 'm', 'M':
		multiplier = 1024 * 1024
		value = raw[:len(raw)-1]
	case 'g', 'G':
		multiplier = 1024 * 1024 * 1024
		value = raw[:len(raw)-1]
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid nginx size %q: %w", raw, err)
	}
	return n * multiplier, nil
}
