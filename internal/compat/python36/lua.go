package python36

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	luaadapter "github.com/jm/security-automation-go/internal/adapters/lua"
)

var (
	luaStringConstPattern = regexp.MustCompile(`(?m)^M\.([A-Z0-9_]+)\s*=\s*"([^"]*)"`)
	luaIntConstPattern    = regexp.MustCompile(`(?m)^M\.([A-Z0-9_]+)\s*=\s*([0-9]+)`)
	luaBoolConstPattern   = regexp.MustCompile(`(?m)^M\.([A-Z0-9_]+)\s*=\s*(true|false)`)
)

func ProjectLuaContract(env map[string]string, initLua []byte) (luaadapter.Contract, []string, error) {
	stringsMap := map[string]string{}
	for _, match := range luaStringConstPattern.FindAllSubmatch(initLua, -1) {
		stringsMap[string(match[1])] = string(match[2])
	}
	intsMap := map[string]int{}
	for _, match := range luaIntConstPattern.FindAllSubmatch(initLua, -1) {
		n, err := strconv.Atoi(string(match[2]))
		if err != nil {
			return luaadapter.Contract{}, nil, fmt.Errorf("project lua contract: %w", err)
		}
		intsMap[string(match[1])] = n
	}
	boolsMap := map[string]bool{}
	for _, match := range luaBoolConstPattern.FindAllSubmatch(initLua, -1) {
		boolsMap[string(match[1])] = string(match[2]) == "true"
	}

	syncDir := strings.TrimSpace(env["LUA_SYNC_DIR"])
	warnings := []string{}
	if syncDir == "" {
		syncDir = "/run/crowdsec-lua"
		warnings = append(warnings, "LUA_SYNC_DIR missing; using Python default")
	}

	cfg := luaadapter.Contract{
		SchemaVersion:    luaadapter.SchemaVersion,
		SyncDir:          syncDir,
		SyncFile:         firstNonEmpty(stringsMap["SYNC_FILE"], syncDir+"/bans.json"),
		EventsFile:       firstNonEmpty(stringsMap["EVENTS_FILE"], syncDir+"/events.jsonl"),
		FailOpen:         boolsMap["FAIL_OPEN"],
		SyncIntervalSecs: intsMap["SYNC_INTERVAL"],
		HeuristicTTLSecs: intsMap["HEURISTIC_TTL"],
		BurstWindowSecs:  intsMap["BURST_WINDOW"],
		BurstThreshold:   intsMap["BURST_THRESHOLD"],
		DeadmanSecs:      intsMap["DEADMAN_SECS"],
		MaxTarpits:       intsMap["MAX_TARPITS"],
		MemoryPressure:   intsMap["MEM_PRESSURE_PCT"],
	}
	if err := luaadapter.Validate(cfg); err != nil {
		return luaadapter.Contract{}, nil, err
	}
	return cfg, warnings, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
