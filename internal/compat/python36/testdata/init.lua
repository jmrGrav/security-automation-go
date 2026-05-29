local M = {}
M.SYNC_FILE   = "/run/crowdsec-lua/bans.json"
M.EVENTS_FILE = "/run/crowdsec-lua/events.jsonl"
M.SYNC_INTERVAL    = 5
M.MAX_TARPITS      = 20
M.HEURISTIC_TTL    = 7200
M.BURST_WINDOW     = 60
M.BURST_THRESHOLD  = 120
M.FAIL_OPEN = true
M.DEADMAN_SECS        = 120
M.MEM_PRESSURE_PCT    = 90
return M
