package models

import "time"

type Decision struct {
	Origin    string
	Type      string
	Scope     string
	Value     string
	Scenario  string
	ID        string
	CreatedAt time.Time
}

type AllowlistEntry struct {
	Value   string
	Comment string
}

type RecentBan struct {
	IP       string
	Scenario string
	Origin   string
	When     time.Time
	ID       string
}
