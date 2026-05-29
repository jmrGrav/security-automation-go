package betterstack

import "time"

type Event struct {
	Message   string
	Source    string
	Level     string
	Timestamp time.Time
	Payload   map[string]any
}
