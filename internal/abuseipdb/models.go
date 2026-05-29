package abuseipdb

import "time"

type Report struct {
	IP         string
	Categories string
	Comment    string
	Timestamp  time.Time
}
