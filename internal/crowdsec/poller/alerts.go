package poller

import (
	"encoding/json"
	"fmt"
)

func parseAlerts(data []byte) ([]LAPIAlert, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var alerts []LAPIAlert
	if err := json.Unmarshal(data, &alerts); err != nil {
		return nil, fmt.Errorf("parse alerts: %w", err)
	}
	return alerts, nil
}
