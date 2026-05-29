package recidive

import (
	"context"
	"errors"
	"time"
)

var ErrNotImplemented = errors.New("recidive service not implemented yet")

type Record struct {
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

type Service interface {
	Run(ctx context.Context) error
}

type PlaceholderService struct{}

func NewPlaceholderService() *PlaceholderService {
	return &PlaceholderService{}
}

func (s *PlaceholderService) Run(context.Context) error {
	// TODO: monitor recent local bans
	// TODO: update recidivists.json state
	// TODO: escalate bans (2nd -> 24h, 3rd+ -> 7d) via cscli
	return ErrNotImplemented
}
