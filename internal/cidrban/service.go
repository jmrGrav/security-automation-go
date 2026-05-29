package cidrban

import (
	"context"
	"errors"
	"time"
)

var ErrNotImplemented = errors.New("cidrban service not implemented yet")

type Record struct {
	IPs      []string  `json:"ips"`
	BannedAt time.Time `json:"banned_at"`
}

type Service interface {
	Run(ctx context.Context) error
}

type PlaceholderService struct{}

func NewPlaceholderService() *PlaceholderService {
	return &PlaceholderService{}
}

func (s *PlaceholderService) Run(context.Context) error {
	// TODO: monitor local bans on 7d window
	// TODO: group by /24
	// TODO: if 2+ IPs, ban /24 for 24h in CF and CrowdSec
	// TODO: update cidr-banned.json state
	return ErrNotImplemented
}
