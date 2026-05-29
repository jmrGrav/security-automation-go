package modsecurity

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("modsecurity service not implemented yet")

type Event struct {
	IP    string
	Score int
	URI   string
}

type Service interface {
	Run(ctx context.Context) error
}

type PlaceholderService struct{}

func NewPlaceholderService() *PlaceholderService {
	return &PlaceholderService{}
}

func (s *PlaceholderService) Run(context.Context) error {
	// TODO: parse /var/log/nginx/error.log for ModSecurity events
	// TODO: filter by score >= 5
	// TODO: report to AbuseIPDB
	// TODO: add 2h CF ban
	return ErrNotImplemented
}
