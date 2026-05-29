package crowdsec

import (
	"context"
	"errors"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

var ErrNotImplemented = errors.New("crowdsec client not implemented yet")

type ActiveBanSource interface {
	ListActiveBans(ctx context.Context) ([]string, error)
	ListRecentBans(ctx context.Context) ([]models.RecentBan, error)
}

type AllowlistManager interface {
	ListAllowlist(ctx context.Context, name string) ([]models.AllowlistEntry, error)
	AddAllowlistEntry(ctx context.Context, name string, entry models.AllowlistEntry) error
}

type DecisionManager interface {
	AddIPDecision(ctx context.Context, ip, duration, reason string) error
	AddRangeDecision(ctx context.Context, cidr, duration, reason string) error
}

type Client struct {
	// TODO: Integrate with translator and adapter for mutations
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) ListActiveBans(context.Context) ([]string, error) {
	// TODO: run "cscli decisions list -o json" and parse output
	// TODO: apply LOCAL_ORIGINS filter (crowdsec, cscli)
	// TODO: normalize IPv6
	return nil, ErrNotImplemented
}

func (c *Client) ListRecentBans(context.Context) ([]models.RecentBan, error) {
	// TODO: read and parse /var/log/crowdsec/decisions.log
	// TODO: apply cutoff based on duration
	return nil, ErrNotImplemented
}

func (c *Client) ListAllowlist(context.Context, string) ([]models.AllowlistEntry, error) {
	// TODO: run "cscli allowlists inspect <name> -o json" and parse output
	return nil, ErrNotImplemented
}

func (c *Client) AddAllowlistEntry(context.Context, string, models.AllowlistEntry) error {
	// TODO: run "cscli allowlists add <name> <value> --comment <comment>"
	return ErrNotImplemented
}

func (c *Client) AddIPDecision(context.Context, string, string, string) error {
	// TODO: run "cscli decisions add --ip <ip> --duration <duration> --reason <reason> --type ban"
	return ErrNotImplemented
}

func (c *Client) AddRangeDecision(context.Context, string, string, string) error {
	// TODO: run "cscli decisions add --range <cidr> --duration <duration> --reason <reason> --type ban"
	return ErrNotImplemented
}
