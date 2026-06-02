package router

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
)

// Selector chooses a read-only AI provider based on quota posture and preference.
type Selector interface {
	SelectProvider(ctx context.Context, req ai.ExplainRequest) (providers.Provider, aiquota.ProviderQuota, error)
}

// StaticSelector chooses among a fixed provider list.
type StaticSelector struct {
	Providers []providers.Provider
	Quota     aiquota.Registry
}

var providerRotation uint64

type enabledProvider interface {
	Enabled() bool
}

// SelectProvider applies preference, exclusion, and quota ranking rules.
func (s StaticSelector) SelectProvider(ctx context.Context, req ai.ExplainRequest) (providers.Provider, aiquota.ProviderQuota, error) {
	candidates := s.availableProviders(req)
	if len(candidates) == 0 {
		return nil, aiquota.ProviderQuota{State: aiquota.Unknown}, nil
	}
	if pref := strings.ToLower(strings.TrimSpace(req.ProviderPreference)); pref != "" && pref != "auto" {
		for _, p := range candidates {
			if providerName(p) == pref {
				return p, quotaFor(s.Quota, providerName(p)), nil
			}
		}
		return nil, aiquota.ProviderQuota{State: aiquota.Unknown}, errors.New("preferred provider unavailable")
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		qi := quotaFor(s.Quota, providerName(candidates[i]))
		qj := quotaFor(s.Quota, providerName(candidates[j]))
		return betterQuota(qi, qj)
	})
	chosen := rotateTopCandidates(candidates, s.Quota)
	return chosen, quotaFor(s.Quota, providerName(chosen)), nil
}

func (s StaticSelector) availableProviders(req ai.ExplainRequest) []providers.Provider {
	out := make([]providers.Provider, 0, len(s.Providers))
	now := time.Now().UTC()
	for _, p := range s.Providers {
		if p == nil {
			continue
		}
		if enabler, ok := p.(enabledProvider); ok && !enabler.Enabled() {
			continue
		}
		q := quotaFor(s.Quota, providerName(p))
		if !aiquota.CanUseAt(q, now) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func providerName(p providers.Provider) string {
	if p == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(string(p.Name())))
}

func quotaFor(reg aiquota.Registry, provider string) aiquota.ProviderQuota {
	if reg == nil {
		return aiquota.ProviderQuota{Provider: provider, State: aiquota.Unknown}
	}
	if quota, ok := reg.Get(provider); ok {
		return quota
	}
	return aiquota.ProviderQuota{Provider: provider, State: aiquota.Unknown}
}

func betterQuota(a, b aiquota.ProviderQuota) bool {
	priority := func(q aiquota.ProviderQuota) int {
		switch q.State {
		case aiquota.Normal:
			return 5
		case aiquota.Warning:
			return 4
		case aiquota.Throttled:
			return 3
		case aiquota.Unknown:
			return 2
		default:
			return 1
		}
	}
	if pa, pb := priority(a), priority(b); pa != pb {
		return pa > pb
	}
	if a.State == aiquota.Normal && b.State == aiquota.Normal {
		if a.LastObservedAt.Equal(b.LastObservedAt) {
			return a.Provider < b.Provider
		}
		return a.LastObservedAt.After(b.LastObservedAt)
	}
	if a.TokensRemain != b.TokensRemain {
		return a.TokensRemain > b.TokensRemain
	}
	return a.RequestsRemain > b.RequestsRemain
}

func rotateTopCandidates(candidates []providers.Provider, reg aiquota.Registry) providers.Provider {
	if len(candidates) == 0 {
		return nil
	}
	topQuota := quotaFor(reg, providerName(candidates[0]))
	topPriority := quotaPriority(topQuota)
	top := make([]providers.Provider, 0, len(candidates))
	for _, p := range candidates {
		if quotaPriority(quotaFor(reg, providerName(p))) != topPriority {
			break
		}
		top = append(top, p)
	}
	if len(top) == 0 {
		return candidates[0]
	}
	if len(top) == 1 {
		return top[0]
	}
	idx := atomic.AddUint64(&providerRotation, 1)
	return top[int(idx-1)%len(top)]
}

func quotaPriority(q aiquota.ProviderQuota) int {
	switch q.State {
	case aiquota.Normal:
		return 5
	case aiquota.Warning:
		return 4
	case aiquota.Throttled:
		return 3
	case aiquota.Unknown:
		return 2
	default:
		return 1
	}
}
