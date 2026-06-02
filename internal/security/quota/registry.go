package quota

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Transition captures the state change triggered by a new observation.
type Transition struct {
	Previous State
	Current  State
}

// Registry stores the latest quota observation per provider.
type Registry struct {
	mu    sync.RWMutex
	items map[string]Observation
}

type TransitionHook func(obs Observation, transition Transition)

var defaultRegistry = NewRegistry()

var (
	hookMu sync.RWMutex
	hook   TransitionHook
)

func NewRegistry() *Registry {
	return &Registry{items: make(map[string]Observation)}
}

func DefaultRegistry() *Registry { return defaultRegistry }

func normalizeProvider(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func (r *Registry) Record(obs Observation) Transition {
	if r == nil {
		return Transition{Previous: Unknown, Current: Unknown}
	}
	obs = ClassifyObservation(obs)
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now().UTC()
	}
	key := normalizeProvider(obs.Provider)
	r.mu.Lock()
	prev := Unknown
	if existing, ok := r.items[key]; ok {
		prev = existing.State
	}
	r.items[key] = obs.clone()
	transition := Transition{Previous: prev, Current: obs.State}
	r.mu.Unlock()
	updateMetrics(obs, transition)
	if current := currentTransitionHook(); current != nil {
		safeInvokeTransitionHook(current, obs.clone(), transition)
	}
	return transition
}

func (r *Registry) Get(provider string) (Observation, bool) {
	if r == nil {
		return Observation{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	obs, ok := r.items[normalizeProvider(provider)]
	if !ok {
		return Observation{}, false
	}
	return obs.clone(), true
}

// State returns the current quota state for a provider when known.
func (r *Registry) State(provider string) (State, bool) {
	obs, ok := r.Get(provider)
	if !ok {
		return Unknown, false
	}
	return obs.State, true
}

func (r *Registry) Snapshot() []Observation {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.items))
	for k := range r.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Observation, 0, len(keys))
	for _, k := range keys {
		out = append(out, r.items[k].clone())
	}
	return out
}

func ResetDefaultRegistry() {
	defaultRegistry = NewRegistry()
}

func SetTransitionHook(h TransitionHook) {
	hookMu.Lock()
	hook = h
	hookMu.Unlock()
}

func ResetTransitionHook() {
	SetTransitionHook(nil)
}

func currentTransitionHook() TransitionHook {
	hookMu.RLock()
	defer hookMu.RUnlock()
	return hook
}

func safeInvokeTransitionHook(h TransitionHook, obs Observation, transition Transition) {
	defer func() {
		_ = recover()
	}()
	h(obs, transition)
}
