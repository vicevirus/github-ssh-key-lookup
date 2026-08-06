package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/local/github-ssh-index/internal/model"
)

type Pacer struct {
	mu                sync.Mutex
	baseInterval      time.Duration
	interval          time.Duration
	next              time.Time
	cooldown          time.Time
	reserve           int
	secondaryStrikes  int
	successesSinceHit int
	lastSecondary     time.Time
}

type Snapshot struct {
	ConfiguredPerHour int        `json:"configured_per_hour"`
	EffectivePerHour  int        `json:"effective_per_hour"`
	SecondaryStrikes  int        `json:"secondary_strikes"`
	CooldownUntil     *time.Time `json:"cooldown_until,omitempty"`
}

func New(perHour, reserve int) *Pacer {
	if perHour < 1 {
		perHour = 1
	}
	interval := time.Hour / time.Duration(perHour)
	return &Pacer{baseInterval: interval, interval: interval, reserve: reserve}
}

func (p *Pacer) Wait(ctx context.Context) error {
	at := p.ReserveAfter(time.Time{})
	return waitUntil(ctx, at)
}

// ReadyAt reports when a new reservation could start without mutating the
// pacer. Pool uses this to choose the credential lane that can run first.
func (p *Pacer) ReadyAt(notBefore time.Time) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	at := p.next
	if at.Before(now) {
		at = now
	}
	if at.Before(p.cooldown) {
		at = p.cooldown
	}
	if at.Before(notBefore) {
		at = notBefore
	}
	return at
}

// ReserveAfter atomically reserves one request slot at or after notBefore.
func (p *Pacer) ReserveAfter(notBefore time.Time) time.Time {
	p.mu.Lock()
	now := time.Now()
	at := p.next
	if at.Before(now) {
		at = now
	}
	if at.Before(p.cooldown) {
		at = p.cooldown
	}
	if at.Before(notBefore) {
		at = notBefore
	}
	p.next = at.Add(p.interval)
	p.mu.Unlock()
	return at
}

func waitUntil(ctx context.Context, at time.Time) error {
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *Pacer) Observe(rate model.Rate) {
	p.mu.Lock()
	if p.secondaryStrikes > 0 {
		p.successesSinceHit++
		if p.successesSinceHit >= 1_000 {
			p.secondaryStrikes--
			p.successesSinceHit = 0
			p.interval = p.baseInterval * time.Duration(1<<p.secondaryStrikes)
		}
	}
	p.mu.Unlock()
	if rate.Limit == 0 || rate.Remaining > p.reserve || rate.ResetAt.IsZero() {
		return
	}
	p.Cooldown(time.Until(rate.ResetAt) + time.Second)
}

func (p *Pacer) SecondaryLimit(minimumWait time.Duration) {
	if minimumWait < time.Minute {
		minimumWait = time.Minute
	}
	p.mu.Lock()
	now := time.Now()
	if now.Sub(p.lastSecondary) >= 30*time.Second {
		if p.secondaryStrikes < 3 {
			p.secondaryStrikes++
		}
		p.lastSecondary = now
	}
	p.successesSinceHit = 0
	p.interval = p.baseInterval * time.Duration(1<<p.secondaryStrikes)
	effectiveStrike := max(1, p.secondaryStrikes)
	wait := minimumWait * time.Duration(1<<(effectiveStrike-1))
	if wait > 15*time.Minute {
		wait = 15 * time.Minute
	}
	until := now.Add(wait)
	if until.After(p.cooldown) {
		p.cooldown = until
	}
	p.mu.Unlock()
}

func (p *Pacer) ExtraCost(cost int) {
	if cost <= 1 {
		return
	}
	p.mu.Lock()
	p.next = p.next.Add(time.Duration(cost-1) * p.interval)
	p.mu.Unlock()
}

func (p *Pacer) Cooldown(wait time.Duration) {
	if wait <= 0 {
		return
	}
	p.mu.Lock()
	until := time.Now().Add(wait)
	if until.After(p.cooldown) {
		p.cooldown = until
	}
	p.mu.Unlock()
}

func (p *Pacer) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	var cooldown *time.Time
	if p.cooldown.After(time.Now()) {
		value := p.cooldown
		cooldown = &value
	}
	return Snapshot{
		ConfiguredPerHour: int(time.Hour / p.baseInterval),
		EffectivePerHour:  int(time.Hour / p.interval),
		SecondaryStrikes:  p.secondaryStrikes,
		CooldownUntil:     cooldown,
	}
}
