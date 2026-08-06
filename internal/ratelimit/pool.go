package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/local/github-ssh-index/internal/model"
)

// Pool keeps one primary/secondary-rate state per credential. A secondary
// limit on one GitHub user must not reduce every independent credential to the
// same pace. A short global breaker remains for correlated abuse responses.
type Pool struct {
	mu             sync.Mutex
	lanes          []*Pacer
	next           int
	globalCooldown time.Time
	secondaryHitAt []time.Time
}

type LaneSnapshot struct {
	Name string `json:"name"`
	Snapshot
}

type PoolSnapshot struct {
	ConfiguredPerHour int            `json:"configured_per_hour"`
	EffectivePerHour  int            `json:"effective_per_hour"`
	SecondaryStrikes  int            `json:"secondary_strikes"`
	CooldownUntil     *time.Time     `json:"cooldown_until,omitempty"`
	Lanes             []LaneSnapshot `json:"lanes"`
}

func NewPool(count, perHour, reserve int) *Pool {
	if count < 1 {
		count = 1
	}
	result := &Pool{
		lanes: make([]*Pacer, count), secondaryHitAt: make([]time.Time, count),
	}
	for index := range result.lanes {
		result.lanes[index] = New(perHour, reserve)
	}
	return result
}

func (p *Pool) Len() int { return len(p.lanes) }

// Wait reserves the earliest available active credential lane.
func (p *Pool) Wait(ctx context.Context, active func(int) bool) (int, error) {
	p.mu.Lock()
	if len(p.lanes) == 0 {
		p.mu.Unlock()
		return -1, errors.New("rate-limit credential pool is empty")
	}
	chosen := -1
	var earliest time.Time
	for offset := 0; offset < len(p.lanes); offset++ {
		index := (p.next + offset) % len(p.lanes)
		if active != nil && !active(index) {
			continue
		}
		ready := p.lanes[index].ReadyAt(p.globalCooldown)
		if chosen < 0 || ready.Before(earliest) {
			chosen, earliest = index, ready
		}
	}
	if chosen < 0 {
		p.mu.Unlock()
		return -1, errors.New("all rate-limit credential lanes are disabled")
	}
	at := p.lanes[chosen].ReserveAfter(p.globalCooldown)
	p.next = (chosen + 1) % len(p.lanes)
	p.mu.Unlock()
	if err := waitUntil(ctx, at); err != nil {
		return -1, err
	}
	return chosen, nil
}

func (p *Pool) Observe(lane int, rate model.Rate) {
	if lane >= 0 && lane < len(p.lanes) {
		p.lanes[lane].Observe(rate)
	}
}

func (p *Pool) ExtraCost(lane, cost int) {
	if lane >= 0 && lane < len(p.lanes) {
		p.lanes[lane].ExtraCost(cost)
	}
}

func (p *Pool) Cooldown(lane int, wait time.Duration) {
	if lane >= 0 && lane < len(p.lanes) {
		p.lanes[lane].Cooldown(wait)
	}
}

func (p *Pool) SecondaryLimit(lane int, wait time.Duration) {
	if lane < 0 || lane >= len(p.lanes) {
		return
	}
	p.lanes[lane].SecondaryLimit(wait)
	now := time.Now()
	p.mu.Lock()
	p.secondaryHitAt[lane] = now
	correlated := 0
	for index, hit := range p.secondaryHitAt {
		if index != lane && now.Sub(hit) <= 30*time.Second {
			correlated++
		}
	}
	if correlated > 0 {
		if wait < time.Minute {
			wait = time.Minute
		}
		until := now.Add(wait)
		if until.After(p.globalCooldown) {
			p.globalCooldown = until
		}
	}
	p.mu.Unlock()
}

func (p *Pool) Snapshot(active func(int) bool) PoolSnapshot {
	p.mu.Lock()
	globalCooldown := p.globalCooldown
	p.mu.Unlock()
	result := PoolSnapshot{Lanes: make([]LaneSnapshot, 0, len(p.lanes))}
	allCooling := true
	activeCount := 0
	var latest time.Time
	for index, lane := range p.lanes {
		if active != nil && !active(index) {
			continue
		}
		activeCount++
		snapshot := lane.Snapshot()
		result.ConfiguredPerHour += snapshot.ConfiguredPerHour
		result.EffectivePerHour += snapshot.EffectivePerHour
		result.SecondaryStrikes += snapshot.SecondaryStrikes
		result.Lanes = append(result.Lanes, LaneSnapshot{
			Name: fmt.Sprintf("credential_%d", index+1), Snapshot: snapshot,
		})
		if snapshot.CooldownUntil == nil {
			allCooling = false
		} else if snapshot.CooldownUntil.After(latest) {
			latest = *snapshot.CooldownUntil
		}
	}
	now := time.Now()
	if globalCooldown.After(now) {
		value := globalCooldown
		result.CooldownUntil = &value
	} else if activeCount > 0 && allCooling && latest.After(now) {
		result.CooldownUntil = &latest
	}
	return result
}
