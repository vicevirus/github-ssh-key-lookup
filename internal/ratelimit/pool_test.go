package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestPoolSecondaryLimitIsolatesCredential(t *testing.T) {
	pool := NewPool(2, 4_700, 200)
	active := func(int) bool { return true }
	pool.SecondaryLimit(0, time.Minute)
	snapshot := pool.Snapshot(active)
	if snapshot.ConfiguredPerHour != 9_400 || snapshot.EffectivePerHour != 7_050 {
		t.Fatalf("one lane throttled every credential: %#v", snapshot)
	}
	if snapshot.SecondaryStrikes != 1 || snapshot.CooldownUntil != nil {
		t.Fatalf("unexpected isolated cooldown state: %#v", snapshot)
	}
	if len(snapshot.Lanes) != 2 || snapshot.Lanes[0].EffectivePerHour != 2_350 ||
		snapshot.Lanes[1].EffectivePerHour != 4_700 {
		t.Fatalf("lane state was not isolated: %#v", snapshot.Lanes)
	}
}

func TestPoolCorrelatedSecondaryLimitsOpenGlobalBreaker(t *testing.T) {
	pool := NewPool(2, 4_700, 200)
	pool.SecondaryLimit(0, time.Minute)
	pool.SecondaryLimit(1, time.Minute)
	if snapshot := pool.Snapshot(func(int) bool { return true }); snapshot.CooldownUntil == nil {
		t.Fatalf("correlated limits did not open global breaker: %#v", snapshot)
	}
}

func TestPoolWaitSkipsInactiveCredential(t *testing.T) {
	pool := NewPool(2, 3_600_000, 0)
	lane, err := pool.Wait(context.Background(), func(index int) bool { return index == 1 })
	if err != nil || lane != 1 {
		t.Fatalf("inactive credential selected: lane=%d err=%v", lane, err)
	}
}
