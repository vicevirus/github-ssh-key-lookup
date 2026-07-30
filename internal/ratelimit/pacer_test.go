package ratelimit

import (
	"testing"
	"time"

	"github.com/local/github-ssh-index/internal/model"
)

func TestSecondaryLimitSlowsAndSuccessfulRequestsRecover(t *testing.T) {
	pacer := New(3_600, 100)
	base := pacer.interval
	pacer.SecondaryLimit(time.Minute)
	if pacer.interval != 2*base || pacer.secondaryStrikes != 1 {
		t.Fatalf("first secondary limit did not halve rate: %#v", pacer)
	}
	pacer.SecondaryLimit(time.Minute)
	if pacer.interval != 2*base || pacer.secondaryStrikes != 1 {
		t.Fatalf("concurrent secondary signals were not debounced: %#v", pacer)
	}
	pacer.lastSecondary = time.Now().Add(-31 * time.Second)
	pacer.SecondaryLimit(time.Minute)
	if pacer.interval != 4*base || pacer.secondaryStrikes != 2 {
		t.Fatalf("second secondary limit did not halve rate again: %#v", pacer)
	}
	for index := 0; index < 1_000; index++ {
		pacer.Observe(model.Rate{})
	}
	if pacer.interval != 2*base || pacer.secondaryStrikes != 1 {
		t.Fatalf("successful requests did not cautiously restore rate: %#v", pacer)
	}
}
