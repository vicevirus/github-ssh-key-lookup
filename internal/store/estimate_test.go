package store

import "testing"

func TestEstimatePhasedCompletionDoesNotApplyRESTDrainRateToEveryAccount(t *testing.T) {
	estimate, ok := estimatePhasedCompletion(phaseEstimateInput{
		EnumeratedUsers:            27_918_819,
		AttemptedUsers:             27_918_819,
		ProcessedUsers:             27_141_757,
		InaccessibleUsers:          3_626_339,
		RESTFallbackUsers:          769_639,
		RemainingShardIDs:          58_392_836,
		ObservedShardIDs:           10_000_000,
		ObservedShardUsers:         8_928_904,
		RESTPerHour:                9_400,
		GraphQLPerHour:             9_400,
		EnumerationUsersPerRequest: 90,
		GraphQLUsersPerRequest:     100,
		RESTRequestsPerFallback:    1,
		EnumerationRESTShare:       2.0 / 3.0,
	})
	if !ok {
		t.Fatal("phase-aware estimate unavailable")
	}
	if estimate.EstimatedFutureUsersLow < 52_000_000 ||
		estimate.EstimatedFutureUsersLow > 52_200_000 {
		t.Fatalf("unexpected future-user estimate: %#v", estimate)
	}
	if estimate.RemainingHoursLow < 900 || estimate.RemainingHoursLow > 1_200 {
		t.Fatalf("early estimate should be measured in weeks, not 2027: %#v", estimate)
	}
	if estimate.RemainingHoursHigh <= estimate.RemainingHoursLow ||
		estimate.RemainingHoursHigh > 1_600 {
		t.Fatalf("unexpected late estimate: %#v", estimate)
	}
	if estimate.RESTHoursLow <= estimate.GraphQLHoursLow {
		t.Fatalf("REST should be the measured bottleneck: %#v", estimate)
	}
	if estimate.EffectiveUsersPerHour < 40_000 || estimate.EffectiveUsersPerHour > 70_000 {
		t.Fatalf("unexpected sustainable throughput: %#v", estimate)
	}
	if estimate.FastScanHoursLow < 80 || estimate.FastScanHoursLow > 110 {
		t.Fatalf("fast scan should finish in roughly four days: %#v", estimate)
	}
	if estimate.FastScanHoursHigh <= estimate.FastScanHoursLow || estimate.FastScanHoursHigh > 130 {
		t.Fatalf("unexpected conservative fast-scan estimate: %#v", estimate)
	}
}

func TestEstimatePhasedCompletionUsesExactFallbackDrainAfterEnumeration(t *testing.T) {
	estimate, ok := estimatePhasedCompletion(phaseEstimateInput{
		EnumerationComplete:        true,
		EnumeratedUsers:            1_000,
		AttemptedUsers:             1_000,
		ProcessedUsers:             200,
		RESTFallbackUsers:          800,
		RESTPerHour:                100,
		GraphQLPerHour:             100,
		EnumerationUsersPerRequest: 90,
		GraphQLUsersPerRequest:     100,
		RESTRequestsPerFallback:    1,
	})
	if !ok {
		t.Fatal("phase-aware estimate unavailable")
	}
	if estimate.EstimatedFutureUsersLow != 0 || estimate.EstimatedTotalLow != 1_000 {
		t.Fatalf("completed enumeration must use an exact population: %#v", estimate)
	}
	if estimate.RemainingHoursLow != 8 {
		t.Fatalf("remaining REST drain=%v hours, want 8", estimate.RemainingHoursLow)
	}
}

func TestEstimatePhasedCompletionRequiresBothCapacityBuckets(t *testing.T) {
	if _, ok := estimatePhasedCompletion(phaseEstimateInput{RESTPerHour: 100}); ok {
		t.Fatal("estimate should wait until both pacer capacities are known")
	}
}
