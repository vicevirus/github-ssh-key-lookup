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
		EnumerationRESTShare:       0.95,
		PrimaryGraphQLShare:        0.8,
		ResourceUsersPerRequest:    100,
		ResourceRESTFailureHigh:    0.01,
	})
	if !ok {
		t.Fatal("phase-aware estimate unavailable")
	}
	if estimate.EstimatedFutureUsersLow < 52_000_000 ||
		estimate.EstimatedFutureUsersLow > 52_200_000 {
		t.Fatalf("unexpected future-user estimate: %#v", estimate)
	}
	if estimate.RemainingHoursLow < 60 || estimate.RemainingHoursLow > 75 {
		t.Fatalf("URL-resource repair should settle near the fast scan: %#v", estimate)
	}
	if estimate.RemainingHoursHigh <= estimate.RemainingHoursLow ||
		estimate.RemainingHoursHigh > 105 {
		t.Fatalf("unexpected late estimate: %#v", estimate)
	}
	if estimate.EffectiveUsersPerHour < 700_000 || estimate.EffectiveUsersPerHour > 900_000 {
		t.Fatalf("unexpected sustainable throughput: %#v", estimate)
	}
	if estimate.FastScanHoursLow < 65 || estimate.FastScanHoursLow > 75 {
		t.Fatalf("fast scan should finish in roughly three days: %#v", estimate)
	}
	if estimate.FastScanHoursHigh <= estimate.FastScanHoursLow || estimate.FastScanHoursHigh > 95 {
		t.Fatalf("unexpected conservative fast-scan estimate: %#v", estimate)
	}
	if estimate.RemainingHoursLow < estimate.FastScanHoursLow ||
		estimate.RemainingHoursHigh < estimate.FastScanHoursHigh {
		t.Fatalf("settled coverage cannot predate the fast scan: %#v", estimate)
	}
}

func TestEstimatePhasedCompletionUsesBatchedResourceRepairAfterEnumeration(t *testing.T) {
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
		ResourceUsersPerRequest:    100,
		ResourceRESTFailureHigh:    0.01,
	})
	if !ok {
		t.Fatal("phase-aware estimate unavailable")
	}
	if estimate.EstimatedFutureUsersLow != 0 || estimate.EstimatedTotalLow != 1_000 {
		t.Fatalf("completed enumeration must use an exact population: %#v", estimate)
	}
	if estimate.RemainingHoursLow != 0.08 {
		t.Fatalf("remaining GraphQL resource drain=%v hours, want 0.08", estimate.RemainingHoursLow)
	}
}

func TestEstimatePhasedCompletionRequiresBothCapacityBuckets(t *testing.T) {
	if _, ok := estimatePhasedCompletion(phaseEstimateInput{RESTPerHour: 100}); ok {
		t.Fatal("estimate should wait until both pacer capacities are known")
	}
}

func TestEstimatePhasedCompletionUsesMeasuredPrimaryThroughput(t *testing.T) {
	estimate, ok := estimatePhasedCompletion(phaseEstimateInput{
		EnumeratedUsers:             10_000,
		AttemptedUsers:              10_000,
		ProcessedUsers:              9_000,
		EstimatedLow:                110_000,
		EstimatedHigh:               110_000,
		RESTPerHour:                 9_400,
		GraphQLPerHour:              9_400,
		GraphQLUsersPerRequest:      180,
		ObservedPrimaryUsersPerHour: 540_000,
		EnumerationUsersPerRequest:  100,
		EnumerationIDsPerRequest:    100,
		EnumerationRESTShare:        0.95,
		PrimaryGraphQLShare:         0.90,
		ResourceUsersPerRequest:     100,
	})
	if !ok {
		t.Fatal("phase-aware estimate unavailable")
	}
	if estimate.GraphQLUsersPerRequest != 180 {
		t.Fatalf("large measured batch was truncated: %#v", estimate)
	}
	if estimate.FastScanHoursLow < 0.18 || estimate.FastScanHoursLow > 0.19 {
		t.Fatalf("measured throughput was not used: %#v", estimate)
	}
	if estimate.EffectiveUsersPerHour < 530_000 || estimate.EffectiveUsersPerHour > 550_000 {
		t.Fatalf("unexpected effective measured rate: %#v", estimate)
	}
}

func TestEstimatePhasedCompletionIgnoresLegacyInaccessibleRatio(t *testing.T) {
	estimate, ok := estimatePhasedCompletion(phaseEstimateInput{
		EnumeratedUsers:             10_000_000,
		AttemptedUsers:              10_000_000,
		ProcessedUsers:              10_000_000,
		InaccessibleUsers:           5_000_000,
		EstimatedLow:                20_000_000,
		EstimatedHigh:               20_000_000,
		RESTPerHour:                 9_400,
		GraphQLPerHour:              9_400,
		ObservedPrimaryUsersPerHour: 500_000,
		EnumerationUsersPerRequest:  100,
		EnumerationIDsPerRequest:    100,
		GraphQLUsersPerRequest:      200,
		EnumerationRESTShare:        0.95,
		PrimaryGraphQLShare:         0.90,
		ResourceUsersPerRequest:     1,
		ResourceRESTFailureHigh:     1,
	})
	if !ok {
		t.Fatal("phase-aware estimate unavailable")
	}
	if estimate.FallbackRatioLow != 0.001 || estimate.FallbackRatioHigh != 0.005 {
		t.Fatalf("legacy inaccessible observations poisoned the future rate: %#v", estimate)
	}
}

func TestEstimatePhasedCompletionTreatsRepairAsReplayWork(t *testing.T) {
	estimate, ok := estimatePhasedCompletion(phaseEstimateInput{
		EnumeratedUsers:            72_000_000,
		AttemptedUsers:             72_000_000,
		ProcessedUsers:             72_000_000,
		RemainingShardIDs:          234_000_000,
		RepairRemainingIDs:         226_000_000,
		EstimatedLow:               170_000_000,
		EstimatedHigh:              210_000_000,
		RESTPerHour:                9_400,
		GraphQLPerHour:             9_400,
		EnumerationIDsPerRequest:   105,
		EnumerationUsersPerRequest: 80,
		GraphQLUsersPerRequest:     100,
		EnumerationRESTShare:       0.95,
		PrimaryGraphQLShare:        0.8,
		ResourceUsersPerRequest:    100,
	})
	if !ok {
		t.Fatal("phase-aware estimate unavailable")
	}
	if estimate.EstimatedTotalLow != 170_000_000 ||
		estimate.EstimatedTotalHigh != 210_000_000 {
		t.Fatalf("repair replay was counted as new accounts: %#v", estimate)
	}
	if estimate.FastScanHoursLow < 240 || estimate.FastScanHoursLow > 260 {
		t.Fatalf("REST replay time was not based on ID/page throughput: %#v", estimate)
	}
	if estimate.EnumerationIDsPerRequest != 105 {
		t.Fatalf("measured ID/page throughput was not retained: %#v", estimate)
	}
}
