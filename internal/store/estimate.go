package store

import "math"

type phaseEstimateInput struct {
	EnumerationComplete         bool
	EnumeratedUsers             int64
	AttemptedUsers              int64
	ProcessedUsers              int64
	InaccessibleUsers           int64
	RESTFallbackUsers           int64
	RemainingShardIDs           int64
	RepairRemainingIDs          int64
	ObservedShardIDs            int64
	ObservedShardUsers          int64
	EstimatedLow                int64
	EstimatedHigh               int64
	RESTPerHour                 float64
	GraphQLPerHour              float64
	ObservedPrimaryUsersPerHour float64
	EnumerationUsersPerRequest  float64
	EnumerationIDsPerRequest    float64
	GraphQLUsersPerRequest      float64
	RESTRequestsPerFallback     float64
	EnumerationRESTShare        float64
	PrimaryGraphQLShare         float64
	ResourceUsersPerRequest     float64
	ResourceRESTFailureLow      float64
	ResourceRESTFailureHigh     float64
}

type phaseEstimate struct {
	Basis                      string
	RateBasis                  string
	EstimatedTotalLow          int64
	EstimatedTotalHigh         int64
	EstimatedFutureUsersLow    int64
	EstimatedFutureUsersHigh   int64
	RemainingAccountsLow       int64
	RemainingAccountsHigh      int64
	RemainingHoursLow          float64
	RemainingHoursHigh         float64
	FastScanHoursLow           float64
	FastScanHoursHigh          float64
	EffectiveUsersPerHour      float64
	FallbackRatioLow           float64
	FallbackRatioHigh          float64
	RESTRequestsLow            float64
	RESTRequestsHigh           float64
	GraphQLPointsLow           float64
	GraphQLPointsHigh          float64
	RESTHoursLow               float64
	RESTHoursHigh              float64
	GraphQLHoursLow            float64
	GraphQLHoursHigh           float64
	EnumerationUsersPerRequest float64
	EnumerationIDsPerRequest   float64
	GraphQLUsersPerRequest     float64
	RESTRequestsPerFallback    float64
	ResourceUsersPerRequest    float64
	ResourceRESTFailureLow     float64
	ResourceRESTFailureHigh    float64
	Preliminary                bool
}

func estimatePhasedCompletion(input phaseEstimateInput) (phaseEstimate, bool) {
	if input.RESTPerHour <= 0 || input.GraphQLPerHour <= 0 {
		return phaseEstimate{}, false
	}

	enumerationUsersPerRequest := boundedRate(
		input.EnumerationUsersPerRequest, 1, 100, 90,
	)
	enumerationIDsPerRequest := boundedRate(
		input.EnumerationIDsPerRequest, 1, 1_000, 100,
	)
	graphqlUsersPerRequest := boundedRate(
		input.GraphQLUsersPerRequest, 1, 250, 100,
	)
	restRequestsPerFallback := boundedRate(
		input.RESTRequestsPerFallback, 1, 10, 1,
	)
	enumerationRESTShare := boundedRate(input.EnumerationRESTShare, 0.05, 1, 0.5)
	primaryGraphQLShare := boundedRate(input.PrimaryGraphQLShare, 0.05, 1, 0.8)
	primaryGraphQLUsersPerHour := input.GraphQLPerHour * primaryGraphQLShare *
		graphqlUsersPerRequest
	if input.ObservedPrimaryUsersPerHour > 0 {
		primaryGraphQLUsersPerHour = math.Min(
			primaryGraphQLUsersPerHour, input.ObservedPrimaryUsersPerHour,
		)
	}
	resourceUsersPerRequest := boundedRate(input.ResourceUsersPerRequest, 1, 100, 100)
	resourceRESTFailureLow := clamp(input.ResourceRESTFailureLow, 0, 1)
	resourceRESTFailureHigh := clamp(
		math.Max(input.ResourceRESTFailureHigh, resourceRESTFailureLow), 0, 1,
	)

	settlementBacklog := max(int64(0), input.EnumeratedUsers-input.ProcessedUsers)
	nonRESTBacklog := max(int64(0), settlementBacklog-input.RESTFallbackUsers)

	futureLow, futureHigh := int64(0), int64(0)
	basis := "exact users enumerated for this run"
	preliminary := input.AttemptedUsers < 1_000_000
	if !input.EnumerationComplete {
		switch {
		case input.RepairRemainingIDs > 0:
			// A repair shard replays an ID range and upserts observations that
			// may already exist. It is incorrect to count every replay position
			// as a new account. Use the planning population envelope for new
			// GraphQL work; REST replay work is accounted for separately below.
			futureLow = max(int64(0), input.EstimatedLow-input.EnumeratedUsers)
			futureHigh = max(futureLow, input.EstimatedHigh-input.EnumeratedUsers)
			basis = "phase-aware repair replay and planning population envelope"
			preliminary = true
		case input.RemainingShardIDs > 0 && input.ObservedShardIDs > 0:
			density := clamp(
				float64(input.ObservedShardUsers)/float64(input.ObservedShardIDs), 0, 1,
			)
			futureLow = int64(math.Ceil(float64(input.RemainingShardIDs) * density))
			futureHigh = input.RemainingShardIDs
			basis = "phase-aware API work from active shard density"
			preliminary = preliminary || input.ObservedShardIDs < 1_000_000
		default:
			futureLow = max(int64(0), input.EstimatedLow-input.EnumeratedUsers)
			futureHigh = max(futureLow, input.EstimatedHigh-input.EnumeratedUsers)
			basis = "phase-aware API work from planning population envelope"
			preliminary = true
		}
	}

	// Legacy inaccessible counts came from the former node-ID query and do not
	// predict nulls from the current database-ID federation query. Live batches
	// show a sub-percent null/identity-repair rate. Keep a bounded 0.1%-0.5%
	// envelope and account for every upper-bound repair as REST below.
	fallbackRatioLow := 0.001
	fallbackRatioHigh := 0.005

	currentResourceUsers := float64(input.RESTFallbackUsers)
	currentRESTRequestsLow := currentResourceUsers * resourceRESTFailureLow * restRequestsPerFallback
	currentRESTRequestsHigh := currentResourceUsers * resourceRESTFailureHigh * restRequestsPerFallback
	currentPrimaryGraphQLPoints := float64(nonRESTBacklog) / graphqlUsersPerRequest
	currentGraphQLPoints := currentPrimaryGraphQLPoints +
		currentResourceUsers/resourceUsersPerRequest
	enumerationRESTRequests := float64(input.RemainingShardIDs) / enumerationIDsPerRequest
	fastScanRESTHoursLow := enumerationRESTRequests /
		(input.RESTPerHour * enumerationRESTShare)
	fastScanGraphQLHoursLow := (float64(nonRESTBacklog) + float64(futureLow)) /
		primaryGraphQLUsersPerHour

	futureResourceUsersLow := float64(futureLow) * fallbackRatioLow
	futureResourceUsersHigh := float64(futureHigh) * fallbackRatioHigh
	restRequestsLow := currentRESTRequestsLow +
		enumerationRESTRequests +
		futureResourceUsersLow*resourceRESTFailureLow*restRequestsPerFallback
	graphqlPointsLow := currentGraphQLPoints + float64(futureLow)/graphqlUsersPerRequest +
		futureResourceUsersLow/resourceUsersPerRequest

	// Ten percent operational overhead is kept on the late side only. The live
	// pacers already reserve primary quota; this margin is for retries, key-page
	// pagination, tail traffic, and API variance.
	const highOverhead = 1.10
	fastScanRESTHoursHigh := enumerationRESTRequests *
		highOverhead / (input.RESTPerHour * enumerationRESTShare)
	fastScanGraphQLHoursHigh := (float64(nonRESTBacklog) + float64(futureHigh)) *
		highOverhead / primaryGraphQLUsersPerHour
	restRequestsHigh := (currentRESTRequestsHigh +
		enumerationRESTRequests +
		futureResourceUsersHigh*resourceRESTFailureHigh*restRequestsPerFallback) * highOverhead
	graphqlPointsHigh := (currentGraphQLPoints +
		float64(futureHigh)/graphqlUsersPerRequest +
		futureResourceUsersHigh/resourceUsersPerRequest) * highOverhead

	restHoursLow := restRequestsLow / input.RESTPerHour
	restHoursHigh := restRequestsHigh / input.RESTPerHour
	graphqlHoursLow := graphqlPointsLow / input.GraphQLPerHour
	graphqlHoursHigh := graphqlPointsHigh / input.GraphQLPerHour
	remainingHoursLow := math.Max(restHoursLow, graphqlHoursLow)
	remainingHoursHigh := math.Max(restHoursHigh, graphqlHoursHigh)
	fastScanHoursLow := math.Max(fastScanRESTHoursLow, fastScanGraphQLHoursLow)
	fastScanHoursHigh := math.Max(fastScanRESTHoursHigh, fastScanGraphQLHoursHigh)
	// Settlement includes the fast scan. Resource repair can drain concurrently
	// and may finish before discovery, but full negative-lookup coverage cannot
	// be complete before every account has received its initial GraphQL attempt.
	remainingHoursLow = math.Max(remainingHoursLow, fastScanHoursLow)
	remainingHoursHigh = math.Max(remainingHoursHigh, fastScanHoursHigh)
	remainingAccountsLow := settlementBacklog + futureLow
	remainingAccountsHigh := settlementBacklog + futureHigh
	effectiveUsersPerHour := 0.0
	if remainingHoursLow > 0 {
		effectiveUsersPerHour = float64(remainingAccountsLow) / remainingHoursLow
	}

	return phaseEstimate{
		Basis:                      basis,
		RateBasis:                  "phase-aware REST enumeration and measured GraphQL observation/resource-repair capacities",
		EstimatedTotalLow:          input.EnumeratedUsers + futureLow,
		EstimatedTotalHigh:         input.EnumeratedUsers + futureHigh,
		EstimatedFutureUsersLow:    futureLow,
		EstimatedFutureUsersHigh:   futureHigh,
		RemainingAccountsLow:       remainingAccountsLow,
		RemainingAccountsHigh:      remainingAccountsHigh,
		RemainingHoursLow:          remainingHoursLow,
		RemainingHoursHigh:         remainingHoursHigh,
		FastScanHoursLow:           fastScanHoursLow,
		FastScanHoursHigh:          fastScanHoursHigh,
		EffectiveUsersPerHour:      effectiveUsersPerHour,
		FallbackRatioLow:           fallbackRatioLow,
		FallbackRatioHigh:          fallbackRatioHigh,
		RESTRequestsLow:            restRequestsLow,
		RESTRequestsHigh:           restRequestsHigh,
		GraphQLPointsLow:           graphqlPointsLow,
		GraphQLPointsHigh:          graphqlPointsHigh,
		RESTHoursLow:               restHoursLow,
		RESTHoursHigh:              restHoursHigh,
		GraphQLHoursLow:            graphqlHoursLow,
		GraphQLHoursHigh:           graphqlHoursHigh,
		EnumerationUsersPerRequest: enumerationUsersPerRequest,
		EnumerationIDsPerRequest:   enumerationIDsPerRequest,
		GraphQLUsersPerRequest:     graphqlUsersPerRequest,
		RESTRequestsPerFallback:    restRequestsPerFallback,
		ResourceUsersPerRequest:    resourceUsersPerRequest,
		ResourceRESTFailureLow:     resourceRESTFailureLow,
		ResourceRESTFailureHigh:    resourceRESTFailureHigh,
		Preliminary:                preliminary,
	}, true
}

func boundedRate(value, low, high, fallback float64) float64 {
	if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return fallback
	}
	return clamp(value, low, high)
}

func clamp(value, low, high float64) float64 {
	return math.Max(low, math.Min(high, value))
}
