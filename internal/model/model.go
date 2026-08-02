package model

import "time"

type Candidate struct {
	QueueID      int64
	Attempts     int
	RunID        *int64
	Source       string
	GitHubID     int64
	NodeID       string
	Login        string
	ScanID       string
	ClaimToken   string
	GenerationID *int64
	PartitionID  *int64
}

type PublicKey struct {
	Fingerprint []byte
	Text        string
	Type        string
	Canonical   string
}

type UserResult struct {
	NodeID        string
	GitHubID      int64
	Login         string
	CreatedAt     time.Time
	Keys          []PublicKey
	HasMoreKeys   bool
	NextCursor    string
	TotalKeyCount int
}

type OverflowJob struct {
	ID               int64
	Attempts         int
	RunID            *int64
	Source           string
	GitHubID         int64
	NodeID           string
	Login            string
	ScanID           string
	Cursor           string
	ClaimToken       string
	CreatedAt        *time.Time
	GenerationID     *int64
	PartitionID      *int64
	ExpectedKeyCount int
	ObservedKeyCount int
	VerificationPass int
}

type Rate struct {
	Limit     int
	Remaining int
	Used      int
	Cost      int
	ResetAt   time.Time
	Resource  string
}
