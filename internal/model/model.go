package model

import "time"

type Candidate struct {
	QueueID  int64
	Attempts int
	RunID    *int64
	Source   string
	GitHubID int64
	NodeID   string
	Login    string
	ScanID   string
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
	Keys          []PublicKey
	HasMoreKeys   bool
	NextCursor    string
	TotalKeyCount int
	InvalidKeys   int
}

type OverflowJob struct {
	ID       int64
	Attempts int
	RunID    *int64
	Source   string
	GitHubID int64
	NodeID   string
	Login    string
	ScanID   string
	Cursor   string
}

type Rate struct {
	Limit     int
	Remaining int
	Used      int
	Cost      int
	ResetAt   time.Time
	Resource  string
}
