// Package audit records what operators did. Entries are written to the
// process log and kept in a bounded ring buffer for the user interface.
//
// The durable record of issuance is the kbissuance store, which replicates;
// this buffer is a convenience for the audit view and is lost on restart.
package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Entry is one auditable action.
type Entry struct {
	At           string `json:"at"`
	Action       string `json:"action"`
	Operator     string `json:"operator,omitempty"`
	Subject      string `json:"subject,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// Log is a bounded in-memory audit buffer.
type Log struct {
	mu      sync.RWMutex
	entries []Entry
	max     int
	logger  *slog.Logger
}

// New returns a log holding at most max entries.
func New(max int, logger *slog.Logger) *Log {
	if max <= 0 {
		max = 1000
	}
	return &Log{max: max, logger: logger}
}

// Write records an entry.
func (l *Log) Write(ctx context.Context, e Entry) {
	e.At = time.Now().UTC().Format(time.RFC3339)

	l.mu.Lock()
	l.entries = append(l.entries, e)
	if len(l.entries) > l.max {
		l.entries = l.entries[len(l.entries)-l.max:]
	}
	l.mu.Unlock()

	if l.logger != nil {
		l.logger.Info("audit",
			"action", e.Action, "operator", e.Operator, "subject", e.Subject,
			"credential", e.CredentialID, "request", e.RequestID, "detail", e.Detail)
	}
}

// Recent returns up to n entries, newest first.
func (l *Log) Recent(n int) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n > len(l.entries) {
		n = len(l.entries)
	}
	out := make([]Entry, 0, n)
	for i := len(l.entries) - 1; i >= len(l.entries)-n; i-- {
		out = append(out, l.entries[i])
	}
	return out
}
