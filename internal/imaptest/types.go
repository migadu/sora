// Package imaptest runs deterministic IMAP protocol checks against a supplied
// server. It has no dependency on Sora's server, database, or storage packages.
package imaptest

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Config describes an existing IMAP endpoint and a test account.
type Config struct {
	Addr                 string
	Username             string
	Password             string
	TLSMode              string // implicit, starttls, or none
	CAFile               string
	ServerName           string
	Insecure             bool
	CommandTimeout       time.Duration
	CaseTimeout          time.Duration
	FTSTimeout           time.Duration // maximum wait for asynchronous fixture body indexing
	Clients              int           // maximum concurrent independent cases; zero selects the default of one
	Run                  string        // regular expression matching case names
	RequiredCapabilities []string
	Trace                io.Writer // authentication commands and replies are suppressed
}

// Case contains a protocol requirement and its independent test scenario.
type Case struct {
	Name        string
	Description string
	RFC         string
	Requires    []string
	Upstream    string // pinned upstream script name, empty for supplemental native cases
	Run         func(*Session) error
}

type Result struct {
	Name          string        `json:"name"`
	RFC           string        `json:"rfc"`
	Upstream      string        `json:"upstream,omitempty"`
	Status        string        `json:"status"` // pass, fail, skip, error
	Duration      time.Duration `json:"duration_ns"`
	Detail        string        `json:"detail,omitempty"`
	CleanupErrors []string      `json:"cleanup_errors,omitempty"`
}

type Report struct {
	Address      string        `json:"address"`
	StartedAt    time.Time     `json:"started_at"`
	Duration     time.Duration `json:"duration_ns"`
	Capabilities []string      `json:"capabilities"`
	Clients      int           `json:"clients"`
	Results      []Result      `json:"results"`
	Passed       int           `json:"passed"`
	Failed       int           `json:"failed"`
	Skipped      int           `json:"skipped"`
	Errors       int           `json:"errors"`
	Error        string        `json:"error,omitempty"`
}

// ExitCode distinguishes assertion failures (1) from unusable/incomplete runs (2).
func (r Report) ExitCode() int {
	if r.Error != "" || r.Errors > 0 || r.Passed+r.Failed == 0 {
		return 2
	}
	if r.Failed > 0 {
		return 1
	}
	return 0
}

type AssertionError struct{ Message string }

func (e *AssertionError) Error() string { return e.Message }

// SkipError identifies an optional RFC feature unavailable in a selected mailbox.
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return e.Reason }

func Skip(reason string) error { return &SkipError{Reason: reason} }

// Check records a violated protocol assertion rather than an infrastructure error.
func Check(ok bool, format string, args ...any) error {
	if !ok {
		return &AssertionError{Message: fmt.Sprintf(format, args...)}
	}
	return nil
}

// Session owns the connections and exact mailbox names created by one case.
type Session struct {
	Client        *Client
	Caps          map[string]bool
	ctx           context.Context
	cfg           Config
	prefix        string
	clients       []*Client
	mailboxes     map[string]bool
	uncertain     []string
	subscriptions map[string]bool
}
