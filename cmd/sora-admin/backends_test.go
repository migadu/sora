package main

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
)

func TestNormalizeBackendHost(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"storage2.example.com", "storage2.example.com", false},
		{" Storage2.Example.COM. ", "storage2.example.com", false},
		{"10.0.0.5", "10.0.0.5", false},
		{"2001:db8:0::1", "2001:db8::1", false}, // bare IPv6, canonicalized
		{"[2001:db8::1]", "2001:db8::1", false},
		{"storage2.example.com:143", "", true}, // a port would cover one protocol only
		{"10.0.0.5:24", "", true},
		{"[2001:db8::1]:143", "", true},
		{"", "", true},
		{"a b", "", true},
	}
	for _, c := range cases {
		got, err := normalizeBackendHost(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("normalizeBackendHost(%q) error = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeBackendHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// notQuiet says what stands between a backend and being safe to stop; only a known
// instance with nothing pending and a current report of no open session is quiet.
func TestNotQuiet(t *testing.T) {
	report := func(open int64, age time.Duration) db.InstanceDrainState {
		return db.InstanceDrainState{Known: true, Sessions: &db.InstanceSessions{Open: open}, ReportAge: age}
	}
	pending := report(0, time.Second)
	pending.Pending, pending.Parked = 3, 1
	unreported := db.InstanceDrainState{Known: true}

	cases := []struct {
		name  string
		state db.InstanceDrainState
		want  string // a fragment of the reason; "" for quiet
	}{
		{"quiet", report(0, time.Second), ""},
		{"unknown instance", db.InstanceDrainState{}, "unknown instance"},
		{"pending", pending, "3 uploads pending (1 parked)"},
		{"sessions open", report(4, time.Second), "4 sessions open"},
		{"no report", unreported, "does not report its sessions"},
		{"stale report", report(0, sessionsReportMaxAge+time.Second), "no sessions report for"},
	}
	for _, c := range cases {
		got := notQuiet(c.state)
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: notQuiet = %q, want %q", c.name, got, c.want)
		}
	}
}

// `maintenance on` says when the instance it was given has stopped reporting: an id a
// retired node left behind is known, but nothing it reports is current.
func TestStaleReportWarning(t *testing.T) {
	if w := staleReportWarning(db.InstanceDrainState{Known: true, Sessions: &db.InstanceSessions{}, ReportAge: time.Second}); w != "" {
		t.Errorf("current report: warning %q", w)
	}
	if w := staleReportWarning(db.InstanceDrainState{Known: true}); w != "" {
		t.Errorf("no report at all (warned about separately): warning %q", w)
	}
	w := staleReportWarning(db.InstanceDrainState{Known: true, Sessions: &db.InstanceSessions{InstanceID: "storage2"}, ReportAge: 90 * 24 * time.Hour})
	if !strings.Contains(w, "storage2") || !strings.Contains(w, "--instance") {
		t.Errorf("stale report: warning %q, want it to name the instance and --instance", w)
	}
}
