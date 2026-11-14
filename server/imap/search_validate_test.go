package imap

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
)

// deepNotCriteria builds `depth` levels of nested NOT iteratively (no recursion in the
// helper itself), mirroring a hostile deeply nested SEARCH command.
func deepNotCriteria(depth int) *imap.SearchCriteria {
	c := &imap.SearchCriteria{Flag: []imap.Flag{imap.FlagSeen}}
	for i := 0; i < depth; i++ {
		c = &imap.SearchCriteria{Not: []imap.SearchCriteria{*c}}
	}
	return c
}

func TestValidateSearchCriteria_RejectsDeepNestingWithNo(t *testing.T) {
	// A zero-value session is sufficient: validateSearchCriteria only logs and increments
	// a metric on rejection (both nil-safe on the embedded server.Session).
	s := &IMAPSession{}

	err := s.validateSearchCriteria("SEARCH", deepNotCriteria(1000))
	if err == nil {
		t.Fatal("expected deeply nested search criteria to be rejected")
	}

	imapErr, ok := err.(*imap.Error)
	if !ok {
		t.Fatalf("expected *imap.Error, got %T (%v)", err, err)
	}
	if imapErr.Type != imap.StatusResponseTypeNo {
		t.Errorf("expected NO response, got %v", imapErr.Type)
	}
	if imapErr.Code != imap.ResponseCodeLimit {
		t.Errorf("expected LIMIT code, got %v", imapErr.Code)
	}
}

func TestValidateSearchCriteria_RejectsWideFanOutWithNo(t *testing.T) {
	s := &IMAPSession{}

	wide := &imap.SearchCriteria{}
	for i := 0; i < 1000; i++ {
		wide.Or = append(wide.Or, [2]imap.SearchCriteria{
			{Flag: []imap.Flag{imap.FlagSeen}},
			{Flag: []imap.Flag{imap.FlagAnswered}},
		})
	}

	err := s.validateSearchCriteria("SORT", wide)
	if err == nil {
		t.Fatal("expected wide fan-out search criteria to be rejected")
	}
	if imapErr, ok := err.(*imap.Error); !ok || imapErr.Type != imap.StatusResponseTypeNo {
		t.Fatalf("expected NO *imap.Error, got %T (%v)", err, err)
	} else if imapErr.Code != imap.ResponseCodeLimit {
		t.Errorf("expected LIMIT code, got %v", imapErr.Code)
	}
}

func TestValidateSearchCriteria_AcceptsTypicalCriteria(t *testing.T) {
	s := &IMAPSession{}

	cases := []*imap.SearchCriteria{
		{}, // SEARCH ALL
		{Flag: []imap.Flag{imap.FlagSeen}},
		{
			Or: [][2]imap.SearchCriteria{
				{{Header: []imap.SearchCriteriaHeaderField{{Key: "From", Value: "a@example.com"}}},
					{Header: []imap.SearchCriteriaHeaderField{{Key: "From", Value: "b@example.com"}}}},
			},
			Not: []imap.SearchCriteria{{Flag: []imap.Flag{imap.FlagDeleted}}},
		},
	}
	for i, c := range cases {
		if err := s.validateSearchCriteria("SEARCH", c); err != nil {
			t.Errorf("case %d: expected typical criteria to pass, got %v", i, err)
		}
	}
}

// Well-formed searches that match no message, or every message, are answered,
// not refused: RFC 3501 §7.1.3 reserves BAD for "a protocol-level error in the
// client's command", and a date span has no limit (#283).
func TestValidateSearchCriteria_AcceptsSearchesThatMatchNothingOrAll(t *testing.T) {
	s := &IMAPSession{}
	day := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

	for name, criteria := range map[string]*imap.SearchCriteria{
		"SINCE after BEFORE":         {Since: day(2025, 3, 1), Before: day(2025, 1, 1)},
		"SENTSINCE after SENTBEFORE": {SentSince: day(2025, 3, 1), SentBefore: day(2025, 1, 1)},
		"LARGER over SMALLER":        {Larger: 5000, Smaller: 10},
		"LARGER equal to SMALLER":    {Larger: 10, Smaller: 10},
		"empty BODY":                 {Body: []string{""}},
		"empty TEXT":                 {Text: []string{""}},
		"date span over a year":      {Since: day(2024, 1, 1), Before: day(2025, 3, 1)},
		"sent date span over a year": {SentSince: day(2024, 1, 1), SentBefore: day(2025, 3, 1)},
		"long Message-ID":            {Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: "<" + strings.Repeat("x", 300) + "@example.com>"}}},
	} {
		if err := s.validateSearchCriteria("SEARCH", criteria); err != nil {
			t.Errorf("%s: refused with %v", name, err)
		}
	}
}
