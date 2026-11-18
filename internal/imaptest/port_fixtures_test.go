package imaptest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUpstreamCoverageAccountsForEveryPinnedScript(t *testing.T) {
	data, err := portFixtures.ReadFile("testdata/imaptest/coverage.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Revision string `json:"revision"`
		Scripts  []struct {
			Name     string   `json:"name"`
			Status   string   `json:"status"`
			GoCase   string   `json:"go_case"`
			Requires []string `json:"requires"`
		} `json:"scripts"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Revision != upstreamRevision {
		t.Fatal("coverage manifest differs from fixture revision")
	}
	ported := map[string]Case{}
	for _, c := range Cases() {
		if c.Upstream != "" {
			if _, exists := ported[c.Upstream]; exists {
				t.Fatalf("duplicate upstream mapping: %s", c.Upstream)
			}
			ported[c.Upstream] = c
		}
	}
	seen := map[string]bool{}
	excluded := 0
	for _, item := range raw.Scripts {
		if seen[item.Name] {
			t.Fatalf("duplicate source script: %s", item.Name)
		}
		seen[item.Name] = true
		switch item.Status {
		case "ported":
			c, exists := ported[item.Name]
			if !exists || c.Name != item.GoCase {
				t.Errorf("missing/wrong Go mapping for %s", item.Name)
			}
		case "excluded":
			excluded++
			if len(item.Requires) == 0 {
				t.Errorf("excluded script lacks capability reason: %s", item.Name)
			}
			if _, exists := ported[item.Name]; exists {
				t.Errorf("unsupported script entered executable catalog: %s", item.Name)
			}
		default:
			t.Errorf("unknown coverage status: %s", item.Status)
		}
	}
	if len(seen) != 74 || len(ported) != 61 || excluded != 13 {
		t.Fatalf("coverage: scripts=%d ported=%d excluded=%d, want74/61/13", len(seen), len(ported), excluded)
	}
	if len(Cases()) != 97 {
		t.Fatalf("catalog=%d, want61 ports +36 supplemental native cases", len(Cases()))
	}
	for name := range ported {
		if !seen[name] {
			t.Errorf("unaccounted port: %s", name)
		}
	}
}

func TestFTSFixtureDateRefreshPreservesBodiesAndOriginals(t *testing.T) {
	now := time.Date(2026, time.November, 18, 12, 30, 0, 0, time.UTC)
	for _, name := range []string{"nil", "search-body"} {
		messages, err := portFixture(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, message := range messages {
			original := bytes.Clone(message)
			fresh, err := portFreshDate(message, now)
			if err != nil {
				t.Fatal(err)
			}
			header, body, ok := bytes.Cut(fresh, []byte("\r\n\r\n"))
			if !ok {
				t.Fatal("missing fresh header delimiter")
			}
			_, oldBody, _ := bytes.Cut(original, []byte("\r\n\r\n"))
			if !bytes.Equal(body, oldBody) || !bytes.Equal(message, original) {
				t.Errorf("%s message%d: changed source/body bytes", name, i+1)
			}
			if !bytes.Contains(header, []byte("Date: "+now.Format(time.RFC1123Z))) {
				t.Errorf("%s message%d: sent date not refreshed", name, i+1)
			}
			again, err := portFixture(name)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again[i], original) {
				t.Fatal("modified the vendored fixture")
			}
		}
	}
}

func TestFTSFixtureRefreshHandlesFoldedDateWithoutChangingOtherHeaders(t *testing.T) {
	now := time.Date(2026, time.November, 18, 12, 30, 0, 0, time.UTC)
	original := []byte("Date: Tue, 1 Jan 2008 00:00:00\r\n +0000\r\nSubject: preserved\r\n folded subject\r\nX-Extra: unchanged\r\n\r\nbody\x00\xff\r\n")
	fresh, err := portFreshDate(original, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("Date: " + now.Format(time.RFC1123Z) + "\r\nSubject: preserved\r\n folded subject\r\nX-Extra: unchanged\r\n\r\nbody\x00\xff\r\n")
	if !bytes.Equal(fresh, want) {
		t.Fatalf("changed content beyond Date: %q", fresh)
	}
}

func TestPortMboxPreservesBytesBlankLinesAndEnvelopeDates(t *testing.T) {
	data := []byte("From sender@example.test Sat Mar 24 23:00:00 2007 +0200\nSubject: first\n\nbody\n\nFrom sender@example.test Sun Mar 25 01:00:00 2007 +0300\nSubject: second\n\nFrom not a dated envelope\n\xff\n")
	messages, dates, err := portParseMbox(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || len(dates) != 2 {
		t.Fatal("wrong mbox message boundaries")
	}
	if string(messages[0]) != "Subject: first\r\n\r\nbody\r\n\r\n" {
		t.Fatalf("changed first message bytes: %q", messages[0])
	}
	if !bytes.HasSuffix(messages[1], []byte("From not a dated envelope\r\n\xff\r\n")) {
		t.Fatalf("changed binary/body bytes: %q", messages[1])
	}
	if dates[0] != "24-Mar-2007 23:00:00 +0200" || dates[1] != "25-Mar-2007 01:00:00 +0300" {
		t.Fatalf("lost envelope zones: %v", dates)
	}
	crlf := bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
	again, _, err := portParseMbox(crlf)
	if err != nil || !bytes.Equal(again[0], messages[0]) {
		t.Fatal("CRLF fixture was normalized twice")
	}
}

func TestAllVendoredFixturesAreReadable(t *testing.T) {
	entries, err := portFixtures.ReadDir("testdata/imaptest")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".mbox") {
			name := strings.TrimSuffix(entry.Name(), ".mbox")
			messages, dates, err := portReadFixture(name)
			if err != nil || len(messages) == 0 || len(messages) != len(dates) {
				t.Errorf("fixture %s: messages=%d dates=%d err=%v", name, len(messages), len(dates), err)
			}
			count++
		}
	}
	if count != 36 {
		t.Fatalf("fixture count=%d, want36", count)
	}
	fallback, err := portFixture("no-special-fixture")
	if err != nil || len(fallback) != 6 {
		t.Fatalf("default fixture fallback: %d messages, %v", len(fallback), err)
	}
}
