//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchCriteriaComplexityLimits proves end-to-end that the server rejects
// pathologically deep or wide SEARCH criteria (instead of recursing unbounded through the
// SQL builder / criteria decoder), while still accepting ordinary shallow criteria.
//
// Exceeding a limit is reported as NO [SERVERLIMIT], which is distinct from the
// BAD [CLIENTBUG] used for criteria that are actually malformed.
func TestIMAP_SearchCriteriaComplexityLimits(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Greeting
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

	// Login
	fmt.Fprintf(conn, "A001 LOGIN %s %s\r\n", account.Email, account.Password)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "A001 OK") {
		t.Fatalf("Login failed: %q (err: %v)", line, err)
	}

	// Select INBOX
	fmt.Fprintf(conn, "A002 SELECT INBOX\r\n")
	if err := readUntilTag(reader, "A002", "OK"); err != nil {
		t.Fatalf("SELECT INBOX: %v", err)
	}

	// readTaggedResult sends a command and returns its full tagged response line,
	// draining any untagged lines in between.
	readTaggedResult := func(tag, command string) string {
		fmt.Fprintf(conn, "%s %s\r\n", tag, command)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("reading response for %s: %v", tag, err)
			}
			if strings.HasPrefix(line, tag+" ") {
				return strings.TrimSpace(line)
			}
		}
	}

	assertOverLimit := func(t *testing.T, tag, command string) {
		t.Helper()
		got := readTaggedResult(tag, command)
		if !strings.HasPrefix(got, tag+" NO ") || !strings.Contains(got, "[SERVERLIMIT]") {
			t.Errorf("expected %s NO [SERVERLIMIT], got %q", tag, got)
		}
	}

	assertAccepted := func(t *testing.T, tag, command string) {
		t.Helper()
		got := readTaggedResult(tag, command)
		if !strings.HasPrefix(got, tag+" OK") {
			t.Errorf("expected %s OK, got %q", tag, got)
		}
	}

	t.Run("DeeplyNestedNotIsRejected", func(t *testing.T) {
		// 40 levels of nested NOT exceeds the 30-level depth cap.
		assertOverLimit(t, "A010", "SEARCH "+strings.Repeat("NOT ", 40)+"ALL")
	})

	t.Run("WideFanOutIsRejected", func(t *testing.T) {
		// 300 sibling OR pairs (~600 nodes) exceeds the 256-node cap.
		wide := strings.TrimSpace(strings.Repeat("OR SEEN ANSWERED ", 300))
		assertOverLimit(t, "A011", "SEARCH "+wide)
	})

	t.Run("ShallowNestingIsAccepted", func(t *testing.T) {
		// A couple of NOT levels is well within limits.
		assertAccepted(t, "A012", "SEARCH NOT NOT ALL")
	})

	t.Run("ShallowSortIsAccepted", func(t *testing.T) {
		// Control: confirms SORT is supported, so the rejection below is attributable to
		// the validator rather than an unsupported command.
		assertAccepted(t, "A013", "SORT (DATE) UTF-8 ALL")
	})

	t.Run("DeeplyNestedSortIsRejected", func(t *testing.T) {
		// SORT funnels through the same shared validator.
		assertOverLimit(t, "A014", "SORT (DATE) UTF-8 "+strings.Repeat("NOT ", 40)+"ALL")
	})

	t.Run("MalformedCriteriaIsClientBug", func(t *testing.T) {
		// A limit rejection must stay distinguishable from a genuinely invalid criteria,
		// which is the distinction SERVERLIMIT exists to draw.
		got := readTaggedResult("A015", "SEARCH NOT")
		if !strings.HasPrefix(got, "A015 BAD") {
			t.Errorf("expected A015 BAD for malformed criteria, got %q", got)
		}
	})
}

// readUntilTag drains untagged lines until the tagged response for tag arrives, returning
// an error unless its status matches wantStatus.
func readUntilTag(reader *bufio.Reader, tag, wantStatus string) error {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.HasPrefix(line, tag+" "+wantStatus) {
				return fmt.Errorf("got %q, want status %s", strings.TrimSpace(line), wantStatus)
			}
			return nil
		}
	}
}
