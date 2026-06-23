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
// pathologically deep or wide SEARCH criteria with a tagged BAD response (instead of
// recursing unbounded through the SQL builder / criteria decoder), while still accepting
// ordinary shallow criteria.
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

	// readTaggedResult sends a command and returns the status word ("OK"/"NO"/"BAD")
	// from its tagged response, draining any untagged lines in between.
	readTaggedResult := func(tag, command string) string {
		fmt.Fprintf(conn, "%s %s\r\n", tag, command)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("reading response for %s: %v", tag, err)
			}
			if strings.HasPrefix(line, tag+" ") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					t.Fatalf("malformed tagged response: %q", line)
				}
				return fields[1]
			}
		}
	}

	t.Run("DeeplyNestedNotIsRejected", func(t *testing.T) {
		// 40 levels of nested NOT exceeds the 30-level depth cap → BAD.
		deep := strings.Repeat("NOT ", 40) + "ALL"
		if got := readTaggedResult("A010", "SEARCH "+deep); got != "BAD" {
			t.Errorf("expected BAD for deeply nested SEARCH, got %s", got)
		}
	})

	t.Run("WideFanOutIsRejected", func(t *testing.T) {
		// 300 sibling OR pairs (~600 nodes) exceeds the 256-node cap → BAD.
		wide := strings.TrimSpace(strings.Repeat("OR SEEN ANSWERED ", 300))
		if got := readTaggedResult("A011", "SEARCH "+wide); got != "BAD" {
			t.Errorf("expected BAD for wide fan-out SEARCH, got %s", got)
		}
	})

	t.Run("ShallowNestingIsAccepted", func(t *testing.T) {
		// A couple of NOT levels is well within limits → OK.
		if got := readTaggedResult("A012", "SEARCH NOT NOT ALL"); got != "OK" {
			t.Errorf("expected OK for shallow nested SEARCH, got %s", got)
		}
	})

	t.Run("ShallowSortIsAccepted", func(t *testing.T) {
		// Control: confirms SORT is supported, so the rejection below is attributable to
		// the validator rather than an unsupported command.
		if got := readTaggedResult("A013", "SORT (DATE) UTF-8 ALL"); got != "OK" {
			t.Errorf("expected OK for shallow SORT, got %s", got)
		}
	})

	t.Run("DeeplyNestedSortIsRejected", func(t *testing.T) {
		// SORT funnels through the same shared validator.
		deep := strings.Repeat("NOT ", 40) + "ALL"
		if got := readTaggedResult("A014", "SORT (DATE) UTF-8 "+deep); got != "BAD" {
			t.Errorf("expected BAD for deeply nested SORT, got %s", got)
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
