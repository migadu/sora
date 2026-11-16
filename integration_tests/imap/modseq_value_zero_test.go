//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_ModSequenceValueZeroRefused: CHANGEDSINCE and the QRESYNC SELECT
// parameter take a mod-sequence-value (RFC 7162 §7):
//
//	chgsince-fetch-mod  = "CHANGEDSINCE" SP mod-sequence-value
//	mod-sequence-value  = 1*DIGIT
//	                       ;; Positive unsigned 63-bit integer
//	                       ;; (mod-sequence)
//	                       ;; (1 <= n <= 9,223,372,036,854,775,807).
//	mod-sequence-valzer = "0" / mod-sequence-value
//
// so 0, or a value past 2^63-1, is a syntax error there: BAD. CHANGEDSINCE 0
// was read as no CHANGEDSINCE at all: FETCH served every message, and with
// VANISHED the BAD said CHANGEDSINCE was missing although it was sent (#1196).
// UNCHANGEDSINCE and SEARCH MODSEQ take a mod-sequence-valzer and keep 0.
func TestIMAP_ModSequenceValueZeroRefused(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: modseq\r\n\r\nhello\r\n"
	c.appendMsg("INBOX", msg)
	c.appendMsg("INBOX", msg)
	c.do("ENABLE QRESYNC")
	selected, _ := c.do("SELECT INBOX")
	m := regexp.MustCompile(`\[UIDVALIDITY (\d+)\]`).FindStringSubmatch(strings.Join(selected, "\n"))
	if m == nil {
		t.Fatalf("SELECT INBOX: no UIDVALIDITY in:\n%s", strings.Join(selected, "\n"))
	}
	uidValidity := m[1]

	run := func(cmd string) (untagged []string, status, resp string) {
		t.Helper()
		tag := c.send(cmd)
		untagged, tagged := c.read(tag, cmd)
		return untagged, strings.TrimPrefix(tagged, tag+" "), strings.Join(append(untagged, tagged), "\n")
	}
	refused := func(cmd string) {
		t.Helper()
		untagged, status, resp := run(cmd)
		if !strings.HasPrefix(status, "BAD ") || strings.Contains(status, "requires CHANGEDSINCE") {
			t.Errorf("%s: want BAD for the mod-sequence-value, got:\n%s", cmd, resp)
		}
		for _, line := range untagged {
			if strings.Contains(line, " FETCH ") {
				t.Errorf("%s: refused command sent FETCH data:\n%s", cmd, resp)
				break
			}
		}
	}

	for _, cmd := range []string{
		"FETCH 1:* (FLAGS) (CHANGEDSINCE 0)",
		"UID FETCH 1:* (FLAGS) (CHANGEDSINCE 0)",
		"UID FETCH 1:* (FLAGS) (CHANGEDSINCE 0 VANISHED)",
		"UID FETCH 1:* (FLAGS) CHANGEDSINCE 0 VANISHED",
		"UID FETCH 1:* (FLAGS) (CHANGEDSINCE 9223372036854775808)",
	} {
		refused(cmd)
	}
	if _, status, resp := run("UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)"); !strings.HasPrefix(status, "OK ") {
		t.Errorf("UID FETCH CHANGEDSINCE 1 VANISHED: want OK, got:\n%s", resp)
	}

	for _, params := range []string{
		"(QRESYNC (" + uidValidity + " 0))",
		"(QRESYNC (" + uidValidity + " 0 1:10))",
		"(QRESYNC (" + uidValidity + " 9223372036854775808))",
	} {
		refused("SELECT INBOX " + params)
	}
	if _, status, resp := run("SELECT INBOX (QRESYNC (" + uidValidity + " 1))"); !strings.HasPrefix(status, "OK ") {
		t.Errorf("SELECT INBOX (QRESYNC (%s 1)): want OK, got:\n%s", uidValidity, resp)
	}

	// mod-sequence-valzer: 0 stays valid (RFC 7162 §3.1.3 for UNCHANGEDSINCE).
	c.do(`STORE 1 (UNCHANGEDSINCE 0) +FLAGS.SILENT (\Flagged)`)
	c.do("SEARCH MODSEQ 0")
}

// TestIMAP_ModSequenceValzerUpperBound: UNCHANGEDSINCE and the MODSEQ search
// key take a mod-sequence-valzer, "0" / mod-sequence-value (RFC 7162 §7), so
// 0 is allowed there but 2^63-1 is still the largest value. A larger one used
// to reach the database, which cannot encode it as a bigint: SEARCH and SORT
// answered NO [SERVERBUG] with the SQL encoder's error, and UNCHANGEDSINCE
// stored unconditionally.
func TestIMAP_ModSequenceValzerUpperBound(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	c.appendMsg("INBOX", "From: a@example.com\r\nTo: b@example.com\r\nSubject: valzer\r\n\r\nhello\r\n")
	c.do("ENABLE CONDSTORE")
	c.do("SELECT INBOX")

	const maxModSeq, overModSeq = "9223372036854775807", "9223372036854775808"
	for _, cmd := range []string{
		"SEARCH MODSEQ " + overModSeq,
		"UID SEARCH MODSEQ 18446744073709551615",
		`SEARCH MODSEQ "/flags/\\seen" all ` + overModSeq,
		"SORT (DATE) UTF-8 MODSEQ " + overModSeq,
		`UID STORE 1 (UNCHANGEDSINCE ` + overModSeq + `) +FLAGS (\Flagged)`,
	} {
		tag := c.send(cmd)
		untagged, tagged := c.read(tag, cmd)
		resp := strings.Join(append(untagged, tagged), "\n")
		if !strings.HasPrefix(tagged, tag+" BAD ") {
			t.Errorf("%s: want BAD for the mod-sequence-valzer, got:\n%s", cmd, resp)
		}
		for _, line := range untagged {
			if strings.Contains(line, " FETCH ") {
				t.Errorf("%s: refused command stored flags:\n%s", cmd, resp)
				break
			}
		}
	}
	if lines, _ := c.do("FETCH 1 (FLAGS)"); strings.Contains(strings.Join(lines, "\n"), `\Flagged`) {
		t.Errorf("refused UNCHANGEDSINCE %s stored \\Flagged:\n%s", overModSeq, strings.Join(lines, "\n"))
	}

	c.do("SEARCH MODSEQ " + maxModSeq)
	c.do("SORT (DATE) UTF-8 MODSEQ " + maxModSeq)
	c.do(`UID STORE 1 (UNCHANGEDSINCE ` + maxModSeq + `) +FLAGS.SILENT (\Flagged)`)
}
