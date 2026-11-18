// Copyright (c) 2007-2026 ImapTest authors. Adapted under the MIT license;
// see testdata/imaptest/COPYING. Native Go scenarios, no script interpreter.
package imaptest

import (
	"fmt"
	"slices"
)

type portSearchStep struct {
	command string
	want    []uint64
	check   bool
	line    int
}

func portSearchCases() []Case {
	return []Case{
		portCase("search-addresses", "Port of imaptest search-addresses criteria and fixture assertions", coreRFC+"6.4.4", nil, portSearchAddresses),
		portCase("search-body", "Full-word body matching and indexed-header TEXT substrings under Sora's search model", coreRFC+"6.4.4", nil, portSearchBody),
		portCase("search-date", "Port of imaptest search-date criteria and fixture assertions", coreRFC+"6.4.4", nil, portSearchDate),
		portCase("search-flags", "Port of imaptest search-flags criteria and fixture assertions", coreRFC+"6.4.4", nil, portSearchFlags),
		portCase("search-header", "Subject searches match; non-indexed HEADER fields produce no matches", coreRFC+"6.4.4", nil, portSearchHeader),
		portCase("search-sets", "Sequence and UID search sets after expunge", coreRFC+"6.4.4", nil, portSearchSets),
		portCase("search-size", "RFC822.SIZE boundaries, negation and Boolean combinations", coreRFC+"6.4.4", nil, portSearchSize),
	}
}

func portSearchAddresses(s *Session) error {
	if _, _, err := portMailbox(s, "search-addresses", -1, true); err != nil {
		return err
	}
	return portRunSearchSteps(s.Client, "search-addresses", []portSearchStep{
		{"search from user-from@domain.org", []uint64{1, 2, 3, 4, 6, 7}, true, 4},
		{"search to user-to@domain.org", []uint64{1, 2, 3, 4}, true, 6},
		{"search cc user-cc@domain.org", []uint64{1, 2, 3, 4, 5}, true, 8},
		{"search bcc user-bcc@domain.org", []uint64{1, 2, 3, 4}, true, 10},
		{"search from realfrom", []uint64{2, 4, 6, 7}, true, 14},
		{"search to realto", []uint64{2, 4}, true, 16},
		{"search cc realcc", []uint64{2, 4}, true, 18},
		{"search bcc realbcc", []uint64{2, 4}, true, 20},
		{"search header from \"\"", []uint64{1, 2, 3, 4, 5, 6, 7}, true, 24},
		{"search header to \"\"", []uint64{1, 2, 3, 4, 6, 7}, true, 26},
		{"search header cc \"\"", []uint64{1, 2, 3, 4, 5}, true, 28},
		{"search header bcc \"\"", []uint64{1, 2, 3, 4}, true, 30},
		{"search from ser-fro", []uint64{1, 2, 3, 4, 5, 6, 7}, true, 34},
		{"search to ser-t", []uint64{1, 2, 3, 4}, true, 36},
		{"search cc ser-c", []uint64{1, 2, 3, 4, 5}, true, 38},
		{"search bcc ser-bc", []uint64{1, 2, 3, 4}, true, 40},
		{"search from ealfro", []uint64{2, 4, 6, 7}, true, 44},
		{"search to ealt", []uint64{2, 4}, true, 46},
		{"search cc ealc", []uint64{2, 4}, true, 48},
		{"search bcc ealbc", []uint64{2, 4}, true, 50},
		{"search from user-from1", []uint64{5}, true, 54},
		{"search from user-from2", []uint64{5}, true, 56},
		{"search to groupname", []uint64{6, 7}, true, 60},
		{"search to groupname2", []uint64{6}, true, 62},
		{"search to groupuser1", []uint64{6}, true, 64},
		{"search to groupuser2", []uint64{6}, true, 66},
		{"search to groupuser3", []uint64{6}, true, 68},
		{"search to groupuser4", nil, true, 70},
	})
}

func portSearchBody(s *Session) error {
	if _, _, err := portIndexedMailbox(s, "search-body", -1, true); err != nil {
		return err
	}
	// Every fixture message contains at least one of these complete words.
	// Wait for indexing of the whole fixture, then run each assertion normally.
	if err := waitForIndexing(s, "OR BODY asdfghjkl OR BODY zxcvbnm BODY qwertyuiop", 1, 2, 3, 4); err != nil {
		return err
	}
	return portRunSearchSteps(s.Client, "search-body", []portSearchStep{
		{"search text asdfghjkl", []uint64{1, 2}, true, 4},
		{"search text zxcvbnm", []uint64{1, 3, 4}, true, 6},
		// Message 3 has the term only in its non-indexed X-Header.
		{"search text qwertyuiop", []uint64{2, 4}, true, 8},
		{"search body asdfghjkl", []uint64{1, 2}, true, 11},
		{"search body zxcvbnm", []uint64{1, 3, 4}, true, 13},
		{"search body qwertyuiop", []uint64{4}, true, 15},
		// Sora's body index matches complete words. TEXT can still match an
		// interior substring in an indexed Subject, which message 2 supplies.
		{"search text sdfghjk", nil, true, 19},
		{"search text xcvbn", nil, true, 21},
		{"search text wertyuio", []uint64{2}, true, 23},
		{"search body sdfghjk", nil, true, 26},
		{"search body xcvbn", nil, true, 28},
		{"search body wertyuio", nil, true, 30},
	})
}

func portSearchDate(s *Session) error {
	if _, _, err := portMailbox(s, "search-date", -1, true); err != nil {
		return err
	}
	return portRunSearchSteps(s.Client, "search-date", []portSearchStep{
		{"search sentbefore 24-mar-2007", nil, true, 5},
		{"search sentbefore 25-mar-2007", []uint64{1}, true, 7},
		{"search sentbefore 26-mar-2007", []uint64{1, 2, 3, 4, 5, 6}, true, 9},
		{"search sentbefore 27-mar-2007", []uint64{1, 2, 3, 4, 5, 6, 7}, true, 11},
		{"search senton 23-mar-2007", nil, true, 15},
		{"search senton 24-mar-2007", []uint64{1}, true, 17},
		{"search senton 25-mar-2007", []uint64{2, 3, 4, 5, 6}, true, 19},
		{"search senton 26-mar-2007", []uint64{7}, true, 21},
		{"search 1:7 sentsince 24-mar-2007", []uint64{1, 2, 3, 4, 5, 6, 7}, true, 25},
		{"search 1:7 sentsince 25-mar-2007", []uint64{2, 3, 4, 5, 6, 7}, true, 27},
		{"search 1:7 sentsince 26-mar-2007", []uint64{7}, true, 29},
		{"search 1:7 sentsince 27-mar-2007", nil, true, 31},
		{"search 8:* sentbefore 27-oct-2007", nil, true, 36},
		{"search 8:* sentbefore 28-oct-2007", []uint64{8}, true, 38},
		{"search 8:* sentbefore 29-oct-2007", []uint64{8, 9, 10, 11, 12, 13, 14, 15}, true, 40},
		{"search 8:* sentbefore 30-oct-2007", []uint64{8, 9, 10, 11, 12, 13, 14, 15, 16}, true, 42},
		{"search 8:* senton 26-oct-2007", nil, true, 46},
		{"search 8:* senton 27-oct-2007", []uint64{8}, true, 48},
		{"search 8:* senton 28-oct-2007", []uint64{9, 10, 11, 12, 13, 14, 15}, true, 50},
		{"search 8:* senton 29-oct-2007", []uint64{16}, true, 52},
		{"search 8:* sentsince 27-oct-2007", []uint64{8, 9, 10, 11, 12, 13, 14, 15, 16}, true, 56},
		{"search 8:* sentsince 28-oct-2007", []uint64{9, 10, 11, 12, 13, 14, 15, 16}, true, 58},
		{"search 8:* sentsince 29-oct-2007", []uint64{16}, true, 60},
		{"search 8:* sentsince 30-oct-2007", nil, true, 62},
		{"search 1:7 not sentbefore 26-mar-2007", []uint64{7}, true, 66},
		{"search 1:7 not senton 25-mar-2007", []uint64{1, 7}, true, 68},
		{"search 8:* not sentsince 28-oct-2007", []uint64{8}, true, 70},
		{"search 8:* not senton 28-oct-2007", []uint64{8, 16}, true, 72},
	})
}

func portSearchFlags(s *Session) error {
	if _, _, err := portMailbox(s, "search-flags", 5, false); err != nil {
		return err
	}
	selected, err := s.Client.OK("SELECT " + Quote(s.Name("messages")))
	if err != nil {
		return err
	}
	permanent := selected.Code("PERMANENTFLAGS")
	if len(permanent) != 1 || !coreHasFlag(permanent[0], "\\*") {
		return Skip("upstream search-flags keyword precondition requires permanent user keywords")
	}
	return portRunSearchSteps(s.Client, "search-flags", []portSearchStep{
		{"store 1 flags ($hello)", nil, false, 3},
		{"store 2 flags (\\seen \\flagged)", nil, false, 4},
		{"store 3 flags (\\answered $hello)", nil, false, 5},
		{"store 4 flags (\\flagged \\draft)", nil, false, 6},
		{"store 5 flags (\\deleted \\answered)", nil, false, 7},
		{"search answered", []uint64{3, 5}, true, 9},
		{"search unanswered", []uint64{1, 2, 4}, true, 11},
		{"search deleted", []uint64{5}, true, 14},
		{"search undeleted", []uint64{1, 2, 3, 4}, true, 16},
		{"search draft", []uint64{4}, true, 19},
		{"search undraft", []uint64{1, 2, 3, 5}, true, 21},
		{"search flagged", []uint64{2, 4}, true, 24},
		{"search unflagged", []uint64{1, 3, 5}, true, 26},
		{"search seen", []uint64{2}, true, 29},
		{"search unseen", []uint64{1, 3, 4, 5}, true, 31},
		{"search keyword $hello", []uint64{1, 3}, true, 34},
		{"search unkeyword $hello", []uint64{2, 4, 5}, true, 36},
		{"search new", []uint64{1, 3, 4, 5}, true, 39},
		{"search old", nil, true, 42},
		{"search recent", []uint64{1, 2, 3, 4, 5}, true, 45},
		{"store 1:* flags (\\seen)", nil, false, 48},
		{"store 2 +flags (\\flagged)", nil, false, 49},
		{"search seen flagged", []uint64{2}, true, 50},
		{"search seen not flagged", []uint64{1, 3, 4, 5}, true, 52},
		{"search not seen flagged", nil, true, 54},
		{"search not seen not flagged", nil, true, 56},
		{"store 1:* flags (\\deleted)", nil, false, 59},
		{"store 2 +flags (\\flagged)", nil, false, 60},
		{"search deleted flagged", []uint64{2}, true, 61},
		{"search deleted not flagged", []uint64{1, 3, 4, 5}, true, 63},
		{"search not deleted flagged", nil, true, 65},
		{"search not deleted not flagged", nil, true, 67},
		{"store 1:* flags (\\seen \\deleted)", nil, false, 70},
		{"store 2 +flags (\\flagged)", nil, false, 71},
		{"search seen flagged", []uint64{2}, true, 72},
		{"search seen not flagged", []uint64{1, 3, 4, 5}, true, 74},
		{"search not seen flagged", nil, true, 76},
		{"search not seen not flagged", nil, true, 78},
		{"search seen deleted flagged", []uint64{2}, true, 80},
		{"search seen deleted not flagged", []uint64{1, 3, 4, 5}, true, 82},
		{"search not seen deleted flagged", nil, true, 84},
		{"search not seen deleted not flagged", nil, true, 86},
		{"search seen not deleted flagged", nil, true, 88},
		{"search seen not deleted not flagged", nil, true, 90},
		{"search not seen not deleted flagged", nil, true, 92},
		{"search not seen not deleted not flagged", nil, true, 94},
	})
}

func portSearchHeader(s *Session) error {
	if _, _, err := portMailbox(s, "search-header", -1, true); err != nil {
		return err
	}
	return portRunSearchSteps(s.Client, "search-header", []portSearchStep{
		{"search subject \"\"", nil, false, 5},
		{"search subject hello", []uint64{1}, true, 8},
		{"search subject beautiful", []uint64{1}, true, 10},
		{"search subject world", []uint64{1}, true, 12},
		{"search subject \"hello beautiful\"", []uint64{1}, true, 14},
		{"search subject \"hello beautiful world\"", []uint64{1}, true, 16},
		{"search subject \"eautiful worl\"", []uint64{1}, true, 18},
		{"search header subject \"\"", []uint64{1}, true, 22},
		{"search not header subject \"\"", []uint64{2}, true, 24},
		// X-Extra is deliberately not indexed. Its positive criterion is
		// false for every message, so negating it includes both messages.
		{"search header x-extra \"\"", nil, true, 26},
		{"search not header x-extra \"\"", []uint64{1, 2}, true, 28},
		{"search header x-extra hello", nil, true, 30},
		{"search header x-extra \"hello beautiful\"", nil, true, 32},
		{"search header x-extra \"eautiful head\"", nil, true, 34},
		{"search header x-extra \"another\"", nil, true, 36},
	})
}

func portRunSearchSteps(c *Client, name string, steps []portSearchStep) error {
	for _, step := range steps {
		response, err := c.OK(step.command)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", name, step.line, err)
		}
		if !step.check {
			continue
		}
		got, err := response.Search()
		if err != nil {
			return err
		}
		slices.Sort(got)
		if err := Check(slices.Equal(got, step.want), "%s:%d %s: got %v, want %v", name, step.line, step.command, got, step.want); err != nil {
			return err
		}
	}
	return nil
}

func portSearchSets(s *Session) error {
	box, _, err := portMailbox(s, "search-sets", 6, true)
	if err != nil {
		return err
	}
	uids, err := coreUIDs(s.Client)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 6, "want 6 fixture UIDs, got %v", uids); err != nil {
		return err
	}
	if err := portUIDSearch(s.Client, "ALL", uids); err != nil {
		return err
	}
	response, err := s.Client.OK("STATUS " + Quote(box) + " (UIDNEXT)")
	if err != nil {
		return err
	}
	status, err := response.StatusValues(box)
	if err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 2 +FLAGS (\\Deleted)"); err != nil {
		return err
	}
	if _, err := s.Client.OK("EXPUNGE"); err != nil {
		return err
	}
	if err := coreSearch(s.Client, "ALL", 1, 2, 3, 4, 5); err != nil {
		return err
	}
	remaining := []uint64{uids[0], uids[2], uids[3], uids[4], uids[5]}
	if err := portUIDSearch(s.Client, "ALL", remaining); err != nil {
		return err
	}
	checks := []portSearchStep{
		{"SEARCH 1:3,5", []uint64{1, 2, 3, 5}, true, 20},
		{"SEARCH 4:2", []uint64{2, 3, 4}, true, 22},
		{fmt.Sprintf("SEARCH UID %d:%d,%d", uids[0], uids[2], uids[4]), []uint64{1, 2, 4}, true, 24},
		{fmt.Sprintf("SEARCH UID %d:%d", uids[3], uids[1]), []uint64{2, 3}, true, 26},
		{fmt.Sprintf("SEARCH 1:3 NOT UID %d", uids[2]), []uint64{1, 3}, true, 29},
		{"SEARCH NOT 2,4", []uint64{1, 3, 5}, true, 31},
		{fmt.Sprintf("SEARCH OR 1 UID %d", uids[2]), []uint64{1, 2}, true, 33},
		{"SEARCH *", []uint64{5}, true, 36},
		{"SEARCH UID *", []uint64{5}, true, 38},
		{fmt.Sprintf("SEARCH UID %d:*", status["UIDNEXT"]), []uint64{5}, true, 40},
		{"SEARCH *:3", []uint64{3, 4, 5}, true, 42},
		{"SEARCH 1,4,*", []uint64{1, 4, 5}, true, 44},
		{fmt.Sprintf("SEARCH (3) UID %d", uids[3]), []uint64{3}, true, 54},
		{fmt.Sprintf("SEARCH (UID %d) 3", uids[3]), []uint64{3}, true, 56},
		{fmt.Sprintf("SEARCH 3 (UID %d)", uids[3]), []uint64{3}, true, 58},
	}
	if err := portRunSearchSteps(s.Client, "search-sets", checks); err != nil {
		return err
	}
	if err := portUIDSearch(s.Client, "UID 1:4294967295", remaining); err != nil {
		return err
	}
	return portUIDSearch(s.Client, fmt.Sprintf("UID %d:4294967295", status["UIDNEXT"]), nil)
}

func portUIDSearch(c *Client, criteria string, want []uint64) error {
	r, err := c.OK("UID SEARCH " + criteria)
	if err != nil {
		return err
	}
	got, err := r.Search()
	if err != nil {
		return err
	}
	slices.Sort(got)
	want = slices.Clone(want)
	slices.Sort(want)
	return Check(slices.Equal(got, want), "UID SEARCH %s: got %v, want %v", criteria, got, want)
}

func portSearchSize(s *Session) error {
	if _, _, err := portMailbox(s, "search-size", -1, true); err != nil {
		return err
	}
	fetched, err := coreFetch(s.Client, "FETCH 1:4 RFC822.SIZE")
	if err != nil {
		return err
	}
	var size uint64
	for _, f := range fetched {
		if f.Seq == 3 {
			size, err = f.Attrs["RFC822.SIZE"].Uint()
			if err != nil {
				return err
			}
		}
	}
	if err := Check(size > 0, "FETCH did not provide fixture 3's RFC822.SIZE"); err != nil {
		return err
	}
	return portRunSearchSteps(s.Client, "search-size", []portSearchStep{
		{fmt.Sprintf("SEARCH SMALLER %d", size), []uint64{1, 2}, true, 9},
		{fmt.Sprintf("SEARCH LARGER %d", size), []uint64{4}, true, 11},
		{fmt.Sprintf("SEARCH NOT SMALLER %d", size), []uint64{3, 4}, true, 13},
		{fmt.Sprintf("SEARCH NOT LARGER %d", size), []uint64{1, 2, 3}, true, 15},
		{fmt.Sprintf("SEARCH NOT SMALLER %d NOT LARGER %d", size, size), []uint64{3}, true, 18},
		{fmt.Sprintf("SEARCH OR SMALLER %d LARGER %d", size, size), []uint64{1, 2, 4}, true, 20},
	})
}
