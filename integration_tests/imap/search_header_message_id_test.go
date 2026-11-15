//go:build integration

package imap_test

import (
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchHeaderMessageIDSubstring: RFC 9051 §6.4.4, HEADER <field-name> <string>:
// "Messages that have a header field with the specified field-name (as defined in
// [RFC5322]) and that contain the specified string in the text of the header field (what
// comes after the colon). If the string to search is zero-length, this matches all
// messages that have a header field with the specified field-name regardless of the
// contents. Servers should use a substring search for this SEARCH item, ... For example,
// this can be used when searching for Message-ID ... header field values that need to be
// exact". Message-ID compared the bracket-stripped term with the stored ID for equality,
// so a part of the ID matched nothing (#529).
func TestIMAP_SearchHeaderMessageIDSubstring(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}

	appendMsg := func(msg string) imap.UID {
		t.Helper()
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close: %v", err)
		}
		data, err := ac.Wait()
		if err != nil {
			t.Fatalf("APPEND: %v", err)
		}
		return data.UID
	}
	m1 := appendMsg("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: one\r\n" +
		"Message-ID: <m1@example.com>\r\n\r\nbody\r\n")
	am1 := appendMsg("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: two\r\n" +
		"Message-ID: <am1@Example.ORG>\r\n\r\nbody\r\n")
	// No Message-ID header: HEADER Message-ID must never match it, not even the empty
	// string, and every NOT HEADER Message-ID must.
	noID := appendMsg("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: three\r\n\r\nbody\r\n")

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT: %v", err)
	}

	header := func(value string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: value}}}
	}
	notHeader := func(value string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Not: []imap.SearchCriteria{*header(value)}}
	}
	for _, tc := range []struct {
		name     string
		criteria *imap.SearchCriteria
		want     []imap.UID
	}{
		{"part of the ID (the issue)", header("m1"), []imap.UID{m1, am1}},
		{"full ID with brackets", header("<m1@example.com>"), []imap.UID{m1}},
		{"full ID without brackets", header("m1@example.com"), []imap.UID{m1}},
		{"full ID, other case", header("<AM1@example.org>"), []imap.UID{am1}},
		{"opening bracket and local part", header("<am1@"), []imap.UID{am1}},
		{"domain and closing bracket", header("@EXAMPLE.com>"), []imap.UID{m1}},
		{"no such ID", header("<m2@example.com>"), nil},
		{"present (empty string)", header(""), []imap.UID{m1, am1}},
		{"NOT full ID", notHeader("<m1@example.com>"), []imap.UID{am1, noID}},
		{"NOT part of the ID", notHeader("m1"), []imap.UID{noID}},
		{"NOT present", notHeader(""), []imap.UID{noID}},
	} {
		data, err := c.UIDSearch(tc.criteria, nil).Wait()
		if err != nil {
			t.Errorf("%s: UID SEARCH failed: %v", tc.name, err)
			continue
		}
		got := data.AllUIDs()
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: UID SEARCH = %v, want %v", tc.name, got, tc.want)
		}
	}
}
