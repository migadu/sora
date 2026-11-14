package imap

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
)

// fetchBinaryItems are FETCH requests that carry BINARY's FETCH items.
var fetchBinaryItems = []struct {
	name    string
	options *imap.FetchOptions
}{
	{"FETCH (BINARY.PEEK[1])", &imap.FetchOptions{BinarySection: []*imap.FetchItemBinarySection{{Part: []int{1}, Peek: true}}}},
	{"FETCH (BINARY[1])", &imap.FetchOptions{BinarySection: []*imap.FetchItemBinarySection{{Part: []int{1}}}}},
	{"FETCH (BINARY.SIZE[1])", &imap.FetchOptions{BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{1}}}}},
	{"FETCH (FLAGS BINARY.SIZE[1])", &imap.FetchOptions{Flags: true, BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{1}}}}},
}

func callFetch(s *IMAPSession, options *imap.FetchOptions) error {
	return callHandler(func() error {
		return s.Fetch(context.Background(), nil, imap.SeqSetNum(1), options)
	})
}

func isBad(err error) bool {
	var imapErr *imap.Error
	return errors.As(err, &imapErr) && imapErr.Type == imap.StatusResponseTypeBad
}

// RFC 9051 Appendix B: "IMAP4rev2 incorporates a subset of functionality
// provided by the BINARY extension [RFC3516]; in particular, it includes
// additional FETCH items (BINARY, BINARY.PEEK, and BINARY.SIZE) but not
// extensions to the APPEND command." Once a session offers neither BINARY nor
// IMAP4rev2, FETCH must refuse the items with BAD instead of answering
// without them, which could be "* 1 FETCH ()" (#606).
func TestDisabledCaps_RefusesFetchBinaryWithoutBinaryAndIMAP4rev2(t *testing.T) {
	for _, disabled := range [][]string{{"BINARY", "IMAP4rev2"}, {"BINARY", "IDLE"}} {
		srv := newDisabledCapsTestServer(t, IMAPServerOptions{DisabledCaps: disabled})
		s := newDisabledCapsTestSession(srv)
		for _, tc := range fetchBinaryItems {
			assertRefusedAsBad(t, fmt.Sprintf("disabled_caps = %v", disabled), tc.name, callFetch(s, tc.options))
		}
	}
}

func TestClientFilter_RefusesFetchBinaryWithoutBinaryAndIMAP4rev2(t *testing.T) {
	disabled := []string{"BINARY", "IMAP4rev2"}
	srv := newDisabledCapsTestServer(t, IMAPServerOptions{CapabilityFilters: []config.ClientCapabilityFilter{{
		ClientName:  "^buggy$",
		DisableCaps: disabled,
	}}})
	s := newDisabledCapsTestSession(srv)
	caps := srv.caps.Copy()
	srv.filterCapabilitiesForClient(caps, &imap.IDData{Name: "buggy"}, "")
	s.sessionCaps.Store(caps)
	for _, tc := range fetchBinaryItems {
		assertRefusedAsBad(t, fmt.Sprintf("client filter disable_caps = %v", disabled), tc.name, callFetch(s, tc.options))
	}
}

// Either capability alone offers the FETCH items: BINARY (RFC 3516 §4.2), or
// IMAP4rev2, which keeps them when BINARY is disabled (RFC 9051 Appendix B).
// The test session has no mailbox selected, so an accepted FETCH ends in NO.
func TestDisabledCaps_KeepsFetchBinaryWithBinaryOrIMAP4rev2(t *testing.T) {
	for _, disabled := range [][]string{{"BINARY"}, {"IMAP4rev2"}, nil} {
		srv := newDisabledCapsTestServer(t, IMAPServerOptions{DisabledCaps: disabled})
		s := newDisabledCapsTestSession(srv)
		for _, tc := range fetchBinaryItems {
			if err := callFetch(s, tc.options); isBad(err) {
				t.Errorf("disabled_caps = %v: %s was refused with BAD: %v", disabled, tc.name, err)
			}
		}
	}
}
