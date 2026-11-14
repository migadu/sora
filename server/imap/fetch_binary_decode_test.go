package imap

import (
	"context"
	"errors"
	"testing"

	"github.com/migadu/go-imap"
)

// binaryDecodeTestBody has a decodable part 1 (base64 text, "line1\nline2\n")
// and a part 2 under a transfer encoding the server cannot decode.
const binaryDecodeTestBody = "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
	"--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nbGluZTEKbGluZTIK\r\n" +
	"--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 a.txt\r\nend\r\n" +
	"--b--\r\n"

// decodeBinary holds the decoded sections, charged to the session budget,
// until the FETCH response is written, and gives the charge back when a later
// item fails with NO [UNKNOWN-CTE].
func TestFetch_DecodeBinaryChargesAndRefusesUnknownCTE(t *testing.T) {
	body := []byte(binaryDecodeTestBody)
	msg := fetchTestMessage(body)

	s, tracker := newFetchTestSession(0)
	bodyData, bodyFetched := body, true
	b, err := s.decodeBinary(context.Background(), &bodyData, &bodyFetched, &imap.FetchOptions{
		BinarySection:     []*imap.FetchItemBinarySection{{Part: []int{1}}},
		BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{1}}},
	}, msg)
	if err != nil {
		t.Fatalf("decodeBinary: %v", err)
	}
	const want = "line1\r\nline2\r\n"
	if got := string(b.sections[0]); got != want || b.sizes[0] != uint32(len(want)) {
		t.Errorf("decoded %q (size %d), want %q (size %d)", got, b.sizes[0], want, len(want))
	}
	if got := tracker.Current(); got != int64(len(want)) || b.charged != got {
		t.Errorf("tracker = %d, charged = %d, want %d", got, b.charged, len(want))
	}
	s.freeSectionCopies(b.charged)

	for _, options := range []*imap.FetchOptions{
		{BinarySection: []*imap.FetchItemBinarySection{{Part: []int{1}}, {Part: []int{2}}}},
		{BinarySection: []*imap.FetchItemBinarySection{{Part: []int{1}}}, BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{2}}}},
	} {
		_, err := s.decodeBinary(context.Background(), &bodyData, &bodyFetched, options, msg)
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != imap.ResponseCodeUnknownCTE {
			t.Errorf("error = %v, want NO [UNKNOWN-CTE]", err)
		}
		if got := tracker.Current(); got != 0 {
			t.Errorf("tracker after refusal = %d bytes, want 0", got)
		}
	}

	// A body that cannot be loaded still answers with empty sections.
	var noBody []byte
	b, err = s.decodeBinary(context.Background(), &noBody, &bodyFetched, &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{{Part: []int{2}}},
	}, msg)
	if err != nil || len(b.sections) != 1 || b.sections[0] != nil {
		t.Errorf("decodeBinary without a body = %+v, %v; want one empty section", b, err)
	}
}
