package imap

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
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

// heldBytes returns the octets the slices keep reachable: the capacity of each
// distinct backing array, which a slice keeps alive however short it is.
func heldBytes(slices [][]byte) int {
	held := make(map[*byte]int)
	for _, s := range slices {
		if c := cap(s); c > 0 {
			end := &s[:c][c-1] // shared by every slice of the same array
			held[end] = max(held[end], c)
		}
	}
	total := 0
	for _, c := range held {
		total += c
	}
	return total
}

// A FETCH can name one part many times over: a 50 KiB command line has room
// for some 2500 items like BINARY.PEEK[1]<0.1>. decodeBinary holds every item
// until the message's FETCH response is written, so an item must hold no more
// than it charges to the session budget. DecodeBinarySection returns a
// <partial> as a slice of the whole decoded section, which would otherwise stay
// reachable, uncharged, once per item.
func TestFetch_DecodeBinaryHoldsOnlyWhatItCharges(t *testing.T) {
	decoded := bytes.Repeat([]byte("0123456789abcdef"), 16*1024) // 256 KiB
	encoded := base64.StdEncoding.EncodeToString(decoded)
	var body strings.Builder
	body.WriteString("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	for len(encoded) > 76 {
		body.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	body.WriteString(encoded + "\r\n")

	const items, chunk = 64, 16
	options := &imap.FetchOptions{}
	for i := range items {
		options.BinarySection = append(options.BinarySection, &imap.FetchItemBinarySection{
			Part: []int{1}, Peek: true, Partial: &imap.SectionPartial{Offset: int64(i) * 4096, Size: chunk},
		})
	}

	bodyData := []byte(body.String())
	s, tracker := newFetchTestSession(0)
	bodyFetched := true
	b, err := s.decodeBinary(context.Background(), &bodyData, &bodyFetched, options, fetchTestMessage(bodyData))
	if err != nil {
		t.Fatalf("decodeBinary: %v", err)
	}
	defer s.freeSectionCopies(b.charged)

	for i, got := range b.sections {
		if want := decoded[i*4096 : i*4096+chunk]; !bytes.Equal(got, want) {
			t.Fatalf("section %d = %q, want %q", i, got, want)
		}
	}
	if held := heldBytes(b.sections); int64(held) > 2*b.charged {
		t.Errorf("%d items hold %d bytes, but charge %d (tracker %d)", items, held, b.charged, tracker.Current())
	}
}
