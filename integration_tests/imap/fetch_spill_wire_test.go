//go:build integration

package imap_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// The unit test proves one extraction per retained section; this wire control
// checks large binary/body chunks and their echoed origins through actual
// APPEND, storage, FETCH encoding and the client parser.
func TestIMAP_LargeSectionSpillWire(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	c, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), (9<<20)/16)
	encoded := base64.StdEncoding.EncodeToString(payload)
	raw := "From: a@example.com\r\nSubject: spill wire\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n"
	appendRaw(t, c, "INBOX", raw, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	for _, binary := range []bool{true, false} {
		for _, offset := range []int64{0, 65536} {
			partial := &imap.SectionPartial{Offset: offset, Size: 65536}
			opts := &imap.FetchOptions{}
			if binary {
				opts.BinarySection = []*imap.FetchItemBinarySection{{Part: []int{1}, Peek: true, Partial: partial}}
			} else {
				opts.BodySection = []*imap.FetchItemBodySection{{Part: []int{1}, Peek: true, Partial: partial}}
			}
			msgs, err := c.Fetch(imap.SeqSetNum(1), opts).Collect()
			if err != nil || len(msgs) != 1 {
				t.Fatalf("binary=%v offset=%d: messages=%d err=%v", binary, offset, len(msgs), err)
			}
			var got, want []byte
			var origin *imap.SectionPartial
			if binary {
				if len(msgs[0].BinarySection) != 1 {
					t.Fatal("missing BINARY section")
				}
				got, origin = msgs[0].BinarySection[0].Bytes, msgs[0].BinarySection[0].Section.Partial
				want = payload[offset : offset+65536]
			} else {
				if len(msgs[0].BodySection) != 1 {
					t.Fatal("missing BODY section")
				}
				got, origin = msgs[0].BodySection[0].Bytes, msgs[0].BodySection[0].Section.Partial
				want = []byte(encoded[offset : offset+65536])
			}
			if !bytes.Equal(got, want) || origin == nil || origin.Offset != offset {
				t.Fatalf("binary=%v offset=%d: bytes=%d origin=%v", binary, offset, len(got), origin)
			}
		}
	}
}
