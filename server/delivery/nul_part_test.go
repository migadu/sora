package delivery

import (
	"bytes"
	"context"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
)

// TestDeliverMessage_NULPartEncoded: an Admin API delivery of a binary part
// holding a NUL goes on (Sieve, then storage) with that part base64 encoded
// (#2051), as an IMAP APPEND stores it (#2011): FETCH BODY sends ordinary
// literals, which cannot carry NUL (RFC 9051 §4.3). BINARY[1] still gives the
// delivered octets.
func TestDeliverMessage_NULPartEncoded(t *testing.T) {
	addr, err := server.NewAddress("user@example.com")
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	const binaryBody = "\x00-\xe4\n\r\n\n"
	raw := "From: user@example.org\r\nMime-Version: 1.0\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" + binaryBody

	sieveStub := &captureSieveExecutor{}
	dctx := &DeliveryContext{
		Ctx:           context.Background(),
		Uploader:      &uploader.UploadWorker{},
		Hostname:      "mx.example.com",
		MetricsLabel:  "http_delivery",
		SieveExecutor: sieveStub,
		Logger:        nopDeliveryLogger{},
	}
	if res, err := dctx.DeliverMessage(RecipientInfo{AccountID: 1, Address: &addr, ToAddress: &addr}, []byte(raw)); err != nil {
		t.Fatalf("DeliverMessage failed: %v (result=%+v)", err, res)
	}
	if !sieveStub.called {
		t.Fatal("DeliverMessage did not reach the Sieve executor")
	}
	if bytes.IndexByte(sieveStub.raw, 0) >= 0 {
		t.Fatalf("delivery went on with the NUL-bearing part as it is:\n%q", sieveStub.raw)
	}
	decoded, err := imapserver.DecodeBinarySection(bytes.NewReader(sieveStub.raw), &imap.FetchItemBinarySection{Part: []int{1}})
	if err != nil || string(decoded) != binaryBody {
		t.Fatalf("BINARY[1] = %q, %v; want %q", decoded, err, binaryBody)
	}
}
