package delivery

import (
	"context"
	"testing"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
)

// captureDeliveryHash records the RecipientInfo delivery hands to Sieve, which
// carries the retry identity (DeliveryHash) the redirect dedup is keyed on.
type captureDeliveryHash struct {
	captureSieveExecutor
	deliveryHash string
}

func (c *captureDeliveryHash) ExecuteSieve(ctx context.Context, recipient RecipientInfo, entity *message.Entity, raw []byte) (*SieveOutcome, error) {
	c.deliveryHash = recipient.DeliveryHash
	return c.captureSieveExecutor.ExecuteSieve(ctx, recipient, entity, raw)
}

// TestDeliverMessage_NULPartKeepsRawDeliveryHash: the retry identity is the
// submission exactly as received. A binary message M and a separate submission
// of EncodeNULParts(M) are stored alike, but they are two submissions: they must
// not share a DeliveryHash, or the second is absorbed as a retry of the first.
// Each submission's own retry keeps its identity.
func TestDeliverMessage_NULPartKeepsRawDeliveryHash(t *testing.T) {
	addr, err := server.NewAddress("user@example.com")
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	raw := []byte("From: sender@example.org\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" +
		"raw\x00body\r\n--b--\r\n")
	encoded, changed, _ := helpers.EncodeNULParts(raw, nil)
	if !changed || helpers.HashContent(raw) == helpers.HashContent(encoded) {
		t.Fatal("fixture must have distinct raw and stored forms")
	}

	for _, tc := range []struct {
		name  string
		input []byte
	}{
		{"binary submission", raw},
		{"already encoded submission", encoded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for attempt := 1; attempt <= 2; attempt++ {
				capture := &captureDeliveryHash{}
				dctx := &DeliveryContext{
					Ctx:           context.Background(),
					Uploader:      &uploader.UploadWorker{},
					Hostname:      "mx.example.com",
					MetricsLabel:  "http_delivery",
					SieveExecutor: capture,
					Logger:        nopDeliveryLogger{},
				}
				if res, err := dctx.DeliverMessage(RecipientInfo{AccountID: 1, Address: &addr, ToAddress: &addr}, tc.input); err != nil {
					t.Fatalf("DeliverMessage failed: %v (result=%+v)", err, res)
				}
				if !capture.called {
					t.Fatal("DeliverMessage did not reach the Sieve executor")
				}
				if got, want := capture.deliveryHash, helpers.HashContent(tc.input); got != want {
					t.Errorf("attempt %d: DeliveryHash = %s, want the hash of the submission as received %s", attempt, got, want)
				}
			}
		})
	}
}
