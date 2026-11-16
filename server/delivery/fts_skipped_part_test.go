package delivery

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/stretchr/testify/require"
)

// TestDeliverMessage_FTSKeepsTextBesideSkippedPart: ExtractPlaintextBody skips an
// inline part whose Content-Type parameters do not parse and still returns the text
// part, with an error naming the skipped part. Admin API delivery must stage that
// text for full-text search, as LMTP does; it staged "", so SEARCH BODY found the
// message only when LMTP had delivered it (#1808).
func TestDeliverMessage_FTSKeepsTextBesideSkippedPart(t *testing.T) {
	rdb := setupDeliveryTestDatabase(t)
	ctx := context.Background()

	email := fmt.Sprintf("delivery-fts-skipped-%d@example.com", time.Now().UnixNano())
	accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email:     email,
		Password:  "testpassword123",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)

	up, err := uploader.NewWithS3Interface(t.TempDir(), 10, 1, 3, time.Second, 0, "delivery-test", rdb, nil, nil, nil)
	require.NoError(t, err)
	dctx := &DeliveryContext{
		Ctx:          ctx,
		RDB:          rdb,
		Uploader:     up,
		Hostname:     "mx.example.com",
		InstanceID:   "delivery-test",
		MetricsLabel: "http_delivery",
		Logger:       nopDeliveryLogger{},
	}
	dctx.SieveExecutor = &StandardSieveExecutor{DeliveryCtx: dctx, VacationOracle: &VacationOracle{RDB: rdb}}

	recipient, err := dctx.LookupRecipient(ctx, email)
	require.NoError(t, err)
	fromAddr, err := server.NewAddress("sender@example.com")
	require.NoError(t, err)
	recipient.FromAddress = &fromAddr

	marker := fmt.Sprintf("fts-skipped-part-%d", time.Now().UnixNano())
	raw := "From: sender@example.com\r\n" +
		"To: " + email + "\r\n" +
		"Subject: " + marker + "\r\n" +
		"Message-ID: <" + marker + "@example.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b1\r\n" +
		"\r\n" +
		"--b1\r\n" +
		"Content-Type: image/png; name=a b.png\r\n" +
		"Content-Disposition: inline\r\n" +
		"\r\n" +
		"PNG\r\n" +
		"--b1\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"hello words\r\n" +
		"--b1--\r\n"

	res, err := dctx.DeliverMessage(*recipient, []byte(raw))
	require.NoError(t, err, "DeliverMessage failed: result=%+v", res)
	require.True(t, res.Success)

	// The text is staged in text_body until the FTS worker turns it into
	// text_body_tsv (a worker of another test sharing the database may have run);
	// an empty text stages no row at all.
	var textBody string
	var indexed bool
	err = rdb.QueryRowWithRetry(ctx, `
		SELECT COALESCE(f.text_body, ''), COALESCE(f.text_body_tsv @@ plainto_tsquery('simple', 'hello'), false)
		FROM messages m
		LEFT JOIN messages_fts_v2 f ON f.content_hash = m.content_hash AND f.account_id = m.account_id
		WHERE m.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL
	`, accountID, marker).Scan(&textBody, &indexed)
	require.NoError(t, err)
	require.True(t, strings.Contains(textBody, "hello words") || indexed,
		"messages_fts_v2 must hold the text part's text, got text_body %q", textBody)
}
