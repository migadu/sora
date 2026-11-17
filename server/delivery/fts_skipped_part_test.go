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
	testDeliverMessageFTSBody(t, "", "hello words")
}

func TestDeliverMessage_FTSRelatedContentIDCFWS(t *testing.T) {
	testDeliverMessageFTSBody(t, "Content-Type: multipart/related; boundary=related; start=\"<root@example.com>\"\r\n\r\n--related\r\nContent-Type: text/plain\r\nContent-ID: <resource@example.com>\r\n\r\nauxiliarywords\r\n--related\r\nContent-Type: text/plain\r\nContent-ID: (selected) <root@example.com> (root)\r\n\r\nrootwords\r\n--related--\r\n", "rootwords")
}

func testDeliverMessageFTSBody(t *testing.T, mimeBody, want string) {
	t.Helper()
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
	if mimeBody == "" {
		mimeBody = "Content-Type: multipart/mixed; boundary=b1\r\n" +
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
	}
	raw := "From: sender@example.com\r\n" +
		"To: " + email + "\r\n" +
		"Subject: " + marker + "\r\n" +
		"Message-ID: <" + marker + "@example.com>\r\n" +
		"MIME-Version: 1.0\r\n" + mimeBody

	res, err := dctx.DeliverMessage(*recipient, []byte(raw))
	require.NoError(t, err, "DeliverMessage failed: result=%+v", res)
	require.True(t, res.Success)

	// The text is staged in text_body until the FTS worker turns it into
	// text_body_tsv (a worker of another test sharing the database may have run);
	// an empty text stages no row at all.
	var textBody string
	var indexed bool
	err = rdb.QueryRowWithRetry(ctx, `
		SELECT COALESCE(f.text_body, ''), COALESCE(f.text_body_tsv @@ plainto_tsquery('simple', $3), false)
		FROM messages m
		LEFT JOIN messages_fts_v2 f ON f.content_hash = m.content_hash AND f.account_id = m.account_id
		WHERE m.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL
	`, accountID, marker, want).Scan(&textBody, &indexed)
	require.NoError(t, err)
	require.True(t, strings.Contains(textBody, want) || indexed,
		"messages_fts_v2 must hold the text part's text, got text_body %q", textBody)
}

func TestDeliverMessage_FTSMalformedHTMLPreservesText(t *testing.T) {
	testDeliverMessageFTSBody(t, "Content-Type: text/html; charset=utf-8\r\n\r\n<p>I <3 this, it's great.</p><p>Price <$50 - don't miss</p><td width=50' >cell text</td><p>tailmarker</p>\r\n", "tailmarker")
}
