package delivery

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/migadu/sora/server/uploader"
)

type nopDeliveryLogger struct{}

func (nopDeliveryLogger) Log(string, ...any) {}

type captureSieveExecutor struct {
	called bool
	entity *message.Entity
	raw    []byte
}

func (c *captureSieveExecutor) ExecuteSieve(_ context.Context, _ RecipientInfo, entity *message.Entity, fullMessageBytes []byte) (*SieveOutcome, error) {
	c.called = true
	c.entity = entity
	c.raw = append([]byte(nil), fullMessageBytes...)
	return &SieveOutcome{
		Discarded:     true,
		MessageBytes:  fullMessageBytes,
		MessageEntity: entity,
	}, nil
}

func TestParseMessageReader(t *testing.T) {
	t.Run("unknown charset", func(t *testing.T) {
		raw := "From: sender@example.com\r\n" +
			"To: user@example.com\r\n" +
			"Subject: Unknown charset\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=x-unknown\r\n" +
			"\r\n" +
			"Hello in an unknown charset.\r\n"

		gotBytes, entity, err := ParseMessageReader(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("ParseMessageReader failed on unknown charset: %v", err)
		}
		if !bytes.Equal(gotBytes, []byte(raw)) {
			t.Fatalf("ParseMessageReader altered bytes: got %q, want %q", gotBytes, raw)
		}
		if entity == nil {
			t.Fatal("ParseMessageReader returned nil entity")
		}
		if got := entity.Header.Get("Subject"); got != "Unknown charset" {
			t.Errorf("Subject = %q, want %q", got, "Unknown charset")
		}
	})

	t.Run("unknown or malformed transfer encoding", func(t *testing.T) {
		raw := "From: sender@example.com\r\n" +
			"To: user@example.com\r\n" +
			"Subject: Malformed encoding\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Content-Transfer-Encoding: 7bit <center>\r\n" +
			"\r\n" +
			"Hello with malformed encoding.\r\n"

		gotBytes, entity, err := ParseMessageReader(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("ParseMessageReader failed on unknown encoding: %v", err)
		}
		if !bytes.Equal(gotBytes, []byte(raw)) {
			t.Fatalf("ParseMessageReader altered bytes: got %q, want %q", gotBytes, raw)
		}
		if entity == nil {
			t.Fatal("ParseMessageReader returned nil entity")
		}
		if got := entity.Header.Get("Subject"); got != "Malformed encoding" {
			t.Errorf("Subject = %q, want %q", got, "Malformed encoding")
		}
	})

	t.Run("malformed MIME header rejected", func(t *testing.T) {
		raw := " Invalid: header\r\n\r\nbody\r\n"
		_, _, err := ParseMessageReader(strings.NewReader(raw))
		if err == nil {
			t.Fatal("ParseMessageReader accepted malformed MIME header, want error")
		}
	})
}

func TestDeliverMessage_UnknownCharsetAndEncoding(t *testing.T) {
	addr, err := server.NewAddress("user@example.com")
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	recipient := RecipientInfo{
		AccountID: 1,
		Address:   &addr,
		ToAddress: &addr,
	}

	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "unknown charset",
			raw: "From: sender@example.com\r\n" +
				"To: user@example.com\r\n" +
				"Subject: Unknown charset\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: text/plain; charset=x-unknown\r\n" +
				"\r\n" +
				"Body bytes.\r\n",
		},
		{
			name: "unknown transfer encoding",
			raw: "From: sender@example.com\r\n" +
				"To: user@example.com\r\n" +
				"Subject: Unknown encoding\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"Content-Transfer-Encoding: 7bit <center>\r\n" +
				"\r\n" +
				"Body bytes.\r\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sieveStub := &captureSieveExecutor{}
			dctx := &DeliveryContext{
				Ctx:           context.Background(),
				Uploader:      &uploader.UploadWorker{},
				Hostname:      "mx.example.com",
				MetricsLabel:  "http_delivery",
				SieveExecutor: sieveStub,
				Logger:        nopDeliveryLogger{},
			}

			res, err := dctx.DeliverMessage(recipient, []byte(tc.raw))
			if err != nil {
				t.Fatalf("DeliverMessage failed: %v (result=%+v)", err, res)
			}
			if !res.Success || !res.Discarded {
				t.Fatalf("unexpected DeliveryResult: %+v", res)
			}
			if !sieveStub.called || sieveStub.entity == nil {
				t.Fatal("DeliverMessage did not reach SieveExecutor with parsed entity")
			}
			if got := sieveStub.entity.Header.Get("Delivered-To"); got != "user@example.com" {
				t.Errorf("Delivered-To after trace re-parse = %q, want %q", got, "user@example.com")
			}
			if sieveStub.entity.Header.Get("Received") == "" {
				t.Errorf("Received header missing after trace re-parse:\n%s", string(sieveStub.raw))
			}
		})
	}

	t.Run("malformed MIME header rejected", func(t *testing.T) {
		sieveStub := &captureSieveExecutor{}
		dctx := &DeliveryContext{
			Ctx:           context.Background(),
			Uploader:      &uploader.UploadWorker{},
			Hostname:      "mx.example.com",
			MetricsLabel:  "http_delivery",
			SieveExecutor: sieveStub,
			Logger:        nopDeliveryLogger{},
		}
		res, err := dctx.DeliverMessage(recipient, []byte(" Invalid: header\r\n\r\nbody\r\n"))
		if err == nil {
			t.Fatalf("DeliverMessage accepted malformed MIME header: %+v", res)
		}
		if sieveStub.called {
			t.Error("SieveExecutor must not be called when initial MIME parse fails")
		}
	})
}

func setupDeliveryTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping database test in short mode")
	}
	conn, err := net.DialTimeout("tcp", "localhost:5432", time.Second)
	if err != nil {
		t.Skipf("PostgreSQL unavailable on localhost:5432: %v", err)
	}
	_ = conn.Close()

	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}
	cfg := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"},
			Port:  5432,
			User:  "postgres",
			Name:  dbName,
		},
	}
	rdb, err := resilient.NewResilientDatabase(context.Background(), cfg, true, true)
	if err != nil {
		t.Fatalf("NewResilientDatabase(%s): %v", dbName, err)
	}
	t.Cleanup(rdb.Close)
	return rdb
}

func TestExecuteSieve_HeaderEditsPreservedOnUnknownCharsetAndEncoding(t *testing.T) {
	rdb := setupDeliveryTestDatabase(t)
	ctx := context.Background()

	enabled := append(append([]string{}, sieveengine.DefaultSieveExtensions...), "editheader")

	cases := []struct {
		name       string
		scriptBody string
		rawMessage string
	}{
		{
			name: "editheader adds unknown charset",
			scriptBody: "addheader \"Content-Type\" \"text/plain; charset=x-unknown\";\r\n" +
				"addheader \"X-Tag\" \"kept\";\r\n",
			rawMessage: "From: sender@example.com\r\n" +
				"To: recipient@example.com\r\n" +
				"Subject: Plain message\r\n" +
				"\r\n" +
				"Hello.\r\n",
		},
		{
			name:       "editheader edits message with unknown charset",
			scriptBody: "addheader \"X-Tag\" \"kept\";\r\n",
			rawMessage: "From: sender@example.com\r\n" +
				"To: recipient@example.com\r\n" +
				"Subject: Already unknown charset\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: text/plain; charset=x-unknown\r\n" +
				"\r\n" +
				"Hello.\r\n",
		},
		{
			name:       "editheader edits message with unknown transfer encoding",
			scriptBody: "addheader \"X-Tag\" \"kept\";\r\n",
			rawMessage: "From: sender@example.com\r\n" +
				"To: recipient@example.com\r\n" +
				"Subject: Already unknown encoding\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"Content-Transfer-Encoding: 7bit <center>\r\n" +
				"\r\n" +
				"Hello.\r\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			email := fmt.Sprintf("sieve-charset-%d@example.com", time.Now().UnixNano())
			accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
				Email:     email,
				Password:  "testpassword123",
				IsPrimary: true,
				HashType:  "bcrypt",
			})
			if err != nil {
				t.Fatalf("CreateAccountWithRetry: %v", err)
			}

			marker := fmt.Sprintf("marker-%d", time.Now().UnixNano())
			script := fmt.Sprintf("require [\"editheader\"];\r\n# %s\r\n%s", marker, tc.scriptBody)
			sc, err := rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
			if err != nil {
				t.Fatalf("CreateScriptWithRetry: %v", err)
			}
			if err := rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
				t.Fatalf("SetScriptActiveWithRetry: %v", err)
			}

			toAddr, err := server.NewAddress(email)
			if err != nil {
				t.Fatalf("NewAddress: %v", err)
			}
			fromAddr, err := server.NewAddress("sender@example.com")
			if err != nil {
				t.Fatalf("NewAddress(from): %v", err)
			}

			msgBytes := []byte(tc.rawMessage)
			entity, err := server.ParseMessage(bytes.NewReader(msgBytes))
			if err != nil {
				t.Fatalf("server.ParseMessage setup: %v", err)
			}

			dctx := &DeliveryContext{
				Ctx:          ctx,
				RDB:          rdb,
				Hostname:     "mx.example.com",
				MetricsLabel: "http_delivery",
				Logger:       nopDeliveryLogger{},
			}
			exec := &StandardSieveExecutor{
				DeliveryCtx:     dctx,
				SieveExtensions: enabled,
			}

			outcome, err := exec.ExecuteSieve(ctx, RecipientInfo{
				AccountID:   accountID,
				Address:     &toAddr,
				ToAddress:   &toAddr,
				FromAddress: &fromAddr,
			}, entity, msgBytes)
			if err != nil {
				t.Fatalf("ExecuteSieve: %v", err)
			}

			if !strings.Contains(string(outcome.MessageBytes), "X-Tag: kept") {
				t.Errorf("ExecuteSieve dropped editheader edits from MessageBytes:\n%s", string(outcome.MessageBytes))
			}
			if outcome.MessageEntity == nil {
				t.Fatal("ExecuteSieve returned nil MessageEntity")
			}
			if got := outcome.MessageEntity.Header.Get("X-Tag"); got != "kept" {
				t.Errorf("MessageEntity Header X-Tag = %q, want %q", got, "kept")
			}
		})
	}
}
