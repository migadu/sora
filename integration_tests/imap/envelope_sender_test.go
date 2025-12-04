//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestEnvelopeSender tests that ENVELOPE returns correct Sender field
// This reproduces imaptest "fetch-envelope command" test 1
//
// According to imaptest failure:
// Expected: Sender field = "Sender Real" <senderuser@senderdomain.org>
// Actual:   Sender field = "From Real" <fromuser@fromdomain.org> (WRONG - should not default to From)
//
// RFC 3501 says: The Sender field is the sender mailbox, defaulting to From if absent.
// But if Sender: header exists, it must be used, not From.
func TestEnvelopeSenderField(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select failed: %v", err)
	}

	// Message with BOTH From and Sender headers (this is the critical test)
	msg := `Date: Thu, 15 Feb 2007 01:02:03 +0200
From: "From Real" <fromuser@fromdomain.org>
Sender: "Sender Real" <senderuser@senderdomain.org>
Reply-To: "ReplyTo Real" <replytouser@replytodomain.org>
To: "To Real" <touser@todomain.org>
Cc: "Cc Real" <ccuser@ccdomain.org>
Bcc: "Bcc Real" <bccuser@bccdomain.org>
Subject: subject header
Message-ID: <msg@id>
In-Reply-To: <reply@to.id>

Body text
`

	appendCmd := c.Append("INBOX", int64(len(msg)), nil)
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Fetch ENVELOPE
	fetchCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		Envelope: true,
	})

	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Envelope == nil {
		t.Fatal("Expected ENVELOPE in response")
	}

	env := msgs[0].Envelope

	// Check From field
	if len(env.From) != 1 {
		t.Fatalf("Expected 1 From address, got %d", len(env.From))
	}
	t.Logf("From: %q <%s@%s>", env.From[0].Name, env.From[0].Mailbox, env.From[0].Host)
	if env.From[0].Name != "From Real" {
		t.Errorf("From name: expected 'From Real', got '%s'", env.From[0].Name)
	}
	if env.From[0].Mailbox != "fromuser" {
		t.Errorf("From mailbox: expected 'fromuser', got '%s'", env.From[0].Mailbox)
	}
	if env.From[0].Host != "fromdomain.org" {
		t.Errorf("From host: expected 'fromdomain.org', got '%s'", env.From[0].Host)
	}

	// THIS IS THE CRITICAL CHECK: Sender field
	// It MUST be the Sender header, NOT default to From
	if len(env.Sender) != 1 {
		t.Fatalf("Expected 1 Sender address, got %d", len(env.Sender))
	}

	t.Logf("Sender: %q <%s@%s>", env.Sender[0].Name, env.Sender[0].Mailbox, env.Sender[0].Host)

	if env.Sender[0].Name != "Sender Real" {
		t.Errorf("ENVELOPE SENDER BUG: Sender name should be 'Sender Real', not 'From Real'. Got '%s'",
			env.Sender[0].Name)
	}
	if env.Sender[0].Mailbox != "senderuser" {
		t.Errorf("ENVELOPE SENDER BUG: Sender mailbox should be 'senderuser', not 'fromuser'. Got '%s'",
			env.Sender[0].Mailbox)
	}
	if env.Sender[0].Host != "senderdomain.org" {
		t.Errorf("ENVELOPE SENDER BUG: Sender host should be 'senderdomain.org', not 'fromdomain.org'. Got '%s'",
			env.Sender[0].Host)
	}

	// Also check Reply-To to ensure we're parsing all fields correctly
	if len(env.ReplyTo) != 1 {
		t.Fatalf("Expected 1 Reply-To address, got %d", len(env.ReplyTo))
	}
	t.Logf("Reply-To: %q <%s@%s>", env.ReplyTo[0].Name, env.ReplyTo[0].Mailbox, env.ReplyTo[0].Host)

	t.Log("✓ ENVELOPE Sender field test completed")
}

// TestEnvelopeSenderDefaultsToFrom tests that Sender defaults to From when Sender header is absent
func TestEnvelopeSenderDefaultsToFrom(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select failed: %v", err)
	}

	// Message WITHOUT Sender header - should default to From
	msg := `Date: Thu, 15 Feb 2007 01:02:03 +0200
From: "From Real" <fromuser@fromdomain.org>
To: "To Real" <touser@todomain.org>
Subject: subject header

Body text
`

	appendCmd := c.Append("INBOX", int64(len(msg)), nil)
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Fetch ENVELOPE
	fetchCmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		Envelope: true,
	})

	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Envelope == nil {
		t.Fatal("Expected ENVELOPE in response")
	}

	env := msgs[0].Envelope

	// When Sender header is absent, Sender field should equal From field
	if len(env.From) != 1 || len(env.Sender) != 1 {
		t.Fatalf("Expected 1 From and 1 Sender, got %d and %d", len(env.From), len(env.Sender))
	}

	t.Logf("From: %q <%s@%s>", env.From[0].Name, env.From[0].Mailbox, env.From[0].Host)
	t.Logf("Sender: %q <%s@%s>", env.Sender[0].Name, env.Sender[0].Mailbox, env.Sender[0].Host)

	// Sender should default to From
	if env.Sender[0].Name != env.From[0].Name {
		t.Errorf("When Sender header absent, Sender name should equal From name. Got Sender='%s', From='%s'",
			env.Sender[0].Name, env.From[0].Name)
	}
	if env.Sender[0].Mailbox != env.From[0].Mailbox {
		t.Errorf("When Sender header absent, Sender mailbox should equal From mailbox")
	}
	if env.Sender[0].Host != env.From[0].Host {
		t.Errorf("When Sender header absent, Sender host should equal From host")
	}

	t.Log("✓ ENVELOPE Sender defaults to From test completed")
}
