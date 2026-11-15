package imap

import (
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// Capability names are case-insensitive (RFC 9051 §9, note 1: "Implementations
// MUST accept these strings in a case-insensitive fashion"), but disabled_caps
// and client_filters looked them up as written, so "idle" and "condstore"
// matched nothing and IDLE and CONDSTORE stayed advertised (#1114). A filter
// still cannot take IMAP4rev1 away, whatever its case: go-imap picks the wire
// version from the server-global set, and this server has no IMAP4rev2 left.
func TestDisabledCaps_NamesAreCaseInsensitive(t *testing.T) {
	c := dialWireCapServer(t, IMAPServerOptions{
		DisabledCaps: []string{"idle"},
		CapabilityFilters: []config.ClientCapabilityFilter{{
			ClientName:  "^ExampleMail$",
			DisableCaps: []string{"condstore", "imap4rev1"},
			Reason:      "example: lowercase capability",
		}},
	})
	c.mustOK(`ID ("name" "ExampleMail")`)
	caps := parseWireCaps(t, c.mustOK("CAPABILITY"))
	for _, gone := range []string{"IDLE", "IMAP4rev2", "CONDSTORE", "QRESYNC"} {
		if slices.Contains(caps, gone) {
			t.Errorf("disabled_caps = [idle], disable_caps = [condstore]: CAPABILITY still advertises %s: %v", gone, caps)
		}
	}
	for _, kept := range []string{"IMAP4rev1", "MOVE"} {
		if !slices.Contains(caps, kept) {
			t.Errorf("CAPABILITY lost %s: %v", kept, caps)
		}
	}
}

// A disabled_caps or disable_caps name that is no capability the server can
// withdraw does nothing. disabled_caps logged it at DEBUG and disable_caps not at
// all, so at the default level a typo, or a capability go-imap adds by itself
// such as ACL, went unnoticed (#1114). PREVIEW counts as withdrawable when it is
// enabled, and a lowercase name is not a typo.
func TestDisabledCaps_UnknownNameWarns(t *testing.T) {
	logs := &syncLogBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer logger.Swap(prev)

	newDisabledCapsTestServer(t, IMAPServerOptions{
		DisabledCaps: []string{"IDEL", "move"},
		Preview:      PreviewOptions{Enabled: true},
		CapabilityFilters: []config.ClientCapabilityFilter{{
			ClientName:  "^ExampleMail$",
			DisableCaps: []string{"CONDSTOR", "ACL", "preview"},
		}},
	})

	out := logs.String()
	warned := func(capability string) string {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line+" ", " capability="+capability+" ") {
				return line
			}
		}
		return ""
	}
	if line := warned("IDEL"); line == "" {
		t.Errorf("disabled_caps = [IDEL]: no WARN; WARN output:\n%s", out)
	}
	for _, capability := range []string{"CONDSTOR", "ACL"} {
		line := warned(capability)
		if line == "" {
			t.Errorf("client_filters disable_caps = [%s]: no WARN; WARN output:\n%s", capability, out)
			continue
		}
		if !strings.Contains(line, "entry=1") {
			t.Errorf("client_filters disable_caps = [%s]: WARN does not name the entry: %s", capability, line)
		}
	}
	for _, capability := range []string{"move", "preview"} {
		if line := warned(capability); line != "" {
			t.Errorf("%s is a capability the server can withdraw, but: %s", capability, line)
		}
	}
}

// AUTH=PLAIN was in the configured set, so disabled_caps and client_filters
// deleted it from that set and the startup log said it was disabled. But go-imap
// builds the AUTH= list from the session's AuthenticateMechanisms, never from the
// set, so clients still saw AUTH=PLAIN and could AUTHENTICATE PLAIN (#1323). It is
// one of the names the server cannot withdraw (it follows tls, tls_use_starttls
// and insecure_auth), so naming it must WARN like STARTTLS and ACL do, and no
// INFO line may claim it was disabled.
func TestDisabledCaps_AuthPlainCannotBeWithdrawn(t *testing.T) {
	logs := &syncLogBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer logger.Swap(prev)

	c := dialWireCapServerNotAuthenticated(t, IMAPServerOptions{
		DisabledCaps: []string{"AUTH=PLAIN"},
		CapabilityFilters: []config.ClientCapabilityFilter{{
			ClientName:  "^ExampleMail$",
			DisableCaps: []string{"auth=plain"},
		}},
	})
	c.mustOK(`ID ("name" "ExampleMail")`)
	if caps := parseWireCaps(t, c.mustOK("CAPABILITY")); !slices.Contains(caps, "AUTH=PLAIN") {
		t.Fatalf("CAPABILITY before login lost AUTH=PLAIN: %v", caps)
	}

	out := logs.String()
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "level=INFO") && strings.Contains(strings.ToUpper(line), "AUTH=PLAIN") {
			t.Errorf("INFO line claims AUTH=PLAIN was disabled: %s", line)
		}
	}
	warned := func(capability string) string {
		for _, line := range lines {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, `capability="`+capability+`"`) {
				return line
			}
		}
		return ""
	}
	if warned("AUTH=PLAIN") == "" {
		t.Errorf("disabled_caps = [AUTH=PLAIN]: no WARN; output:\n%s", out)
	}
	if line := warned("auth=plain"); line == "" {
		t.Errorf("client_filters disable_caps = [auth=plain]: no WARN; output:\n%s", out)
	} else if !strings.Contains(line, "entry=1") {
		t.Errorf("client_filters disable_caps = [auth=plain]: WARN does not name the entry: %s", line)
	}
}
