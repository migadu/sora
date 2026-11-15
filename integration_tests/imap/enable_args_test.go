//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENABLE takes at least one capability name: enable = "ENABLE" 1*(SP
// capability) (RFC 9051 §9, RFC 5161 §4), and a bare ENABLE is "BAD - No
// arguments, or syntax error in an argument" (RFC 9051 §6.3.1, RFC 5161 §3.1).
// It was answered "* ENABLED" and OK.
func TestIMAP_EnableWithoutCapabilityIsBAD(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	for _, command := range []string{`ENABLE`, `ENABLE `} {
		untagged, tagged := rc.cmd("A", command)
		assert.True(t, strings.HasPrefix(tagged, "A BAD [CLIENTBUG]"), "%q: %s (untagged %q)", command, tagged, untagged)
		assert.Empty(t, untagged, "%q", command)
		_, tagged = rc.cmd("N", "NOOP")
		require.True(t, strings.HasPrefix(tagged, "N OK"), "NOOP after %q: %s", command, tagged)
	}

	// With a capability ENABLE is served, an unknown one ignored: "the server
	// MUST ignore the argument" (RFC 9051 §6.3.1).
	for _, tc := range []struct{ command, want string }{
		{`ENABLE X-UNKNOWN`, "* ENABLED"},
		{`ENABLE X-UNKNOWN CONDSTORE`, "* ENABLED CONDSTORE"},
	} {
		untagged, tagged := rc.cmd("G", tc.command)
		require.True(t, strings.HasPrefix(tagged, "G OK"), "%s: %s", tc.command, tagged)
		require.Equal(t, []string{tc.want}, untagged, "%s", tc.command)
	}
}
