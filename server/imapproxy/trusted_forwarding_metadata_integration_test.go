//go:build integration

package imapproxy

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/proxy"
	"github.com/stretchr/testify/require"
)

func TestTrustedIMAPBackendKeepsMetadataWithProxyHeader(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, owner := common.SetupIMAPServerWithPROXY(t)
	defer backend.Close()
	cm, err := proxy.NewConnectionManager([]string{backend.Address}, 143, false, false, true, 3*time.Second)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{name: "review", hostname: "review-metadata-proxy", ctx: ctx, cancel: cancel,
		activeSessions: make(map[*Session]struct{}), connManager: cm, authLimiter: &fakeAuthLimiter{}, remoteUseIDCommand: true}
	_, client := tcpPair(t)
	sess := newSession(srv, client)
	sess.username = owner.Email
	sess.routingInfo = &proxy.UserRoutingInfo{RemoteUseIDCommand: true}
	require.NoError(t, sess.connectToBackend())
	defer sess.backendConn.Close()
	require.NoError(t, sess.backendConn.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = fmt.Fprint(sess.backendConn, "review ID NIL\r\n")
	require.NoError(t, err)
	var lines []string
	for {
		line, err := sess.backendReader.ReadString('\n')
		require.NoError(t, err)
		lines = append(lines, line)
		if strings.HasPrefix(line, "review ") {
			require.Contains(t, line, "review OK")
			break
		}
	}
	response := strings.Join(lines, "")
	t.Logf("real trusted Sora backend ID response: %s", response)
	require.Contains(t, response, `"x-forward-proxy-server" "review-metadata-proxy"`)
	require.Contains(t, response, `"x-forward-proxy-user" "`+owner.Email+`"`)
	require.Contains(t, response, `"x-proxy-ttl" "9"`)
}
