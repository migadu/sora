//go:build integration

package pop3proxy

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server/proxy"
	"github.com/stretchr/testify/require"
)

type trustedMetadataLog struct {
	sync.Mutex
	bytes.Buffer
}

func (w *trustedMetadataLog) Write(p []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	return w.Buffer.Write(p)
}
func (w *trustedMetadataLog) text() string { w.Lock(); defer w.Unlock(); return w.Buffer.String() }

func TestTrustedPOPBackendKeepsMetadataWithProxyHeader(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	var logs trustedMetadataLog
	old := logger.Swap(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer logger.Swap(old)
	backend, owner := common.SetupPOP3ServerWithPROXY(t)
	defer backend.Close()
	cm, err := proxy.NewConnectionManager([]string{backend.Address}, 110, false, false, true, 3*time.Second)
	require.NoError(t, err)
	srv := &POP3ProxyServer{name: "review", hostname: "review-metadata-proxy", connManager: cm, remoteUseXCLIENT: true}
	srv.settings.Store(&reloadableSettings{masterSASLUsername: "proxyuser", masterSASLPassword: "proxypass"})
	_, client := tcpPair(t)
	sess := &POP3ProxySession{server: srv, clientConn: client, listenerConn: client, ctx: context.Background(), username: owner.Email,
		sessionID: "review-pop-proxy-session", routingInfo: &proxy.UserRoutingInfo{RemoteUseXCLIENT: true}}
	require.NoError(t, sess.connectToBackend())
	defer sess.backendConn.Close()
	var processed string
	for _, line := range strings.Split(logs.text(), "\n") {
		if strings.Contains(line, "processed xclient forwarding parameters") {
			processed = line
			break
		}
	}
	t.Logf("real trusted Sora backend accepted metadata: %s", processed)
	require.NotEmpty(t, processed, "backend lost the previously accepted XCLIENT metadata")
	// Current PROXY TLV support carries SESSION independently of XCLIENT.
	require.Contains(t, logs.text(), "proxy_session=review-pop-proxy-session")
	require.Contains(t, processed, "ttl=9")
	require.Contains(t, processed, "variables_count=3")
}
