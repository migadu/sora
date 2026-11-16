//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bodyCaptureRelayQueue records the bytes of every message handed to the relay.
type bodyCaptureRelayQueue struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (q *bodyCaptureRelayQueue) Enqueue(from, to, messageType string, messageBytes []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.bodies = append(q.bodies, slices.Clone(messageBytes))
	return nil
}

// Hold records the message when it is committed, which is when the relay worker
// would first see it.
func (q *bodyCaptureRelayQueue) Hold(from, to, messageType string, messageBytes []byte) (func() error, func(), error) {
	return func() error { return q.Enqueue(from, to, messageType, messageBytes) }, func() {}, nil
}

func (q *bodyCaptureRelayQueue) snapshot() [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	return slices.Clone(q.bodies)
}

// TestDelivery_SieveRedirectHops_DeleteheaderKeepsCount is issue #1624 on the Admin
// API /deliver path: with editheader enabled, a script that deletes X-Sora-Loop and
// Delivered-To before redirect must not restart the redirect hop count. Each redirect
// is stamped one above the count the message arrived with, so a message fed back
// through the same script is redirected max_redirect_hops times and then kept.
func TestDelivery_SieveRedirectHops_DeleteheaderKeepsCount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB

	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	require.NoError(t, err)

	script := strings.Join([]string{
		`require ["editheader"];`,
		`deleteheader "X-Sora-Loop";`,
		`deleteheader "Delivered-To";`,
		`redirect "other@example.org";`,
	}, "\r\n") + "\r\n"
	const maxHops = 2
	rq := &bodyCaptureRelayQueue{}
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, script)
	executor := dctx.SieveExecutor.(*delivery.StandardSieveExecutor)
	executor.SieveExtensions = sieveengine.EffectiveExtensions(append(slices.Clone(sieveengine.DefaultSieveExtensions), "editheader"))
	executor.MaxRedirectHops = maxHops
	executor.RelayQueue = rq

	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	sender, err := server.NewAddress("sender@example.com")
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr, FromAddress: &sender}
	inboxBefore := countLiveInMailbox(t, rdb, accountID, "INBOX")

	msg := []byte(fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: redirect hops\r\nMessage-ID: <%d@example.com>\r\n\r\nbody\r\n",
		account.Email, time.Now().UnixNano()))
	for pass := 1; pass <= maxHops+2; pass++ {
		before := len(rq.snapshot())
		res, err := dctx.DeliverMessage(recipient, msg)
		require.NoError(t, err, "pass %d", pass)
		require.True(t, res.Success, "pass %d: delivery must succeed (result=%+v)", pass, res)
		relayed := rq.snapshot()
		if len(relayed) == before {
			break // not redirected: kept
		}
		msg = relayed[len(relayed)-1]
		parsed, err := mail.ReadMessage(strings.NewReader(string(msg)))
		require.NoError(t, err, "pass %d: parse relayed message", pass)
		assert.Equal(t, pass, helpers.RedirectHopCount(helpers.HeaderGetter(parsed.Header)),
			"pass %d: the redirected copy's %s must be one above the count it arrived with", pass, helpers.RedirectLoopHeader)
	}

	assert.Equal(t, maxHops, len(rq.snapshot()), "the message must be redirected max_redirect_hops times")
	assert.Equal(t, 1, countLiveInMailbox(t, rdb, accountID, "INBOX")-inboxBefore,
		"the redirect refused at the hop limit keeps the message")
}
