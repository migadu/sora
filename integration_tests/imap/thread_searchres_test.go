//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestIMAP_Thread_SearchRes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	for i := 1; i <= 3; i++ {
		c.appendMsg("INBOX", fmt.Sprintf("Message-ID: <thread%d@example.com>\r\nSubject: Solo %d\r\n\r\nbody\r\n", i, i))
	}
	c.do("SELECT INBOX")
	c.do("UID SEARCH RETURN (SAVE) UID 1,3")
	for _, tc := range []struct{ criteria, want string }{
		{"$", "* THREAD (1)(3)"},
		{"NOT $", "* THREAD (2)"},
		{"OR $ UID 2", "* THREAD (1)(2)(3)"},
	} {
		t.Run(tc.criteria, func(t *testing.T) {
			lines, _ := c.do("UID THREAD REFERENCES UTF-8 " + tc.criteria)
			var got string
			for _, line := range lines {
				if strings.HasPrefix(line, "* THREAD") {
					got = strings.TrimSpace(line)
				}
			}
			if got != tc.want {
				t.Errorf("THREAD %s = %q, want %q", tc.criteria, got, tc.want)
			}
		})
	}
}

func TestIMAP_Thread_RefusalMetric(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	c, done := dialSelected(t, &common.IMAPServerOpts{ThreadMaxMessages: 2})
	defer done()
	appendStandalone(t, c, 3)
	counter := metrics.IMAPSearchRefused.WithLabelValues("result_cap")
	before := testutil.ToFloat64(counter)
	_, err := c.UIDThread(&imapclient.ThreadOptions{Algorithm: imap.ThreadReferences, SearchCriteria: &imap.SearchCriteria{}}).Wait()
	if err == nil {
		t.Fatal("THREAD over cap succeeded")
	}
	if delta := testutil.ToFloat64(counter) - before; delta != 1 {
		t.Errorf("THREAD refusal metric delta = %v, want 1", delta)
	}
}
