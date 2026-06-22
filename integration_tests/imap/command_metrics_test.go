//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	dto "github.com/prometheus/client_model/go"
)

// TestIMAP_CommandMetricsCoverage verifies that the meteredSession wrapper
// (server/imap/metered.go) records sora_commands_total and
// sora_command_duration_seconds for commands that have no bespoke
// instrumentation of their own. Before the wrapper only FETCH and APPEND were
// tracked; this guards against that regression returning.
func TestIMAP_CommandMetricsCoverage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	client, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer client.Close()

	if err := client.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	const mailbox = "MetricsCoverageBox"

	// commandCount returns the current value of sora_commands_total for a given
	// command with status="success". WithLabelValues materializes the child at 0
	// if it does not exist yet, so a pre-run read is always safe.
	commandCount := func(command string) float64 {
		return testutil.ToFloat64(metrics.CommandsTotal.WithLabelValues("imap", command, "success"))
	}

	// Each entry runs one command and names the label it must bump.
	cases := []struct {
		command string
		run     func(t *testing.T)
	}{
		{"CREATE", func(t *testing.T) {
			if err := client.Create(mailbox, nil).Wait(); err != nil {
				t.Fatalf("CREATE failed: %v", err)
			}
		}},
		{"SELECT", func(t *testing.T) {
			if _, err := client.Select("INBOX", nil).Wait(); err != nil {
				t.Fatalf("SELECT failed: %v", err)
			}
		}},
		{"STATUS", func(t *testing.T) {
			if _, err := client.Status(mailbox, &imap.StatusOptions{NumMessages: true}).Wait(); err != nil {
				t.Fatalf("STATUS failed: %v", err)
			}
		}},
		{"SUBSCRIBE", func(t *testing.T) {
			if err := client.Subscribe(mailbox).Wait(); err != nil {
				t.Fatalf("SUBSCRIBE failed: %v", err)
			}
		}},
		{"LIST", func(t *testing.T) {
			if _, err := client.List("", "*", nil).Collect(); err != nil {
				t.Fatalf("LIST failed: %v", err)
			}
		}},
	}

	for _, tc := range cases {
		before := commandCount(tc.command)
		tc.run(t)
		after := commandCount(tc.command)

		if after < before+1 {
			t.Errorf("sora_commands_total{command=%q,status=\"success\"} did not increase: before=%.0f after=%.0f", tc.command, before, after)
		} else {
			t.Logf("✅ %s: sora_commands_total %.0f -> %.0f", tc.command, before, after)
		}
	}

	// Also prove the latency histogram fires on the same path. SELECT was run
	// above, so its sample count must now be > 0.
	if n := histogramSampleCount(t, "sora_command_duration_seconds", "SELECT"); n == 0 {
		t.Errorf("sora_command_duration_seconds{command=\"SELECT\"} has 0 samples; duration histogram not recorded")
	} else {
		t.Logf("✅ sora_command_duration_seconds{command=\"SELECT\"} sample_count=%d", n)
	}
}

// TestIMAP_CommandClientVsServerError verifies the meteredSession status
// taxonomy: a benign client-side condition (SELECT of a non-existent mailbox,
// returned as a tagged NO) is classified as status="client_error", NOT
// "server_error". This keeps expected client outcomes — rate-limited retries,
// missing mailboxes, mid-command disconnects — out of the server_error bucket
// operators alert on (server/imap/metered.go: commandStatus).
func TestIMAP_CommandClientVsServerError(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	client, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer client.Close()

	if err := client.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	count := func(status string) float64 {
		return testutil.ToFloat64(metrics.CommandsTotal.WithLabelValues("imap", "SELECT", status))
	}

	clientBefore := count("client_error")
	serverBefore := count("server_error")

	// SELECT of a mailbox that does not exist returns a tagged NO — a client-side
	// condition, not a server fault.
	if _, err := client.Select("This_Mailbox_Does_Not_Exist_42", nil).Wait(); err == nil {
		t.Fatal("expected SELECT of a non-existent mailbox to fail, but it succeeded")
	}

	if got := count("client_error"); got < clientBefore+1 {
		t.Errorf("sora_commands_total{command=\"SELECT\",status=\"client_error\"} did not increase: before=%.0f after=%.0f", clientBefore, got)
	} else {
		t.Logf("✅ SELECT of missing mailbox -> client_error %.0f -> %.0f", clientBefore, got)
	}
	if got := count("server_error"); got != serverBefore {
		t.Errorf("benign client error must NOT increment server_error: before=%.0f after=%.0f", serverBefore, got)
	} else {
		t.Logf("✅ server_error unchanged (%.0f) — benign error kept out of the alert bucket", got)
	}
}

// TestIMAP_AppendUsesSharedTaxonomy verifies that APPEND — which self-instruments
// rather than going through the meteredSession wrapper — classifies its status
// with the same success / client_error / server_error taxonomy. APPEND to a
// non-existent mailbox returns NO [TRYCREATE], a client-side condition, so it must
// land in client_error and leave server_error untouched.
func TestIMAP_AppendUsesSharedTaxonomy(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	client, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer client.Close()

	if err := client.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	count := func(status string) float64 {
		return testutil.ToFloat64(metrics.CommandsTotal.WithLabelValues("imap", "APPEND", status))
	}

	clientBefore := count("client_error")
	serverBefore := count("server_error")

	const msg = "From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n\r\nbody\r\n"
	appendCmd := client.Append("This_Mailbox_Does_Not_Exist_42", int64(len(msg)), nil)
	_, _ = appendCmd.Write([]byte(msg))
	_ = appendCmd.Close()
	if _, err := appendCmd.Wait(); err == nil {
		t.Fatal("expected APPEND to a non-existent mailbox to fail, but it succeeded")
	}

	if got := count("client_error"); got < clientBefore+1 {
		t.Errorf("sora_commands_total{command=\"APPEND\",status=\"client_error\"} did not increase: before=%.0f after=%.0f", clientBefore, got)
	} else {
		t.Logf("✅ APPEND to missing mailbox -> client_error %.0f -> %.0f", clientBefore, got)
	}
	if got := count("server_error"); got != serverBefore {
		t.Errorf("benign APPEND client error must NOT increment server_error: before=%.0f after=%.0f", serverBefore, got)
	} else {
		t.Logf("✅ APPEND server_error unchanged (%.0f)", got)
	}
}

// histogramSampleCount reads the observation count of a histogram metric for the
// given IMAP command label from the default gatherer.
func histogramSampleCount(t *testing.T, name, command string) uint64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelValue(m, "protocol") == "imap" && labelValue(m, "command") == command {
				return m.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

func labelValue(m *dto.Metric, name string) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}
