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
