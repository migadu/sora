package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/relayqueue"
	"github.com/migadu/sora/server/sieveengine"
)

// vacationLog collects the shared vacation handler's diagnostics.
type vacationLog struct{ lines []string }

func (l *vacationLog) Log(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

// runVacation answers a personal message to user@example.com with the shared vacation
// handler, which both LMTP and /admin/mail/deliver build around their RelayQueue option,
// and reports a panic instead of crashing the test.
func runVacation(queue delivery.RelayQueue, log delivery.Logger) (err error, panicked any) {
	defer func() { panicked = recover() }()
	sender, _ := server.NewAddress("sender@example.org")
	recipient, _ := server.NewAddress("user@example.com")
	msg, perr := message.Read(strings.NewReader("From: sender@example.org\r\n" +
		"To: user@example.com\r\n" +
		"Subject: hello\r\n" +
		"Message-ID: <hello@example.org>\r\n" +
		"\r\n" +
		"Are you there?\r\n"))
	if perr != nil {
		return perr, nil
	}
	handler := &delivery.StandardVacationHandler{Hostname: "mx.example.com", RelayQueue: queue, Logger: log}
	return handler.HandleVacationResponse(context.Background(), 1, sieveengine.VacationReply{Body: "I am away"}, &sender, &recipient, msg), nil
}

// On a node without [relay], deps.relayQueue (*relayqueue.DiskQueue) and deps.relayWorker
// (*relayqueue.Worker) are nil. Copied into the LMTP and Admin API options' interface
// fields, a nil pointer made a non-nil interface, so every "relay not configured" check
// took the configured branch and called Enqueue on the nil queue: a Sieve vacation reply
// or redirect panicked inside the delivery instead of being skipped. The options must
// carry nil interfaces, and the vacation handler given them must skip the reply.
func TestRelayOptions_NodeWithoutRelay(t *testing.T) {
	deps := &serverDependencies{}
	lmtpOptions := buildLMTPServerOptions(deps, config.ServerConfig{Type: "lmtp", Name: "lmtp", Addr: "127.0.0.1:24"})
	adminOptions := buildAdminAPIServerOptions(deps, config.ServerConfig{Type: "http_admin_api", Name: "admin-api", Addr: "127.0.0.1:8080"})

	if lmtpOptions.RelayQueue != nil {
		t.Errorf("LMTP RelayQueue is a non-nil interface (%T) on a node without [relay]", lmtpOptions.RelayQueue)
	}
	if lmtpOptions.RelayWorker != nil {
		t.Errorf("LMTP RelayWorker is a non-nil interface (%T) on a node without [relay]", lmtpOptions.RelayWorker)
	}
	if adminOptions.RelayQueue != nil {
		t.Errorf("Admin API RelayQueue is a non-nil interface (%T) on a node without [relay]", adminOptions.RelayQueue)
	}

	for _, tc := range []struct {
		name  string
		queue delivery.RelayQueue
	}{
		{"LMTP", lmtpOptions.RelayQueue},
		{"AdminAPI", adminOptions.RelayQueue},
	} {
		t.Run(tc.name+"/vacation", func(t *testing.T) {
			log := &vacationLog{}
			err, panicked := runVacation(tc.queue, log)
			if panicked != nil {
				t.Fatalf("vacation reply panicked: %v", panicked)
			}
			if err != nil {
				t.Fatalf("vacation reply: %v", err)
			}
			if got := strings.Join(log.lines, "\n"); !strings.Contains(got, "external relay not configured") {
				t.Errorf("vacation log = %q, want the reply skipped as \"external relay not configured\"", got)
			}
		})
	}
}

// A node with [relay] still hands its queue and worker to LMTP and the Admin API.
func TestRelayOptions_NodeWithRelay(t *testing.T) {
	queue, err := relayqueue.NewDiskQueue(t.TempDir(), 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	worker := relayqueue.NewWorker(queue, nil, time.Minute, 1, 1, time.Hour, time.Hour, nil)
	deps := &serverDependencies{relayQueue: queue, relayWorker: worker}

	lmtpOptions := buildLMTPServerOptions(deps, config.ServerConfig{Type: "lmtp", Name: "lmtp", Addr: "127.0.0.1:24"})
	adminOptions := buildAdminAPIServerOptions(deps, config.ServerConfig{Type: "http_admin_api", Name: "admin-api", Addr: "127.0.0.1:8080"})

	if lmtpOptions.RelayQueue != delivery.RelayQueue(queue) {
		t.Errorf("LMTP RelayQueue = %v, want the node's queue", lmtpOptions.RelayQueue)
	}
	if lmtpOptions.RelayWorker != lmtp.RelayWorkerNotifier(worker) {
		t.Errorf("LMTP RelayWorker = %v, want the node's worker", lmtpOptions.RelayWorker)
	}
	if adminOptions.RelayQueue != delivery.RelayQueue(queue) {
		t.Errorf("Admin API RelayQueue = %v, want the node's queue", adminOptions.RelayQueue)
	}
}
