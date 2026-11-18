package imaptest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// runnerPeer tests lifecycle/reporting through real TCP, independently of Sora.
// The wire tests cover response and literal parsing in more detail.
type runnerPeer struct {
	listener        net.Listener
	mu              sync.Mutex
	commands        []string
	mailboxes       map[string]bool
	refuseDelete    bool
	dropCreate      bool
	dropRename      bool
	noSubscriptions bool
	stalls          chan struct{}
	conns           map[net.Conn]bool
	wg              sync.WaitGroup
}

func newRunnerPeer(t *testing.T) *runnerPeer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &runnerPeer{listener: listener, mailboxes: map[string]bool{"INBOX": true, "Sent": true}, conns: map[net.Conn]bool{}}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns[conn] = true
			p.mu.Unlock()
			p.wg.Add(1)
			go p.serve(conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		p.mu.Lock()
		for conn := range p.conns {
			_ = conn.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p
}

func (p *runnerPeer) serve(conn net.Conn) {
	defer p.wg.Done()
	defer conn.Close()
	defer func() { p.mu.Lock(); delete(p.conns, conn); p.mu.Unlock() }()
	fmt.Fprint(conn, "* OK test endpoint\r\n")
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		tag, command, ok := strings.Cut(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), " ")
		if !ok {
			return
		}
		verb, arg, _ := strings.Cut(command, " ")
		p.mu.Lock()
		p.commands = append(p.commands, command)
		status := "OK"
		switch strings.ToUpper(verb) {
		case "CAPABILITY":
			fmt.Fprint(conn, "* CAPABILITY IMAP4rev1 UIDPLUS\r\n")
		case "LSUB":
			name := strings.Trim(strings.TrimPrefix(arg, "\"\" "), "\"")
			if p.mailboxes[name] && !p.noSubscriptions {
				fmt.Fprintf(conn, "* LSUB () \"/\" %s\r\n", Quote(name))
			}
		case "LIST":
			name := strings.Trim(strings.TrimPrefix(arg, "\"\" "), "\"")
			if p.mailboxes[name] {
				fmt.Fprintf(conn, "* LIST () \"/\" %s\r\n", Quote(name))
			}
		case "UNSUBSCRIBE":
			if p.noSubscriptions {
				status = "NO"
			}
		case "CREATE":
			p.mailboxes[strings.Trim(arg, "\"")] = true
			if p.dropCreate {
				p.mu.Unlock()
				return
			}
		case "RENAME":
			names := strings.Fields(arg)
			if len(names) == 2 {
				delete(p.mailboxes, strings.Trim(names[0], "\""))
				p.mailboxes[strings.Trim(names[1], "\"")] = true
			}
			if p.dropRename {
				p.mu.Unlock()
				return
			}
		case "DELETE":
			if p.refuseDelete {
				status = "NO"
			} else {
				delete(p.mailboxes, strings.Trim(arg, "\""))
			}
		case "FAIL":
			status = "NO"
		case "STALL":
			stalls := p.stalls
			p.mu.Unlock()
			if stalls != nil {
				stalls <- struct{}{}
			}
			// Wait for EOF when cancellation closes the active client. No
			// command completion is sent, so the client is genuinely in IO.
			_, _ = reader.ReadString('\n')
			return
		}
		p.mu.Unlock()
		if _, err := fmt.Fprintf(conn, "%s %s complete\r\n", tag, status); err != nil {
			return
		}
	}
}

func (p *runnerPeer) config() Config {
	return Config{Addr: p.listener.Addr().String(), Username: "tester", Password: "a-private-password", TLSMode: "none", CommandTimeout: time.Second, CaseTimeout: 3 * time.Second}
}

func TestRunnerIsolatesCleansAndContinuesAfterAssertion(t *testing.T) {
	p := newRunnerPeer(t)
	var names []string
	cases := []Case{
		{Name: "first", RFC: "rfc3501", Run: func(s *Session) error {
			name, err := s.NewMailbox("messages")
			if err != nil {
				return err
			}
			names = append(names, name)
			return Check(false, "deliberate protocol failure")
		}},
		{Name: "second", RFC: "rfc3501", Run: func(s *Session) error {
			name, err := s.NewMailbox("messages")
			if err != nil {
				return err
			}
			names = append(names, name)
			if err := s.DeleteMailbox(s.Client, "INBOX"); err == nil {
				return errors.New("accepted deleting unowned mailbox")
			}
			if err := s.RenameMailbox(s.Client, name, "Sent"); err == nil {
				return errors.New("accepted rename outside owned prefix")
			}
			return nil
		}},
	}
	var progress []Result
	report, err := runCases(context.Background(), p.config(), func(r Result) { progress = append(progress, r) }, func(string) ([]Case, error) { return cases, nil })
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed != 1 || report.Passed != 1 || report.ExitCode() != 1 || len(progress) != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if len(names) != 2 || names[0] == names[1] {
		t.Fatalf("mailbox names not isolated: %v", names)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.mailboxes) != 2 || !p.mailboxes["INBOX"] || !p.mailboxes["Sent"] {
		t.Fatalf("cleanup touched existing folders or leaked test folders: %v", p.mailboxes)
	}
	for _, name := range names {
		unsubscribe, deleted := -1, -1
		for i, command := range p.commands {
			if command == "UNSUBSCRIBE "+Quote(name) {
				unsubscribe = i
			}
			if command == "DELETE "+Quote(name) {
				deleted = i
			}
		}
		if unsubscribe < 0 || deleted <= unsubscribe {
			t.Errorf("cleanup order for %s: %v", name, p.commands)
		}
	}
}

func TestRunnerSkipsOptionalButFailsRequiredCapabilities(t *testing.T) {
	p := newRunnerPeer(t)
	run := func(*Session) error { t.Error("unsupported case was executed"); return nil }
	cases := []Case{{Name: "optional", Requires: []string{"MOVE"}, Run: run}}
	report, err := runCases(context.Background(), p.config(), nil, func(string) ([]Case, error) { return cases, nil })
	if err != nil || report.Skipped != 1 || report.ExitCode() != 2 {
		t.Fatalf("all-skipped run must be unsuccessful: report=%+v err=%v", report, err)
	}
	cfg := p.config()
	cfg.RequiredCapabilities = []string{"MOVE"}
	report, err = runCases(context.Background(), cfg, nil, func(string) ([]Case, error) { return cases, nil })
	if err == nil || !strings.Contains(report.Error, "MOVE") || report.ExitCode() != 2 {
		t.Fatalf("missing required capability was not fatal: %+v %v", report, err)
	}
}

func TestRunnerCleanupFailureIsAnError(t *testing.T) {
	p := newRunnerPeer(t)
	p.mu.Lock()
	p.refuseDelete = true
	p.mu.Unlock()
	cases := []Case{{Name: "cleanup", Run: func(s *Session) error { _, err := s.NewMailbox("keep"); return err }}}
	report, err := runCases(context.Background(), p.config(), nil, func(string) ([]Case, error) { return cases, nil })
	if err != nil || report.Errors != 1 || report.ExitCode() != 2 || len(report.Results[0].CleanupErrors) != 1 {
		t.Fatalf("cleanup failure lost: %+v %v", report, err)
	}
}

func TestRunnerDoesNotUnsubscribeUnsubscribedMailbox(t *testing.T) {
	p := newRunnerPeer(t)
	p.mu.Lock()
	p.noSubscriptions = true
	p.mu.Unlock()
	cases := []Case{{Name: "unsubscribed", Run: func(s *Session) error { _, err := s.NewMailbox("messages"); return err }}}
	report, err := runCases(context.Background(), p.config(), nil, func(string) ([]Case, error) { return cases, nil })
	if err != nil || report.Passed != 1 || report.ExitCode() != 0 {
		t.Fatalf("cleanup required nonexistent subscription: %+v %v", report, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, command := range p.commands {
		if strings.HasPrefix(command, "UNSUBSCRIBE ") {
			t.Fatalf("unsubscribed absent subscription: %s", command)
		}
	}
}

func TestRunnerReportsAmbiguousMailboxMutations(t *testing.T) {
	for _, operation := range []string{"CREATE", "RENAME"} {
		t.Run(operation, func(t *testing.T) {
			p := newRunnerPeer(t)
			p.mu.Lock()
			p.dropCreate = operation == "CREATE"
			p.dropRename = operation == "RENAME"
			p.mu.Unlock()
			cases := []Case{{Name: "lost-completion", Run: func(s *Session) error {
				name, err := s.NewMailbox("before")
				if err != nil {
					return err
				}
				return s.RenameMailbox(s.Client, name, s.Name("after"))
			}}}
			report, err := runCases(context.Background(), p.config(), nil, func(string) ([]Case, error) { return cases, nil })
			if err != nil || report.Errors != 1 || len(report.Results[0].CleanupErrors) == 0 {
				t.Fatalf("lost completion not reported: %+v %v", report, err)
			}
			if !strings.Contains(strings.Join(report.Results[0].CleanupErrors, " "), operation+" outcome unknown") {
				t.Fatalf("ambiguous %s omitted affected names: %+v", operation, report.Results[0])
			}
		})
	}
}

func TestAdditionalSessionEnforcesRequiredCapabilities(t *testing.T) {
	p := newRunnerPeer(t)
	cases := []Case{{Name: "additional", Run: func(s *Session) error {
		// Simulate an endpoint profile change after the primary connection.
		s.cfg.RequiredCapabilities = []string{"MOVE"}
		_, err := s.NewClient()
		return err
	}}}
	report, err := runCases(context.Background(), p.config(), nil, func(string) ([]Case, error) { return cases, nil })
	if err != nil || report.Errors != 1 || !strings.Contains(report.Results[0].Detail, "MOVE") {
		t.Fatalf("additional session ignored capability profile: %+v %v", report, err)
	}
}

func TestRunnerCancellationStillCleansCreatedMailbox(t *testing.T) {
	p := newRunnerPeer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cases := []Case{{Name: "cancel", Run: func(s *Session) error {
		if _, err := s.NewMailbox("cancel"); err != nil {
			return err
		}
		cancel()
		return ctx.Err()
	}}}
	report, err := runCases(ctx, p.config(), nil, func(string) ([]Case, error) { return cases, nil })
	if err == nil || report.ExitCode() != 2 {
		t.Fatalf("canceled run passed: %+v %v", report, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.mailboxes) != 2 {
		t.Fatalf("canceled run leaked test mailbox: %v", p.mailboxes)
	}
}

func TestRunnerRedactsErrorsAndRejectsEmptySelection(t *testing.T) {
	p := newRunnerPeer(t)
	cfg := p.config()
	cases := []Case{{Name: "error", Run: func(*Session) error { return fmt.Errorf("peer echoed %s", cfg.Password) }}}
	report, err := runCases(context.Background(), cfg, nil, func(string) ([]Case, error) { return cases, nil })
	if err != nil || strings.Contains(report.Results[0].Detail, cfg.Password) || !strings.Contains(report.Results[0].Detail, "[REDACTED]") {
		t.Fatalf("credential redaction failed: %+v %v", report, err)
	}
	if _, err := Select("^no-such-conformance-case$"); err == nil {
		t.Fatal("empty selection accepted")
	}
}

func TestCaseCatalogHasUniqueNamesAndReferences(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Cases() {
		if c.Name == "" || seen[c.Name] || c.Run == nil || !strings.HasPrefix(c.RFC, "https://www.rfc-editor.org/") {
			t.Errorf("invalid case metadata: %+v", c)
		}
		seen[c.Name] = true
	}
	if len(seen) < 15 {
		t.Fatalf("unexpectedly small catalog: %d", len(seen))
	}
}

func TestRunnerConcurrentCasesRespectLimitAndReportCatalogOrder(t *testing.T) {
	p := newRunnerPeer(t)
	cfg := p.config()
	cfg.Clients = 2
	var trace strings.Builder // not intrinsically safe for simultaneous writes
	cfg.Trace = &trace
	const count = 5
	started := make(chan int, count)
	gates := make([]chan struct{}, count)
	var activeMu sync.Mutex
	active, maximum := 0, 0
	var names []string
	cases := make([]Case, count)
	for i := range cases {
		gates[i] = make(chan struct{})
		cases[i] = Case{Name: fmt.Sprintf("case-%d", i), Run: func(s *Session) error {
			name, err := s.NewMailbox("messages")
			if err != nil {
				return err
			}
			activeMu.Lock()
			active++
			maximum = max(maximum, active)
			names = append(names, name)
			activeMu.Unlock()
			defer func() { activeMu.Lock(); active--; activeMu.Unlock() }()
			started <- i
			select {
			case <-gates[i]:
				return nil
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
		}}
	}
	type outcome struct {
		report Report
		err    error
	}
	done := make(chan outcome, 1)
	var progress []string
	go func() {
		report, err := runCases(context.Background(), cfg, func(r Result) { progress = append(progress, r.Name) }, func(string) ([]Case, error) { return cases, nil })
		done <- outcome{report, err}
	}()
	receive := func() int {
		t.Helper()
		select {
		case i := <-started:
			return i
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent case did not reach barrier")
			return -1
		}
	}
	first := map[int]bool{receive(): true, receive(): true}
	if !first[0] || !first[1] {
		t.Fatalf("first workers did not receive the first two cases: %v", first)
	}
	select {
	case i := <-started:
		t.Fatalf("case %d exceeded the worker limit", i)
	default:
	}
	// Keep case zero blocked while every other case passes through the
	// second worker, forcing completion order to differ from catalog order.
	close(gates[1])
	for want := 2; want < count; want++ {
		if got := receive(); got != want {
			t.Fatalf("worker started case %d, want %d", got, want)
		}
		close(gates[want])
	}
	close(gates[0])
	var got outcome
	select {
	case got = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent run did not finish cleanup")
	}
	if got.err != nil || got.report.Passed != count || got.report.ExitCode() != 0 || got.report.Clients != 2 {
		t.Fatalf("unexpected concurrent report: %+v %v", got.report, got.err)
	}
	if maximum != 2 {
		t.Errorf("maximum active cases = %d, want 2", maximum)
	}
	for i, result := range got.report.Results {
		if result.Name != cases[i].Name {
			t.Errorf("report result %d is %s, want %s", i, result.Name, cases[i].Name)
		}
	}
	if len(progress) != count || progress[0] != cases[1].Name {
		t.Errorf("progress did not follow completion order: %v", progress)
	}
	seen := make(map[string]bool)
	for _, name := range names {
		if seen[name] {
			t.Errorf("concurrent cases shared mailbox %s", name)
		}
		seen[name] = true
	}
	if strings.Contains(trace.String(), cfg.Password) || !strings.Contains(trace.String(), "CREATE") {
		t.Error("concurrent trace lost data or exposed credentials")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.mailboxes) != 2 {
		t.Errorf("concurrent cleanup left mailboxes: %v", p.mailboxes)
	}
}

func TestRunnerCancellationStopsWorkersAndCleansActiveCases(t *testing.T) {
	p := newRunnerPeer(t)
	p.mu.Lock()
	p.stalls = make(chan struct{}, 2)
	p.mu.Unlock()
	cfg := p.config()
	cfg.Clients = 2
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cases := make([]Case, 6)
	for i := range cases {
		cases[i] = Case{Name: fmt.Sprintf("cancel-%d", i), Run: func(s *Session) error {
			if _, err := s.NewMailbox("active"); err != nil {
				return err
			}
			_, err := s.Client.OK("STALL")
			return err
		}}
	}
	type outcome struct {
		report Report
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		report, err := runCases(ctx, cfg, nil, func(string) ([]Case, error) { return cases, nil })
		done <- outcome{report, err}
	}()
	for range 2 {
		select {
		case <-p.stalls:
		case <-time.After(3 * time.Second):
			t.Fatal("active case did not block in IO")
		}
	}
	cancel()
	var got outcome
	select {
	case got = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not unblock clients and finish cleanup")
	}
	if got.err == nil || got.report.ExitCode() != 2 || got.report.Errors != 2 || len(got.report.Results) != 2 {
		t.Fatalf("cancelled worker run returned %+v %v", got.report, got.err)
	}
	for i, result := range got.report.Results {
		if result.Name != cases[i].Name || len(result.CleanupErrors) != 0 {
			t.Errorf("unexpected cancelled case: %+v", result)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.mailboxes) != 2 {
		t.Errorf("cancelled workers leaked mailboxes: %v", p.mailboxes)
	}
}

func TestRunnerRejectsInvalidWorkerLimits(t *testing.T) {
	for _, clients := range []int{-1, 1025} {
		cfg := Config{Clients: clients}
		report, err := runCases(context.Background(), cfg, nil, func(string) ([]Case, error) { t.Error("invalid clients reached case selection"); return nil, nil })
		if err == nil || report.ExitCode() != 2 || !strings.Contains(report.Error, "clients") {
			t.Errorf("clients=%d accepted: %+v %v", clients, report, err)
		}
	}
}
