package imaptest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Cases returns the catalog without opening a connection. Every case has its own
// mailbox names and connections and may be selected independently.
func Cases() []Case {
	cases := append(coreCases(), extensionCases()...)
	cases = append(cases, portMIMECases()...)
	cases = append(cases, portSortThreadCases()...)
	cases = append(cases, portMailboxCases()...)
	cases = append(cases, portSearchCases()...)
	cases = append(cases, portExtensionCases()...)
	slices.SortFunc(cases, func(a, b Case) int { return strings.Compare(a.Name, b.Name) })
	return cases
}

// Select filters the catalog. An empty selection is an error, never a passing run.
func Select(pattern string) ([]Case, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid case filter: %w", err)
	}
	var selected []Case
	for _, c := range Cases() {
		if re.MatchString(c.Name) {
			selected = append(selected, c)
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("case filter matched no tests")
	}
	return selected, nil
}

// Run connects to an already-running server. It never starts Sora, reads a Sora
// configuration, provisions accounts, or accesses a database or object store.
func Run(ctx context.Context, cfg Config, progress func(Result)) (Report, error) {
	return runCases(ctx, cfg, progress, Select)
}

func runCases(ctx context.Context, cfg Config, progress func(Result), selectCases func(string) ([]Case, error)) (report Report, runErr error) {
	report.Address = cfg.Addr
	report.StartedAt = time.Now().UTC()
	report.Results = []Result{}
	report.Capabilities = []string{}
	defer func() {
		report.Duration = time.Since(report.StartedAt)
		if runErr != nil {
			report.Error = redact(runErr.Error(), cfg.Password)
			runErr = errors.New(report.Error)
		}
	}()
	if cfg.TLSMode == "" {
		cfg.TLSMode = "implicit"
	}
	if cfg.CommandTimeout == 0 {
		cfg.CommandTimeout = 30 * time.Second
	}
	if cfg.CaseTimeout == 0 {
		cfg.CaseTimeout = 2 * time.Minute
	}
	if cfg.FTSTimeout == 0 {
		cfg.FTSTimeout = 90 * time.Second
	}
	if cfg.Clients == 0 {
		cfg.Clients = 1
	}
	report.Clients = cfg.Clients
	if cfg.Clients < 1 || cfg.Clients > 1024 {
		return report, errors.New("clients must be between 1 and 1024")
	}
	if cfg.Trace != nil {
		cfg.Trace = &synchronizedTrace{Writer: cfg.Trace}
	}
	if _, _, err := net.SplitHostPort(cfg.Addr); err != nil {
		return report, fmt.Errorf("address must be host:port: %w", err)
	}
	if cfg.TLSMode != "implicit" && cfg.TLSMode != "starttls" && cfg.TLSMode != "none" {
		return report, errors.New("TLS mode must be implicit, starttls, or none")
	}
	if cfg.CommandTimeout <= 0 || cfg.CaseTimeout <= 0 || cfg.FTSTimeout <= 0 {
		return report, errors.New("command, case and FTS timeouts must be positive")
	}
	if cfg.Username == "" {
		return report, errors.New("a test username is required")
	}
	for _, credential := range []string{cfg.Username, cfg.Password} {
		if strings.ContainsAny(credential, "\r\n\x00") {
			return report, errors.New("credentials must not contain CR, LF, or NUL")
		}
	}
	cases, err := selectCases(cfg.Run)
	if err != nil {
		return report, err
	}
	if len(cases) == 0 {
		return report, errors.New("case selection is empty")
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return report, fmt.Errorf("generate mailbox prefix: %w", err)
	}
	prefix := "sora-imaptest-" + hex.EncodeToString(random[:]) + "-"
	control, err := Dial(ctx, cfg)
	if err != nil {
		return report, fmt.Errorf("connect/authenticate: %w", err)
	}
	defer func() { _ = control.Close() }()
	for cap := range control.Capabilities {
		report.Capabilities = append(report.Capabilities, cap)
	}
	slices.Sort(report.Capabilities)
	if !control.Capabilities["IMAP4REV1"] {
		return report, errors.New("this suite requires IMAP4rev1; rev2-only servers need a separate profile")
	}
	if missing := missingCaps(control.Capabilities, cfg.RequiredCapabilities); len(missing) != 0 {
		return report, fmt.Errorf("required capabilities missing: %s", strings.Join(missing, ", "))
	}
	_ = control.Close()
	type completedCase struct {
		index  int
		result Result
	}
	workers := min(cfg.Clients, len(cases))
	jobs := make(chan int)
	completed := make(chan completedCase, workers)
	var running sync.WaitGroup
	running.Add(workers)
	for range workers {
		go func() {
			defer running.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case i, ok := <-jobs:
					if !ok || ctx.Err() != nil {
						return
					}
					result := executeCase(ctx, cfg, cases[i], control.Capabilities, fmt.Sprintf("%s%02d-", prefix, i+1))
					completed <- completedCase{index: i, result: result}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i := range cases {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case jobs <- i:
			}
		}
	}()
	go func() { running.Wait(); close(completed) }()
	ordered := make([]*Result, len(cases))
	for item := range completed {
		result := item.result
		ordered[item.index] = &result
		switch result.Status {
		case "pass":
			report.Passed++
		case "fail":
			report.Failed++
		case "skip":
			report.Skipped++
		case "error":
			report.Errors++
		}
		if progress != nil {
			progress(result)
		}
	}
	for _, result := range ordered {
		if result != nil {
			report.Results = append(report.Results, *result)
		}
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	return report, nil
}

// Every connection receives the same writer wrapper for this run. It keeps a
// trace record atomic even when cases and their additional sessions overlap.
type synchronizedTrace struct {
	io.Writer
	mu sync.Mutex
}

func (w *synchronizedTrace) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Writer.Write(data)
}

func executeCase(ctx context.Context, cfg Config, c Case, caps map[string]bool, prefix string) Result {
	result := Result{Name: c.Name, RFC: c.RFC, Upstream: c.Upstream, Status: "skip"}
	started := time.Now()
	if missing := missingCaps(caps, c.Requires); len(missing) != 0 {
		result.Detail = "unsupported optional capabilities: " + strings.Join(missing, ", ")
		result.Duration = time.Since(started)
		return result
	}
	caseCtx, cancel := context.WithTimeout(ctx, cfg.CaseTimeout)
	s := &Session{ctx: caseCtx, cfg: cfg, prefix: prefix, mailboxes: map[string]bool{}}
	client, err := s.NewClient()
	if err == nil {
		s.Client = client
		s.Caps = client.Capabilities
		if missing := missingCaps(s.Caps, c.Requires); len(missing) != 0 {
			err = Skip("connection lacks optional capabilities: " + strings.Join(missing, ", "))
		} else {
			err = c.Run(s)
		}
	}
	for _, client := range s.clients {
		_ = client.Close()
	}
	cancel()
	result.Status = "pass"
	if err != nil {
		var assertion *AssertionError
		var skip *SkipError
		switch {
		case errors.As(err, &assertion):
			result.Status = "fail"
		case errors.As(err, &skip):
			result.Status = "skip"
		default:
			result.Status = "error"
		}
		result.Detail = redact(err.Error(), cfg.Password)
	}
	// Cleanup belongs to the case's worker slot. The next case cannot start
	// in that slot until selected sessions are closed and cleanup is done.
	if len(s.mailboxes) > 0 || len(s.subscriptions) > 0 {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), cfg.CommandTimeout)
		cleanupClient, err := Dial(cleanupCtx, cfg)
		if err != nil {
			result.CleanupErrors = append(result.CleanupErrors, redact(fmt.Sprintf("cleanup connection failed: %v; remaining test mailboxes: %s", err, strings.Join(s.mailboxNames(), ", ")), cfg.Password))
		}
		if cleanupClient != nil {
			result.CleanupErrors = append(result.CleanupErrors, s.cleanup(cleanupCtx, cleanupClient)...)
			_ = cleanupClient.Close()
		}
		cancelCleanup()
		if len(result.CleanupErrors) > 0 {
			result.Status = "error"
		}
	}
	if len(s.uncertain) > 0 {
		result.CleanupErrors = append(result.CleanupErrors, s.uncertain...)
		result.Status = "error"
	}
	result.Duration = time.Since(started)
	return result
}

func missingCaps(caps map[string]bool, required []string) []string {
	var missing []string
	for _, cap := range required {
		cap = strings.ToUpper(strings.TrimSpace(cap))
		if cap != "" && !caps[cap] {
			missing = append(missing, cap)
		}
	}
	slices.Sort(missing)
	return slices.Compact(missing)
}

func redact(text, password string) string {
	if password != "" {
		return strings.ReplaceAll(text, password, "[REDACTED]")
	}
	return text
}

func (s *Session) NewClient() (*Client, error) {
	c, err := Dial(s.ctx, s.cfg)
	if err != nil {
		return nil, err
	}
	if !c.Capabilities["IMAP4REV1"] {
		_ = c.Close()
		return nil, errors.New("test connection does not advertise IMAP4rev1")
	}
	if missing := missingCaps(c.Capabilities, s.cfg.RequiredCapabilities); len(missing) != 0 {
		_ = c.Close()
		return nil, fmt.Errorf("test connection lacks required capabilities: %s", strings.Join(missing, ", "))
	}
	s.clients = append(s.clients, c)
	return c, nil
}

func (s *Session) NewUnauthenticatedClient() (*Client, error) {
	c, err := DialUnauthenticated(s.ctx, s.cfg)
	if err != nil {
		return nil, err
	}
	s.clients = append(s.clients, c)
	return c, nil
}

func (s *Session) Name(suffix string) string {
	return s.prefix + strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, suffix)
}

func (s *Session) NewMailbox(suffix string) (string, error) {
	name := s.Name(suffix)
	return name, s.CreateMailbox(s.Client, name)
}

func (s *Session) CreateMailbox(c *Client, name string) error {
	return s.CreateMailboxAs(c, name, name)
}

// CreateMailboxAs records a canonical LIST name when CREATE uses a trailing
// hierarchy delimiter. Only names in this case's generated prefix are accepted.
func (s *Session) CreateMailboxAs(c *Client, wireName, name string) error {
	if !strings.HasPrefix(wireName, s.prefix) || !strings.HasPrefix(name, s.prefix) || s.mailboxes[name] {
		return errors.New("CREATE must use an unused name in this case's prefix")
	}
	if _, err := c.OK("CREATE " + Quote(wireName)); err != nil {
		var refusal *AssertionError
		if !errors.As(err, &refusal) {
			s.uncertain = append(s.uncertain, "CREATE outcome unknown; check temporary mailbox "+name)
		}
		return err
	}
	s.mailboxes[name] = true
	return s.TrackSubscription(name)
}

func (s *Session) TrackSubscription(name string) error {
	if !strings.HasPrefix(name, s.prefix) {
		return errors.New("subscription name must belong to this case's prefix")
	}
	if s.subscriptions == nil {
		s.subscriptions = map[string]bool{}
	}
	s.subscriptions[name] = true
	return nil
}

func (s *Session) PipelineCreates(c *Client, names ...string) ([]Response, error) {
	commands := make([]string, len(names))
	seen := map[string]bool{}
	for i, name := range names {
		if !strings.HasPrefix(name, s.prefix) || s.mailboxes[name] || seen[name] {
			return nil, errors.New("pipeline CREATE names must be unused and belong to this case")
		}
		seen[name] = true
		commands[i] = "CREATE " + Quote(name)
	}
	results, err := c.Pipeline(commands...)
	if err != nil {
		for _, name := range names {
			s.uncertain = append(s.uncertain, "pipelined CREATE outcome unknown; check temporary mailbox "+name)
		}
		return results, err
	}
	var failure error
	for i, result := range results {
		if result.Status == "OK" {
			s.mailboxes[names[i]] = true
			_ = s.TrackSubscription(names[i])
		} else if failure == nil {
			failure = Check(false, "pipelined CREATE %s returned %s", names[i], result.Status)
		}
	}
	return results, failure
}

func (s *Session) RenameMailbox(c *Client, old, name string) error {
	if !s.mailboxes[old] || !strings.HasPrefix(name, s.prefix) || s.mailboxes[name] {
		return errors.New("rename must use an owned mailbox and an unused name in this case's prefix")
	}
	if _, err := c.OK("RENAME " + Quote(old) + " " + Quote(name)); err != nil {
		var refusal *AssertionError
		if !errors.As(err, &refusal) {
			s.uncertain = append(s.uncertain, "RENAME outcome unknown; check temporary mailboxes "+old+" and "+name)
		}
		return err
	}
	delete(s.mailboxes, old)
	s.mailboxes[name] = true
	return s.TrackSubscription(name)
}

func (s *Session) DeleteMailbox(c *Client, name string) error {
	if !s.mailboxes[name] {
		return errors.New("refusing to delete a mailbox not created by this case")
	}
	if _, err := c.OK("DELETE " + Quote(name)); err != nil {
		return err
	}
	delete(s.mailboxes, name)
	return nil
}

func (s *Session) mailboxNames() []string {
	names := make([]string, 0, len(s.mailboxes))
	for name := range s.mailboxes {
		names = append(names, name)
	}
	for name := range s.subscriptions {
		if !s.mailboxes[name] {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	slices.Reverse(names)
	return names
}

func (s *Session) cleanup(ctx context.Context, c *Client) []string {
	names := s.mailboxNames()
	var failures []string
	for i, name := range names {
		if err := ctx.Err(); err != nil {
			failures = append(failures, "cleanup interrupted; remaining test mailboxes: "+strings.Join(names[i:], ", "))
			break
		}
		// Query this exact name: RFC 3501 does not require UNSUBSCRIBE to
		// succeed when no subscription exists. Remove subscriptions before
		// deleting the mailbox so a failed case cannot leave stale entries.
		listed, err := c.OK("LSUB \"\" " + Quote(name))
		if err != nil {
			failures = append(failures, redact(fmt.Sprintf("list subscription %s: %v", name, err), s.cfg.Password))
		} else {
			for _, reply := range listed.Data("LSUB") {
				if len(reply.Values) >= 4 && reply.Values[3].Text == name {
					if _, err := c.OK("UNSUBSCRIBE " + Quote(name)); err != nil {
						failures = append(failures, redact(fmt.Sprintf("unsubscribe %s: %v", name, err), s.cfg.Password))
					}
					break
				}
			}
		}
		if s.mailboxes[name] {
			// Hierarchy-only parents can disappear when their last child is
			// deleted. Query the exact tracked name before attempting DELETE.
			listed, err := c.OK("LIST \"\" " + Quote(name))
			if err != nil {
				failures = append(failures, redact(fmt.Sprintf("list %s: %v", name, err), s.cfg.Password))
				continue
			}
			for _, reply := range listed.Data("LIST") {
				if len(reply.Values) >= 4 && reply.Values[3].Text == name {
					if _, err := c.OK("DELETE " + Quote(name)); err != nil {
						failures = append(failures, redact(fmt.Sprintf("delete %s: %v", name, err), s.cfg.Password))
					}
					break
				}
			}
		}
	}
	return failures
}
