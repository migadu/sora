package sieveengine

import (
	"bytes"
	"context"
	"fmt"
	"net/mail"
	"runtime/debug"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/emersion/go-message"
	msieve "github.com/migadu/go-managesieve/managesieve"
	"github.com/migadu/go-sieve"
	"github.com/migadu/go-sieve/interp"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
)

type Action string

const (
	ActionKeep     Action = "keep"
	ActionDiscard  Action = "discard"
	ActionFileInto Action = "fileinto"
	ActionRedirect Action = "redirect"
)

// scriptExecutionTimeout bounds the total execution time of a single Sieve script
// (CPU/resource-exhaustion guard). It is also passed to go-sieve as the per-match
// regex soft-wait cap (Options.Interp.RegexLimits.MaxExecTime), so a large but
// input-bounded body :matches/:regex completes within the script budget instead of
// failing on go-sieve's tight 100ms default under load or race instrumentation.
// Configurable via SetScriptExecutionTimeout (from [sieve] max_execution_time).
var scriptExecutionTimeout = 2 * time.Second

const (
	minScriptExecutionTimeout = 100 * time.Millisecond
	maxScriptExecutionTimeout = 60 * time.Second
)

// SetScriptExecutionTimeout overrides the Sieve script execution budget (and the
// per-match regex soft-wait cap derived from it). The value is clamped to
// [100ms, 60s]; a non-positive value leaves the current setting unchanged. Call once
// at startup before serving.
func SetScriptExecutionTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	if d < minScriptExecutionTimeout {
		d = minScriptExecutionTimeout
	}
	if d > maxScriptExecutionTimeout {
		d = maxScriptExecutionTimeout
	}
	scriptExecutionTimeout = d
}

// DefaultSieveExtensions is the safe subset of SIEVE extensions enabled by default.
// Excludes security-sensitive extensions like editheader.
// The canonical list is go-managesieve's (managesieve/extensions.go).
var DefaultSieveExtensions = msieve.DefaultEnabledExtensions

// EffectiveExtensions resolves a configured [sieve] enabled_extensions list to
// the set scripts are compiled with and advertised as: the configured names
// the engine supports, or the default set when nothing is configured or
// nothing configured is supported. Every ingress path, ManageSieve included,
// and every capability report go through here, so they cannot drift. The
// dropped names are reported by InvalidExtensions, for a warning at startup.
func EffectiveExtensions(configured []string) []string {
	valid, _ := msieve.FilterExtensions(configured)
	if len(valid) == 0 {
		// A copy: every server keeps the result as its own, and one sorting or
		// appending to it in place must not change what the others compile.
		return slices.Clone(DefaultSieveExtensions)
	}
	return valid
}

// InvalidExtensions returns the configured names the engine does not support.
func InvalidExtensions(configured []string) []string {
	_, invalid := msieve.FilterExtensions(configured)
	return invalid
}

// MaxRedirects is how many redirect actions one script may execute for one
// message, the limit CompileScript's options enforce (what RFC 5804 §1.7's
// MAXREDIRECTS capability describes; this ManageSieve does not advertise it).
// It is distinct from max_redirect_hops, which bounds how many times a message
// may be redirected on its way through several servers.
func MaxRedirects() int {
	return sieve.DefaultOptions().Interp.MaxRedirects
}

// ValidateScript compiles content against the configured [sieve]
// enabled_extensions, as delivery will. Every path that stores a script must
// call it first: a stored script that does not compile is skipped whole at
// delivery, so every rule in it is silently lost, not just the bad one.
func ValidateScript(content string, configured []string) error {
	_, err := CompileScript(content, EffectiveExtensions(configured))
	return err
}

// HeaderEdit represents a header modification from editheader extension
type HeaderEdit struct {
	Action    string // "add" or "delete"
	FieldName string
	Value     string
	Last      bool // for addheader: add at end; for deleteheader: count from end
	Index     int  // for deleteheader: specific index (0 means all)
}

type Result struct {
	Action        Action
	Mailbox       string            // used for fileinto
	RedirectTo    []string          // used for redirect: every address to relay to, without repeats
	Flags         []string          // flags to add to the message
	Copy          bool              // RFC3894 - :copy modifier for redirect and fileinto
	CreateMailbox bool              // RFC5490 - :create modifier (mailbox extension)
	HeaderEdits   []HeaderEdit      // RFC5293 - editheader extension (addheader/deleteheader)
	Additional    map[string]string // future-proofing

	// RecordRedirect charges one redirect against the account's redirect rate limit.
	// Evaluation charges nothing, since only delivery knows whether a redirect went
	// out: it calls this once for each RedirectTo address it has queued or sent, and
	// not for one the relay is missing for or refused, the message being kept then.
	// It is nil when the action is not a redirect or no rate limit applies.
	RecordRedirect func(ctx context.Context) error

	// Vacation is the auto-reply the script's vacation action asks for, or nil. It is
	// not an Action: RFC 5230 §4.7 says "Vacation does not affect Sieve's implicit keep
	// action" and makes it compatible with keep, fileinto, redirect and discard, so
	// delivery sends it alongside Action, whatever that is.
	Vacation *VacationReply

	// Rejected marks an ActionDiscard that came from an RFC 5429 reject or
	// ereject (RejectExtended). Delivery treats it as any other discard: the
	// message is dropped and no bounce, DSN or MDN is sent. RejectReason is the
	// script's reason after variable expansion, kept for the log.
	Rejected       bool
	RejectExtended bool
	RejectReason   string
}

// VacationReply is an RFC 5230 auto-reply a script decided to send, its :days window
// for this sender and response identity already checked.
type VacationReply struct {
	From    string // the :from address; delivery uses it only if the account owns it
	Subject string
	Body    string // the reason
	IsMime  bool

	// ClaimResponse atomically consumes the :days window for this sender and
	// response identity. It is nil without a VacationOracle. Delivery calls it
	// after suppression/MIME checks, immediately before relay handoff; false means
	// another delivery already consumed the window and this reply must be skipped.
	ClaimResponse func(ctx context.Context) (bool, error)
}

type Context struct {
	EnvelopeFrom string
	EnvelopeTo   string
	// Header is the parsed header block of Message. The body test reads the top-level
	// Content-Type and Content-Transfer-Encoding from here and the body from Message,
	// so the two must describe the same bytes.
	Header map[string][]string
	// Message is the complete raw message as received, after any Received and
	// Delivered-To headers delivery stamps and before any header edits this evaluation
	// makes: header block, blank line, and the body still MIME-structured and
	// transfer-encoded. The body test (RFC 5173) walks the MIME parts itself and the
	// size test (RFC 5228 §5.9) measures the whole message, so this must not be the
	// extracted search text. It is never empty: a delivery has at least a header.
	Message []byte
	// MailboxExists answers the mailbox extension's mailboxexists test (RFC 5490
	// §3.1) for the user the script runs for: the mailbox exists and a fileinto
	// may deliver into it. nil takes every mailbox to exist, for an evaluation that
	// has no mailstore behind it.
	MailboxExists func(ctx context.Context, mailbox string) (bool, error)
}

// VacationOracle defines the methods SievePolicy needs to interact with
// persistent storage for vacation response tracking.
type VacationOracle interface {
	// IsVacationResponseAllowed checks if a vacation response is allowed to be sent
	// to the given originalSender for the specified user and response identity,
	// considering the duration since the last response.
	IsVacationResponseAllowed(ctx context.Context, AccountID int64, originalSender string, responseIdentity string, duration time.Duration) (bool, error)
	// ClaimVacationResponse atomically checks and consumes the suppression period.
	// Unlike the evaluation-time check, this handoff-time decision is definitive.
	ClaimVacationResponse(ctx context.Context, AccountID int64, originalSender, responseIdentity string, duration time.Duration) (bool, error)
}

// RedirectOracle defines the methods SievePolicy needs to interact with
// persistent storage for redirect tracking.
type RedirectOracle interface {
	CountRedirectsSince(ctx context.Context, accountID int64, window time.Duration) (int, error)
	RecordRedirect(ctx context.Context, accountID int64) error
}

type Executor interface {
	Evaluate(evalCtx context.Context, ctx Context) (Result, error)
}

// SieveExecutor implements the Executor interface using the go-sieve library
type SieveExecutor struct {
	script *sieve.Script
	// policy is now initialized with AccountID and vacationOracle
	policy *SievePolicy
}

// NewSieveExecutor creates a new SieveExecutor with the given script content.
// This version initializes a SievePolicy without a VacationOracle or a specific AccountID.
// It's suitable for scripts that do not use vacation actions requiring persistent state,
// or for contexts like syntax validation where policy interaction is minimal or doesn't require user context.
// For scripts that may use vacation with persistence, use NewSieveExecutorWithOracle.
func NewSieveExecutor(scriptContent string) (Executor, error) {
	return NewSieveExecutorWithExtensions(scriptContent, nil)
}

// NewSieveExecutorWithExtensions creates a new SieveExecutor with the given script content and enabled extensions.
// enabledExtensions is the set a require may name; nil enables none (go-sieve), so
// callers pass EffectiveExtensions.
func NewSieveExecutorWithExtensions(scriptContent string, enabledExtensions []string) (Executor, error) {
	compiled, err := CompileScript(scriptContent, enabledExtensions)
	if err != nil {
		return nil, err
	}
	// Basic policy, no oracle, no AccountID by default.
	return &SieveExecutor{script: compiled.script, policy: &SievePolicy{}}, nil
}

// NewSieveExecutorWithOracle creates a new SieveExecutor with the given script content, AccountID, and oracles.
func NewSieveExecutorWithOracle(scriptContent string, AccountID int64, vacOracle VacationOracle, redirectOracle RedirectOracle, redirectRateLimit int, redirectRateWindow time.Duration, maxRedirectHops int) (Executor, error) {
	return NewSieveExecutorWithOracleAndExtensions(scriptContent, AccountID, vacOracle, redirectOracle, redirectRateLimit, redirectRateWindow, maxRedirectHops, nil)
}

// NewSieveExecutorWithOracleAndExtensions creates a new SieveExecutor with the given script content, AccountID, oracles, and enabled extensions.
func NewSieveExecutorWithOracleAndExtensions(scriptContent string, AccountID int64, vacOracle VacationOracle, redirectOracle RedirectOracle, redirectRateLimit int, redirectRateWindow time.Duration, maxRedirectHops int, enabledExtensions []string) (Executor, error) {
	compiled, err := CompileScript(scriptContent, enabledExtensions)
	if err != nil {
		return nil, err
	}
	return compiled.NewExecutor(AccountID, vacOracle, redirectOracle, redirectRateLimit, redirectRateWindow, maxRedirectHops), nil
}

// CompiledScript is a parsed Sieve script, the expensive half of an evaluation. It is
// immutable, so a single copy can back any number of concurrent evaluations for the
// account that owns the script; see ScriptCache.
type CompiledScript struct {
	script *sieve.Script
}

// CompileScript parses and compiles script content with the given extensions enabled.
// enabledExtensions is the set a require may name; nil enables none (go-sieve), so
// callers pass EffectiveExtensions.
func CompileScript(scriptContent string, enabledExtensions []string) (*CompiledScript, error) {
	options := sieve.DefaultOptions()
	options.EnabledExtensions = enabledExtensions
	// Raise the per-match regex soft-wait cap to the whole-script budget. The match
	// input is already truncated to MaxInputLength, so a large body match is bounded;
	// go-sieve's 100ms default can otherwise spuriously fail it under load or -race.
	options.Interp.RegexLimits.MaxExecTime = scriptExecutionTimeout
	script, err := sieve.Load(strings.NewReader(scriptContent), options)
	if err != nil {
		return nil, err
	}
	return &CompiledScript{script: script}, nil
}

// NewExecutor binds a compiled script to an account and its oracles. It is cheap:
// the returned Executor shares the compiled script and only carries per-account policy.
func (c *CompiledScript) NewExecutor(AccountID int64, vacOracle VacationOracle, redirectOracle RedirectOracle, redirectRateLimit int, redirectRateWindow time.Duration, maxRedirectHops int) Executor {
	return &SieveExecutor{
		script: c.script,
		policy: &SievePolicy{
			AccountID:          AccountID,
			vacationOracle:     vacOracle,
			redirectOracle:     redirectOracle,
			redirectRateLimit:  redirectRateLimit,
			redirectRateWindow: redirectRateWindow,
			maxRedirectHops:    maxRedirectHops,
		},
	}
}

// Evaluate evaluates the Sieve script with the given context
func (e *SieveExecutor) Evaluate(evalCtx context.Context, ctx Context) (Result, error) {
	// An empty Message is a caller that did not set it, not a message: it would
	// make every body test false and every `size :under` true without a word.
	if len(ctx.Message) == 0 {
		return Result{}, fmt.Errorf("sieve: Context.Message is empty")
	}

	// Create envelope and message implementations
	envelope := &SieveEnvelope{
		From: ctx.EnvelopeFrom,
		To:   ctx.EnvelopeTo,
	}

	// RFC 5228 §2.6.2.1: Header field names are case-insensitive
	// Normalize all header keys to lowercase to ensure consistent matching
	normalizedHeaders := make(map[string][]string, len(ctx.Header))
	for key, values := range ctx.Header {
		normalizedHeaders[strings.ToLower(key)] = values
	}

	message := &SieveMessage{
		Headers: normalizedHeaders,
		Body:    messageBody(ctx.Message),
		Size:    len(ctx.Message),
	}

	// Create a per-execution policy to ensure thread safety and isolation.
	// The e.policy acts as a template containing configuration.
	execPolicy := &SievePolicy{
		AccountID:          e.policy.AccountID,
		vacationOracle:     e.policy.vacationOracle,
		redirectOracle:     e.policy.redirectOracle,
		redirectRateLimit:  e.policy.redirectRateLimit,
		redirectRateWindow: e.policy.redirectRateWindow,
		maxRedirectHops:    e.policy.maxRedirectHops,
		vacationResponses:  make(map[string]time.Time),
		mailboxExists:      ctx.MailboxExists,
	}

	// Limit execution time of the Sieve script to prevent CPU/resource exhaustion
	timeout := scriptExecutionTimeout
	if deadline, ok := evalCtx.Deadline(); ok {
		left := time.Until(deadline)
		if left < timeout {
			timeout = left
		}
	}
	timeoutCtx, cancel := context.WithTimeout(evalCtx, timeout)
	defer cancel()

	// Create runtime data
	data := sieve.NewRuntimeData(e.script, execPolicy, envelope, message) // RuntimeData holds policy

	// Execute the script
	if err := timeoutCtx.Err(); err != nil {
		return Result{Action: ActionKeep}, err
	}
	err := runScript(timeoutCtx, e.script, data)
	if err != nil {
		return Result{Action: ActionKeep}, err
	}
	if err := timeoutCtx.Err(); err != nil {
		return Result{Action: ActionKeep}, err
	}

	// Process the results
	result := Result{
		Action:     ActionKeep,
		Additional: make(map[string]string),
		Flags:      make([]string, 0),
	}

	// Handle fileinto action
	if len(data.Mailboxes) > 0 {
		// Use the first mailbox (we could support multiple mailboxes in the future)
		result.Action = ActionFileInto
		result.Mailbox = data.Mailboxes[0]

		// Check if ImplicitKeep is true (means :copy was used) OR if Keep is true (explicit keep action)
		// With normal fileinto (no :copy), ImplicitKeep would be false, but an explicit keep
		// after fileinto should still save a copy to INBOX
		result.Copy = data.ImplicitKeep || data.Keep

		// Check if :create modifier was used (RFC 5490 - mailbox extension)
		// MailboxesCreate contains mailboxes that should be created if they don't exist
		if len(data.MailboxesCreate) > 0 {
			// Check if the target mailbox should be created
			for _, createMailbox := range data.MailboxesCreate {
				if createMailbox == result.Mailbox {
					result.CreateMailbox = true
					break
				}
			}
		}
	} else if len(data.RedirectAddr) > 0 {
		// Handle redirect action. A script may redirect to several addresses
		// (RFC 5228 §2.10.4); one named twice gets a single copy (§2.10.3).
		result.Action = ActionRedirect
		for _, addr := range data.RedirectAddr {
			if !slices.Contains(result.RedirectTo, addr) {
				result.RedirectTo = append(result.RedirectTo, addr)
			}
		}
		// The rate limit is charged by delivery, for the addresses it relays to,
		// and not as each redirect command runs: a redirect that fileinto took
		// over, that a later script error undid, or that no relay took is never sent.
		result.RecordRedirect = execPolicy.redirectRecorder()

		// Check if ImplicitKeep is true (means :copy was used) OR if Keep is true (explicit keep action)
		// With normal redirect (no :copy), ImplicitKeep would be false, but an explicit keep
		// after redirect should still save a local copy
		result.Copy = data.ImplicitKeep || data.Keep
	} else if !data.Keep && !data.ImplicitKeep {
		// Handle discard action
		// This includes both explicit discard commands and scripts with no keep action
		result.Action = ActionDiscard
		// reject/ereject cancel the implicit keep too; go-sieve has already
		// refused a reject next to keep, fileinto, redirect or vacation.
		result.Rejected = data.Rejected
		result.RejectExtended = data.RejectExtended
		result.RejectReason = data.RejectReason
	}

	// The vacation reply is decided apart from the action above: it neither depends
	// on nor changes what happens to the message (RFC 5230 §4.7). go-sieve keys
	// VacationResponses by the envelope sender, so there is at most one, and it has
	// already refused a vacation next to reject.
	for sender, vacation := range data.VacationResponses {
		// RFC 5230 §4.1: clamp to the site's supported range before converting
		// to time.Duration, which would overflow for large Sieve numbers.
		days := max(1, min(vacation.Days, consts.MaxVacationDays))
		duration := time.Duration(days) * 24 * time.Hour
		allowed, err := execPolicy.VacationResponseAllowed(timeoutCtx, data, sender, vacation.ResponseIdentity, duration)
		if err != nil || !allowed {
			// An oracle error must not fail the delivery; it costs this one reply.
			break
		}
		result.Vacation = &VacationReply{
			From:          vacation.From,
			Subject:       vacation.Subject,
			Body:          vacation.Body,
			IsMime:        vacation.IsMime,
			ClaimResponse: execPolicy.vacationClaimer(sender, vacation.ResponseIdentity, duration),
		}
		break
	}

	// Handle flags
	if len(data.Flags) > 0 {
		result.Flags = data.Flags
	}

	// Handle header edits (RFC 5293 - editheader extension)
	if len(data.HeaderEdits) > 0 {
		result.HeaderEdits = make([]HeaderEdit, len(data.HeaderEdits))
		for i, edit := range data.HeaderEdits {
			result.HeaderEdits[i] = HeaderEdit{
				Action:    edit.Action,
				FieldName: edit.FieldName,
				Value:     edit.Value,
				Last:      edit.Last,
				Index:     edit.Index,
			}
		}
	}

	return result, nil
}

// SievePolicy implements the PolicyReader interface
type SievePolicy struct {
	vacationResponses map[string]time.Time

	AccountID      int64
	vacationOracle VacationOracle

	redirectOracle     RedirectOracle
	redirectRateLimit  int
	redirectRateWindow time.Duration
	maxRedirectHops    int // mail-loop backstop; 0 = unlimited

	// redirectsAllowed holds the distinct addresses this evaluation has let a
	// redirect through to. They count against the rate limit as they
	// accumulate, though nothing is recorded until delivery relays them.
	redirectsAllowed []string

	mailboxExists func(ctx context.Context, mailbox string) (bool, error) // Context.MailboxExists
}

// MailboxExists implements go-sieve's MailboxChecker, the mailboxexists test (RFC
// 5490 §3.1), through Context.MailboxExists. Without a policy implementing it the
// interpreter takes every mailbox to exist.
func (p *SievePolicy) MailboxExists(ctx context.Context, mailbox string) (bool, error) {
	if p.mailboxExists == nil {
		return true, nil
	}
	return p.mailboxExists(ctx, mailbox)
}

func (p *SievePolicy) RedirectAllowed(ctx context.Context, d *interp.RuntimeData, addr string) (bool, error) {
	// (3) Validate target. Malformed -> skip redirect, keep message.
	// Note: go-sieve redirects to its own copy of addr; this is a format gate only.
	if _, err := mail.ParseAddress(addr); err != nil {
		return false, nil
	}

	// (2) Loop / backscatter suppression (RFC 5230-style).
	headerGet := func(k string) []string {
		vals, _ := d.Msg.HeaderGet(k)
		return vals
	}

	// (0) Mail-loop backstop: refuse to redirect a message Sora has already
	// redirected maxRedirectHops times (counted via the X-Sora-Loop header).
	// maxRedirectHops <= 0 disables this backstop (Delivered-To still applies).
	if p.maxRedirectHops > 0 && helpers.RedirectHopCount(headerGet) >= p.maxRedirectHops {
		return false, nil
	}

	if reason := helpers.ShouldSuppressAuto(d.Envelope.EnvelopeFrom(), headerGet); reason != "" {
		return false, nil
	}

	// A repeated address is relayed once, so it is already accounted for.
	if slices.Contains(p.redirectsAllowed, addr) {
		return true, nil
	}

	// (1) Per-account rate limit.
	if p.redirectOracle != nil && p.redirectRateLimit > 0 {
		n, err := p.redirectOracle.CountRedirectsSince(ctx, p.AccountID, p.redirectRateWindow)
		if err != nil {
			// fail-closed-to-keep
			return false, nil
		}
		if n+len(p.redirectsAllowed) >= p.redirectRateLimit {
			return false, nil
		}
	}
	p.redirectsAllowed = append(p.redirectsAllowed, addr)
	return true, nil
}

// redirectRecorder returns Result.RecordRedirect, or nil when no rate limit applies.
// The returned function takes its own context: it runs on the delivery path, after
// this evaluation's budget has expired.
func (p *SievePolicy) redirectRecorder() func(context.Context) error {
	oracle := p.redirectOracle
	if oracle == nil || p.redirectRateLimit <= 0 {
		return nil
	}
	accountID := p.AccountID
	return func(ctx context.Context) error {
		return oracle.RecordRedirect(ctx, accountID)
	}
}

// VacationResponseAllowed is called by the Sieve interpreter.
// `recipient` is the address of the original sender of the message being processed.
// `responseIdentity` identifies the unexpanded vacation arguments or explicit handle.
// `duration` is the :days parameter from the vacation command.
func (p *SievePolicy) VacationResponseAllowed(ctx context.Context, d *interp.RuntimeData,
	originalSender, responseIdentity string, duration time.Duration) (bool, error) {

	// Key for in-memory tracking (per script execution, per response identity)
	// This is the cooldown per response identity within the same script evaluation.
	inMemoryKey := originalSender + ":" + responseIdentity

	if p.vacationOracle != nil {
		// Use the oracle for the persistent check (this is the main :days check)
		allowed, err := p.vacationOracle.IsVacationResponseAllowed(ctx, p.AccountID, originalSender, responseIdentity, duration)
		if err != nil {
			return false, fmt.Errorf("checking persistent vacation allowance via oracle: %w", err)
		}
		if !allowed {
			return false, nil // Persistently not allowed
		}
	} else {
		// Fallback to only in-memory check if no oracle (e.g. for default script without DB access, or testing)
		if p.vacationResponses == nil {
			p.vacationResponses = make(map[string]time.Time)
		}
		lastSent, exists := p.vacationResponses[inMemoryKey]
		if exists && time.Since(lastSent) < duration {
			return false, nil // Deny based on in-script, per-identity cooldown for this session
		}
	}

	// If allowed (either by oracle or by lack of recent in-memory for no-oracle case),
	// update the in-memory map for this specific script execution session and response identity.
	if p.vacationResponses == nil {
		p.vacationResponses = make(map[string]time.Time)
	}
	p.vacationResponses[inMemoryKey] = time.Now()

	return true, nil
}

// vacationClaimer returns the deferred claim of the persistent :days window for
// `originalSender`, or nil when there is no oracle (the in-memory fallback tracking
// lives and dies with a single evaluation). The returned function takes its own
// context: it runs on the delivery path, after this evaluation's budget has expired.
func (p *SievePolicy) vacationClaimer(originalSender, responseIdentity string, duration time.Duration) func(context.Context) (bool, error) {
	oracle := p.vacationOracle
	if oracle == nil {
		return nil
	}
	accountID := p.AccountID
	return func(ctx context.Context) (bool, error) {
		claimed, err := oracle.ClaimVacationResponse(ctx, accountID, originalSender, responseIdentity, duration)
		if err != nil {
			return false, fmt.Errorf("failed to claim vacation response via oracle: %w", err)
		}
		return claimed, nil
	}
}

// SieveEnvelope implements the Envelope interface
type SieveEnvelope struct {
	From string
	To   string
	Auth string
}

func (e *SieveEnvelope) EnvelopeFrom() string {
	return e.From
}

func (e *SieveEnvelope) EnvelopeTo() string {
	return e.To
}

func (e *SieveEnvelope) AuthUsername() string {
	return e.Auth
}

// SieveMessage implements the Message interface
type SieveMessage struct {
	Headers map[string][]string
	Body    []byte
	Size    int
}

func (m *SieveMessage) HeaderGet(key string) ([]string, error) {
	// RFC 5228 §2.6.2.1: Header field names are case-insensitive
	// Since LMTP normalizes headers to lowercase, we must do case-insensitive lookup
	return m.Headers[strings.ToLower(key)], nil
}

func (m *SieveMessage) MessageSize() int {
	return m.Size
}

func (m *SieveMessage) BodyRaw() ([]byte, bool, error) {
	return m.Body, m.Body != nil, nil
}

// messageBody returns the octets after the blank line that ends msg's header block,
// or nil when there is no blank line. RFC 5173 §4: "If a message consists of a header
// only, not followed by an empty line, then that set is empty and all "body" tests
// return false, including those that test for an empty string." The engine reports
// nil as no body, which is what makes every body test false. Lines may end in CRLF
// or bare LF, and the two may be mixed.
func messageBody(msg []byte) []byte {
	for i := 0; i < len(msg); {
		n := bytes.IndexByte(msg[i:], '\n')
		if n < 0 {
			return nil
		}
		line := msg[i : i+n]
		i += n + 1
		if len(line) == 0 || (len(line) == 1 && line[0] == '\r') {
			return msg[i:]
		}
	}
	return nil
}

// ApplyHeaderEdits applies header modifications to raw message bytes (RFC 5293)
// Returns the modified message bytes with header edits applied
func ApplyHeaderEdits(messageBytes []byte, edits []HeaderEdit) ([]byte, error) {
	if len(edits) == 0 {
		return messageBytes, nil
	}

	// Parse message using go-message
	entity, err := message.Read(bytes.NewReader(messageBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	// Apply header edits
	for _, edit := range edits {
		switch edit.Action {
		case "add":
			if edit.Last {
				// Add at the end - go-message naturally adds to the end
				entity.Header.Add(edit.FieldName, edit.Value)
			} else {
				// Add at the beginning - need to preserve existing and prepend
				existingValues := entity.Header.Values(edit.FieldName)
				entity.Header.Del(edit.FieldName)
				entity.Header.Add(edit.FieldName, edit.Value)
				for _, v := range existingValues {
					entity.Header.Add(edit.FieldName, v)
				}
			}

		case "delete":
			if edit.Index > 0 {
				// Delete specific index
				values := entity.Header.Values(edit.FieldName)
				if len(values) == 0 {
					continue
				}

				idx := edit.Index - 1
				if edit.Last {
					idx = len(values) - edit.Index
				}

				if idx >= 0 && idx < len(values) {
					entity.Header.Del(edit.FieldName)
					for i, v := range values {
						if i != idx {
							entity.Header.Add(edit.FieldName, v)
						}
					}
				}

			} else if edit.Value != "" {
				// Delete first occurrence matching value
				values := entity.Header.Values(edit.FieldName)
				entity.Header.Del(edit.FieldName)
				deleted := false
				for _, v := range values {
					if !deleted && v == edit.Value {
						deleted = true
						continue
					}
					entity.Header.Add(edit.FieldName, v)
				}

			} else {
				// Delete all occurrences
				entity.Header.Del(edit.FieldName)
			}
		}
	}

	// Write modified message back to bytes
	var buf bytes.Buffer
	if err := entity.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("failed to write modified message: %w", err)
	}

	return buf.Bytes(), nil
}

// maxLoggedRejectReason bounds the reject reason in a log line. The reason is
// script-controlled and, through variables, can carry message content.
const maxLoggedRejectReason = 256

// RejectLogFields names the action ("reject" or "ereject") and gives its
// reason cut to maxLoggedRejectReason bytes on a rune boundary, for a log line.
func (r Result) RejectLogFields() (action, reason string) {
	action = "reject"
	if r.RejectExtended {
		action = "ereject"
	}
	reason = r.RejectReason
	if len(reason) > maxLoggedRejectReason {
		cut := maxLoggedRejectReason
		for cut > 0 && !utf8.RuneStart(reason[cut]) {
			cut--
		}
		reason = reason[:cut] + "..."
	}
	return action, reason
}

// scriptRunner is what runScript needs of a compiled script; *sieve.Script
// satisfies it, and a test can stand in a script that panics.
type scriptRunner interface {
	Execute(ctx context.Context, d *interp.RuntimeData) error
}

// runScript executes a script and turns a panic in the interpreter into an
// evaluation error, so delivery keeps the message as it does for any other
// Sieve error. Without this the panic would unwind through the LMTP command
// handler, which answers 421 and closes the connection, and the MTA would
// retry the same message into the same panic until it expired and bounced.
func runScript(ctx context.Context, script scriptRunner, data *interp.RuntimeData) (err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			if len(stack) > maxPanicStackBytes {
				stack = stack[:maxPanicStackBytes]
			}
			err = fmt.Errorf("sieve script panicked: %v\n%s", r, stack)
		}
	}()
	return script.Execute(ctx, data)
}

// maxPanicStackBytes bounds the stack kept in a script panic's error.
const maxPanicStackBytes = 4096
