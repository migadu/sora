package sieveengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/mail"
	"runtime/debug"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
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

// scriptExecutionTimeout supplies the cooperative execution budget of a Sieve
// script and the per-match regex deadline (Options.Interp.RegexLimits.MaxExecTime).
// Inputs over 1 KB check it while matching; smaller matches and compilation run
// inline under the input/pattern/program limits. It is not a strict wall-clock cap.
// Configurable via SetScriptExecutionTimeout (from [sieve] max_execution_time).
var scriptExecutionTimeout = 2 * time.Second

const (
	minScriptExecutionTimeout = 100 * time.Millisecond
	maxScriptExecutionTimeout = 60 * time.Second
)

// SetScriptExecutionTimeout overrides the Sieve script execution budget (and the
// large-input regex deadline derived from it). The value is clamped to
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

// MaxFileintoTargets is how many mailboxes one script may file one message into.
// Every target is a stored copy (a message row and an upload entry, and with
// :create maybe a new mailbox), so without a bound a script could make each
// incoming message cost hundreds of them. RFC 5228 §2.10.4: "Site policy MAY
// limit the number of actions taken ... In the event that a script hits a policy
// limit on the number of actions taken for a particular message, an error
// occurs." Pigeonhole's sieve_max_actions defaults to 32 as well.
const MaxFileintoTargets = 32

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
	// Action sums up what the script did with the message, for the log and for the
	// merge with the default script: fileinto if it filed it anywhere, else redirect
	// if it redirected it, else discard if nothing keeps it, else keep. It does not
	// choose between them: delivery carries out every fileinto in Mailboxes and every
	// redirect in RedirectTo, and Destinations says where the message is stored.
	Action          Action
	Mailboxes       []string          // every fileinto target, in script order, without repeats
	CreateMailboxes []string          // RFC 5490 :create - the Mailboxes to create if missing
	RedirectTo      []string          // every address to relay to, without repeats
	Flags           []string          // flags to add to the message
	Copy            bool              // with fileinto or redirect: the message is also kept (explicit keep, or every one used RFC 3894 :copy)
	HeaderEdits     []HeaderEdit      // RFC5293 - editheader extension (addheader/deleteheader)
	Additional      map[string]string // future-proofing

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
	Subject string // the :subject, even empty; without one the RFC 5230 §5.3 default
	Body    string // the reason
	IsMime  bool
	// Addresses is the :addresses list: addresses of the recipient besides the
	// account's own, for the personal message check (RFC 5230 §4.5).
	Addresses []string

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
	// so the two must describe the same bytes. Build it with HeaderMap: keys that fold
	// to one name under i;ascii-casemap are merged, but only HeaderMap keeps their
	// fields in message order.
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
	// RFC 5228 sections 1.1, 2.4.2.1 and 8.1 require Sieve scripts to be valid UTF-8 and
	// forbid NUL octets (0x00) inside strings and comments; PostgreSQL text columns also
	// reject both with SQLSTATE 22021. go-sieve's lexer only rejects NUL at top-level
	// token boundaries and never validates UTF-8.
	if !helpers.TextStorable(scriptContent) {
		if !utf8.ValidString(scriptContent) {
			return nil, errors.New("sieve: script is not valid UTF-8")
		}
		return nil, errors.New("sieve: script contains NUL byte")
	}
	options := sieve.DefaultOptions()
	options.EnabledExtensions = enabledExtensions
	// Raise the large-input regex deadline to the whole-script budget: go-sieve's
	// 100ms default can otherwise spuriously fail a body match under load or -race.
	// Inputs over 1 KB check the deadline as they are read, then stop on timeout;
	// short matches and compilation remain inline under the fixed size limits.
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

	// Header names compare under i;ascii-casemap (RFC 5228 §2.7): the map is
	// keyed by the lower-cased name and HeaderGet lowers the name it looks up.
	// Keys that fold to one name are that name's fields, so their values are
	// merged rather than one key's replacing the other's.
	normalizedHeaders := make(map[string][]string, len(ctx.Header))
	for key, values := range ctx.Header {
		name := lowerASCII(key)
		if prev, ok := normalizedHeaders[name]; ok {
			values = append(slices.Clip(prev), values...)
		}
		normalizedHeaders[name] = values
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
	// Over the limit the script is in error: none of its actions are carried out
	// and the message is kept (RFC 5228 §2.10.6), as for any other run-time error.
	if len(data.Mailboxes) > MaxFileintoTargets {
		return Result{Action: ActionKeep}, fmt.Errorf("sieve: too many fileinto actions: %d mailboxes, at most %d", len(data.Mailboxes), MaxFileintoTargets)
	}

	// Process the results
	result := Result{
		Action:     ActionKeep,
		Additional: make(map[string]string),
		Flags:      make([]string, 0),
	}

	// Every fileinto and every redirect the script ran is carried out, next to one
	// another and to a keep: RFC 5228 §2.10.4 lets a site limit the actions, but a
	// script that hits such a limit is an error, not one whose actions are skipped.
	// go-sieve has already dropped a repeated fileinto target (§2.10.3); a repeated
	// redirect address is relayed once.
	result.Mailboxes = data.Mailboxes
	result.CreateMailboxes = data.MailboxesCreate
	for _, addr := range data.RedirectAddr {
		if !slices.Contains(result.RedirectTo, addr) {
			result.RedirectTo = append(result.RedirectTo, addr)
		}
	}
	// Delivery charges only addresses actually handed to a relay, including a
	// redirect next to fileinto. An unsent redirect consumes no allowance.
	if len(result.RedirectTo) > 0 {
		result.RecordRedirect = execPolicy.redirectRecorder()
	}

	if len(result.Mailboxes) > 0 || len(result.RedirectTo) > 0 {
		result.Action = ActionFileInto
		if len(result.Mailboxes) == 0 {
			result.Action = ActionRedirect
		}
		// The implicit keep survives only a fileinto or redirect with :copy (RFC 3894
		// §3); an explicit keep stores the message as well.
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
			Addresses:     vacation.Addresses,
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
	return m.Headers[lowerASCII(key)], nil
}

// HeaderMap returns the fields of h for Context.Header, keyed by the name folded
// under i;ascii-casemap (RFC 5228 §2.7), each name's values in message order.
//
// go-message's Header.Map keys a field by textproto.CanonicalMIMEHeaderKey, which
// returns a name holding a byte that is not an RFC 7230 token character, such as
// "(" or "/", as written, although RFC 5322 §3.6.8 allows those bytes in a field
// name (ftext = %d33-57 / %d59-126). "X(a" and "x(A" are then two keys of one
// field name, and a map cannot say which field came first, which :index counts
// from (RFC 5260 §6) and the date test takes (RFC 5260 §4).
func HeaderMap(h message.Header) map[string][]string {
	m := make(map[string][]string, h.Len())
	fields := h.Fields()
	for fields.Next() {
		name := lowerASCII(fields.Key())
		m[name] = append(m[name], fields.Value())
	}
	return m
}

// lowerASCII lowers the US-ASCII letters of a header name and leaves every other
// byte as it is. Header names compare under i;ascii-casemap (RFC 5228 §2.7), which
// "treats US-ASCII letters case-insensitively" and under which "letters outside
// ASCII are not treated case-insensitively" (RFC 4790 §9.2.1); strings.ToLower
// would also lower U+212A KELVIN SIGN to "k" and U+0130 LATIN CAPITAL LETTER I
// WITH DOT ABOVE to "i".
func lowerASCII(s string) string {
	i := 0
	for i < len(s) && (s[i] < 'A' || s[i] > 'Z') {
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if 'A' <= b[i] && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
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

// ApplyHeaderEdits applies a script's addheader/deleteheader edits (RFC 5293) to
// the raw message, in order, each to the header the earlier ones left, as the
// script saw it. It edits the header's list of fields and nothing else: every
// field it does not add or delete and the whole body keep their bytes, so a DKIM
// signature over them still verifies.
func ApplyHeaderEdits(messageBytes []byte, edits []HeaderEdit) ([]byte, error) {
	if len(edits) == 0 {
		return messageBytes, nil
	}

	end := headerEnd(messageBytes)
	fields := parseHeaderFields(messageBytes[:end])

	// Added fields end their lines as the message does, so a bare-LF message does
	// not get mixed line breaks.
	eol := "\r\n"
	if n := bytes.IndexByte(messageBytes, '\n'); n == 0 || n > 0 && messageBytes[n-1] != '\r' {
		eol = "\n"
	}

	for _, edit := range edits {
		// RFC 5293 §5: "The field-name is mandatory and always matched as a
		// case-insensitive US-ASCII string."
		key := lowerASCII(edit.FieldName)
		switch edit.Action {
		case "add":
			raw, err := formatAddedField(edit.FieldName, edit.Value, eol)
			if err != nil {
				return nil, err
			}
			f := headerField{key: key, value: edit.Value, raw: raw}
			// RFC 5293 §4: "By default, the header field is inserted at the
			// beginning of the existing message header.  If the optional flag
			// ":last" is specified, it is appended at the end."
			if edit.Last {
				fields = append(fields, f)
			} else {
				fields = slices.Insert(fields, 0, f)
			}

		case "delete":
			switch {
			case edit.Index > 0:
				// RFC 5293 §5: :index counts the named fields "beginning at 1,
				// the first named header field.  If :last is specified, the
				// count is backwards; 1 denotes the last named header field".
				var named []int
				for i, f := range fields {
					if f.key == key {
						named = append(named, i)
					}
				}
				n := edit.Index - 1
				if edit.Last {
					n = len(named) - edit.Index
				}
				if n >= 0 && n < len(named) {
					fields = slices.Delete(fields, named[n], named[n]+1)
				}
			case edit.Value != "":
				// go-sieve records one edit for each field whose value matched
				// the value-patterns, carrying that value.
				if i := slices.IndexFunc(fields, func(f headerField) bool {
					return f.key == key && f.value == edit.Value
				}); i >= 0 {
					fields = slices.Delete(fields, i, i+1)
				}
			default:
				fields = slices.DeleteFunc(fields, func(f headerField) bool { return f.key == key })
			}
		}
	}

	out := make([]byte, 0, len(messageBytes)+len(edits)*64)
	for i, f := range fields {
		out = append(out, f.raw...)
		// Only the last line of a header with no body can lack a line break; a
		// field may now follow it.
		if i < len(fields)-1 && !bytes.HasSuffix(f.raw, []byte{'\n'}) {
			out = append(out, eol...)
		}
	}
	return append(out, messageBytes[end:]...), nil
}

// headerField is one field of a message header: its bytes as the message has
// them (the first line, any continuation lines and their line breaks), its name
// lower-cased for i;ascii-casemap, and its value as the script's header map holds
// it. A line with no colon is kept with an empty key and never matches an edit.
type headerField struct {
	key   string
	value string
	raw   []byte
}

// parseHeaderFields splits a header block into its fields. A line that starts
// with SP or HT continues the field before it (RFC 5322 §2.2.3).
func parseHeaderFields(header []byte) []headerField {
	var fields []headerField
	start := 0
	for i := 0; i < len(header); {
		next := len(header)
		if n := bytes.IndexByte(header[i:], '\n'); n >= 0 {
			next = i + n + 1
		}
		if i > start && header[i] != ' ' && header[i] != '\t' {
			fields = append(fields, newHeaderField(header[start:i]))
			start = i
		}
		i = next
	}
	if start < len(header) {
		fields = append(fields, newHeaderField(header[start:]))
	}
	return fields
}

func newHeaderField(raw []byte) headerField {
	f := headerField{raw: raw}
	firstLine := raw
	if n := bytes.IndexByte(raw, '\n'); n >= 0 {
		firstLine = raw[:n]
	}
	colon := bytes.IndexByte(firstLine, ':')
	if colon < 0 {
		return f
	}
	// go-message, which built the script's header map, drops the SP/HT around
	// the name and unfolds the value: each line without its line break and the
	// SP/HT around it, the non-empty ones joined with a single space.
	f.key = lowerASCII(string(bytes.Trim(raw[:colon], " \t")))
	var value strings.Builder
	for line := range bytes.Lines(raw[colon+1:]) {
		if l, ok := bytes.CutSuffix(line, []byte{'\n'}); ok {
			line = bytes.TrimSuffix(l, []byte{'\r'})
		}
		if line = bytes.Trim(line, " \t"); len(line) == 0 {
			continue
		}
		if value.Len() > 0 {
			value.WriteByte(' ')
		}
		value.Write(line)
	}
	f.value = value.String()
	return f
}

// formatAddedField formats an addheader field as go-message writes a new field,
// folded to RFC 5322 line lengths, with its lines ending in eol. A value holding
// a CR or LF is refused.
func formatAddedField(name, value, eol string) ([]byte, error) {
	var h textproto.Header
	h.Add(name, value)
	var b bytes.Buffer
	if err := textproto.WriteHeader(&b, h); err != nil {
		return nil, fmt.Errorf("addheader %q: %w", name, err)
	}
	raw := b.Bytes()[:b.Len()-2] // WriteHeader ends the header with a blank line
	if eol == "\n" {
		raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	}
	return raw, nil
}

// headerEnd returns the length of msg's header block: the octets before the blank
// line that ends it, or all of msg when there is none.
func headerEnd(msg []byte) int {
	for i := 0; i < len(msg); {
		if msg[i] == '\n' || msg[i] == '\r' && i+1 < len(msg) && msg[i+1] == '\n' {
			return i
		}
		n := bytes.IndexByte(msg[i:], '\n')
		if n < 0 {
			break
		}
		i += n + 1
	}
	return len(msg)
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

// Destination is a mailbox delivery stores the message in.
type Destination struct {
	Mailbox string
	Create  bool // RFC 5490 §3.2 fileinto :create: create the mailbox if it is missing
}

// Destinations lists the mailboxes the message is stored in: every fileinto target,
// then INBOX when the message is kept (RFC 5228 §2.10.2, §4.3), each mailbox once
// (§2.10.3; mailbox names are case-insensitive here). redirectFailed reports a
// redirect that could not be handed to the relay: a message then stored nowhere
// else is kept in INBOX rather than lost (§4.2: "Any ignored redirect MUST NOT
// cancel the implicit keep"). An empty list means nothing is stored.
func (r Result) Destinations(redirectFailed bool) []Destination {
	dests := make([]Destination, 0, len(r.Mailboxes)+1)
	add := func(mailbox string, create bool) {
		for i := range dests {
			if strings.EqualFold(dests[i].Mailbox, mailbox) {
				// One copy, but a :create on either spelling still creates it.
				dests[i].Create = dests[i].Create || create
				return
			}
		}
		dests = append(dests, Destination{Mailbox: mailbox, Create: create})
	}
	for _, mailbox := range r.Mailboxes {
		create := slices.Contains(r.CreateMailboxes, mailbox)
		if create {
			// The copy goes into the mailbox :create makes: "Foo" for "Foo/" (RFC 3501
			// §6.3.3). A name that makes none stays as it is; creating it fails, and
			// delivery keeps the message instead.
			if name, err := helpers.MailboxNameToCreate(mailbox); err == nil {
				mailbox = name
			}
		}
		add(mailbox, create)
	}
	if r.Action == ActionKeep || r.Copy || (redirectFailed && len(dests) == 0) {
		add(consts.MailboxInbox, false)
	}
	return dests
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
