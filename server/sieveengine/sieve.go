package sieveengine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/foxcpp/go-sieve"
	"github.com/foxcpp/go-sieve/interp"
)

type Action string

const (
	ActionKeep     Action = "keep"
	ActionDiscard  Action = "discard"
	ActionFileInto Action = "fileinto"
	ActionRedirect Action = "redirect"
	ActionVacation Action = "vacation"
)

type Result struct {
	Action         Action
	Mailbox        string            // used for fileinto
	RedirectTo     string            // used for redirect
	Flags          []string          // flags to add to the message
	VacationFrom   string            // used for vacation - from address
	VacationSubj   string            // used for vacation - subject
	VacationMsg    string            // used for vacation - message body
	VacationIsMime bool              // used for vacation - is MIME message
	Copy           bool              // RFC3894 - :copy modifier for redirect and fileinto
	Additional     map[string]string // future-proofing
}

type Context struct {
	EnvelopeFrom string
	EnvelopeTo   string
	Header       map[string][]string
	Body         string
}

// VacationOracle defines the methods SievePolicy needs to interact with
// persistent storage for vacation response tracking.
type VacationOracle interface {
	// IsVacationResponseAllowed checks if a vacation response is allowed to be sent
	// to the given originalSender for the specified user and handle,
	// considering the duration since the last response.
	IsVacationResponseAllowed(ctx context.Context, AccountID int64, originalSender string, handle string, duration time.Duration) (bool, error)
	// RecordVacationResponseSent records that a vacation response has been sent
	// to the originalSender for the specified user and handle.
	RecordVacationResponseSent(ctx context.Context, AccountID int64, originalSender string, handle string) error
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
// If enabledExtensions is nil, all extensions are allowed
func NewSieveExecutorWithExtensions(scriptContent string, enabledExtensions []string) (Executor, error) {
	// Load the script
	scriptReader := strings.NewReader(scriptContent)
	options := sieve.DefaultOptions()
	options.EnabledExtensions = enabledExtensions
	script, err := sieve.Load(scriptReader, options)
	if err != nil {
		return nil, err
	}

	policy := &SievePolicy{} // Basic policy, no oracle, no AccountID by default.

	return &SieveExecutor{
		script: script,
		policy: policy,
	}, nil
}

// NewSieveExecutorWithOracle creates a new SieveExecutor with the given script content, AccountID, and vacation oracle.
func NewSieveExecutorWithOracle(scriptContent string, AccountID int64, oracle VacationOracle) (Executor, error) {
	return NewSieveExecutorWithOracleAndExtensions(scriptContent, AccountID, oracle, nil)
}

// NewSieveExecutorWithOracleAndExtensions creates a new SieveExecutor with the given script content, AccountID, vacation oracle, and enabled extensions.
func NewSieveExecutorWithOracleAndExtensions(scriptContent string, AccountID int64, oracle VacationOracle, enabledExtensions []string) (Executor, error) {
	scriptReader := strings.NewReader(scriptContent)
	options := sieve.DefaultOptions()
	options.EnabledExtensions = enabledExtensions
	script, err := sieve.Load(scriptReader, options)
	if err != nil {
		return nil, err
	}

	policy := &SievePolicy{
		AccountID:      AccountID,
		vacationOracle: oracle,
	}

	return &SieveExecutor{
		script: script,
		policy: policy,
	}, nil
}

// Evaluate evaluates the Sieve script with the given context
func (e *SieveExecutor) Evaluate(evalCtx context.Context, ctx Context) (Result, error) {
	// Create envelope and message implementations
	envelope := &SieveEnvelope{
		From: ctx.EnvelopeFrom,
		To:   ctx.EnvelopeTo,
	}

	message := &SieveMessage{
		Headers: ctx.Header,
		Body:    []byte(ctx.Body),
		Size:    len(ctx.Body),
	}

	// Create runtime data
	data := sieve.NewRuntimeData(e.script, e.policy, envelope, message) // RuntimeData holds policy

	// Execute the script
	err := e.script.Execute(evalCtx, data) // Pass the evaluation context
	if err != nil {
		return Result{Action: ActionKeep}, err
	}

	// Process the results
	result := Result{
		Action:     ActionKeep,
		Additional: make(map[string]string),
		Flags:      make([]string, 0),
	}

	// Check if vacation response was triggered
	if e.policy.vacationTriggered {
		result.Action = ActionVacation
		result.VacationFrom = e.policy.lastVacationFrom
		result.VacationSubj = e.policy.lastVacationSubj
		result.VacationMsg = e.policy.lastVacationMsg
		result.VacationIsMime = e.policy.lastVacationIsMime

		// Reset the vacation triggered flag for next evaluation
		e.policy.vacationTriggered = false
	}

	// Handle fileinto action
	if len(data.Mailboxes) > 0 {
		// Use the first mailbox (we could support multiple mailboxes in the future)
		result.Action = ActionFileInto
		result.Mailbox = data.Mailboxes[0]

		// Check if ImplicitKeep is true, which means :copy was used
		// With normal fileinto (no :copy), ImplicitKeep would be false
		result.Copy = data.ImplicitKeep
	}

	// Handle redirect action
	if len(data.RedirectAddr) > 0 {
		// Use the first redirect address (we could support multiple redirects in the future)
		result.Action = ActionRedirect
		result.RedirectTo = data.RedirectAddr[0]

		// Check if ImplicitKeep is true, which means :copy was used
		// With normal redirect (no :copy), ImplicitKeep would be false
		result.Copy = data.ImplicitKeep
	}

	// Handle discard action
	if !data.Keep && !data.ImplicitKeep && len(data.Mailboxes) == 0 && len(data.RedirectAddr) == 0 {
		result.Action = ActionDiscard
	}

	// Handle flags
	if len(data.Flags) > 0 {
		result.Flags = data.Flags
	}

	return result, nil
}

// SievePolicy implements the PolicyReader interface
type SievePolicy struct {
	vacationResponses  map[string]time.Time
	lastVacationFrom   string
	lastVacationSubj   string
	lastVacationMsg    string
	lastVacationIsMime bool
	lastVacationHandle string // Stores the handle of the currently allowed vacation
	vacationTriggered  bool

	AccountID      int64
	vacationOracle VacationOracle
}

func (p *SievePolicy) RedirectAllowed(ctx context.Context, d *interp.RuntimeData, addr string) (bool, error) {
	// For now, always allow redirects
	return true, nil
}

// VacationResponseAllowed is called by the Sieve interpreter.
// `recipient` is the address of the original sender of the message being processed.
// `handle` can be used to distinguish between multiple vacation actions in a script.
// `duration` is the :days parameter from the vacation command.
func (p *SievePolicy) VacationResponseAllowed(ctx context.Context, d *interp.RuntimeData,
	originalSender, handle string, duration time.Duration) (bool, error) {

	// Key for in-memory tracking (per script execution, per handle)
	// This is for Sieve's :handle specific cooldown within the same script evaluation.
	inMemoryKey := originalSender + ":" + handle

	if p.vacationOracle != nil {
		// Use the oracle for the persistent check (this is the main :days check)
		allowed, err := p.vacationOracle.IsVacationResponseAllowed(ctx, p.AccountID, originalSender, handle, duration)
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
			return false, nil // Deny based on in-script, per-handle cooldown for this session
		}
	}

	// If allowed (either by oracle or by lack of recent in-memory for no-oracle case),
	// update the in-memory map for this specific script execution session and handle.
	if p.vacationResponses == nil {
		p.vacationResponses = make(map[string]time.Time)
	}
	p.vacationResponses[inMemoryKey] = time.Now()

	// Store the handle for which the response is allowed, so SendVacationResponse can use it.
	p.lastVacationHandle = handle

	return true, nil
}

// SendVacationResponse is called by the Sieve interpreter if VacationResponseAllowed returned true.
// `recipient` is the address to send the vacation message TO (i.e., the original sender).
func (p *SievePolicy) SendVacationResponse(ctx context.Context, d *interp.RuntimeData,
	recipient, from, subject, body string, isMime bool) error {

	// Store the vacation response details
	p.lastVacationFrom = from
	p.lastVacationSubj = subject
	p.lastVacationMsg = body
	p.lastVacationIsMime = isMime
	p.vacationTriggered = true

	if p.vacationOracle != nil {
		if err := p.vacationOracle.RecordVacationResponseSent(ctx, p.AccountID, recipient, p.lastVacationHandle); err != nil {
			return fmt.Errorf("failed to record vacation response sent via oracle: %w", err)
		}
	}
	return nil
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
	return m.Headers[key], nil
}

func (m *SieveMessage) MessageSize() int {
	return m.Size
}
