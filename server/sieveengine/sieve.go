package sieveengine

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/foxcpp/go-sieve"
	"github.com/foxcpp/go-sieve/interp"
	"github.com/migadu/sora/server/managesieve"
)

type Action string

const (
	ActionKeep     Action = "keep"
	ActionDiscard  Action = "discard"
	ActionFileInto Action = "fileinto"
	ActionRedirect Action = "redirect"
	ActionVacation Action = "vacation"
)

// DefaultSieveExtensions is an alias for the authoritative list of supported Sieve extensions.
// The canonical list is maintained in server/managesieve/capabilities.go
var DefaultSieveExtensions = managesieve.SupportedExtensions

// HeaderEdit represents a header modification from editheader extension
type HeaderEdit struct {
	Action    string // "add" or "delete"
	FieldName string
	Value     string
	Last      bool // for addheader: add at end; for deleteheader: count from end
	Index     int  // for deleteheader: specific index (0 means all)
}

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
	CreateMailbox  bool              // RFC5490 - :create modifier (mailbox extension)
	HeaderEdits    []HeaderEdit      // RFC5293 - editheader extension (addheader/deleteheader)
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

	// Create a per-execution policy to ensure thread safety and isolation.
	// The e.policy acts as a template containing configuration.
	execPolicy := &SievePolicy{
		AccountID:         e.policy.AccountID,
		vacationOracle:    e.policy.vacationOracle,
		vacationResponses: make(map[string]time.Time),
	}

	// Create runtime data
	data := sieve.NewRuntimeData(e.script, execPolicy, envelope, message) // RuntimeData holds policy

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
	// The go-sieve library stores vacation responses in data.VacationResponses
	vacationTriggered := len(data.VacationResponses) > 0

	// Handle fileinto action (takes precedence over vacation)
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
		// Handle redirect action (takes precedence over vacation)
		// Use the first redirect address (we could support multiple redirects in the future)
		result.Action = ActionRedirect
		result.RedirectTo = data.RedirectAddr[0]

		// Check if ImplicitKeep is true (means :copy was used) OR if Keep is true (explicit keep action)
		// With normal redirect (no :copy), ImplicitKeep would be false, but an explicit keep
		// after redirect should still save a local copy
		result.Copy = data.ImplicitKeep || data.Keep
	} else if !data.Keep && !data.ImplicitKeep {
		// Handle discard action
		// This includes both explicit discard commands and scripts with no keep action
		result.Action = ActionDiscard
	} else if vacationTriggered {
		// Process vacation responses
		// Per RFC 5230, vacation is an implicit keep, so we only reach here if ImplicitKeep is still true
		// (fileinto/redirect/discard are handled above and cancel the implicit keep)
		// Get the first vacation response (there should only be one per evaluation)
		for sender, vacation := range data.VacationResponses {
			// Check with the policy/oracle if we should send this vacation response
			duration := time.Duration(vacation.Days) * 24 * time.Hour
			allowed, err := execPolicy.VacationResponseAllowed(evalCtx, data, sender, vacation.Handle, duration)
			if err != nil {
				// Log error but don't fail the message delivery
				continue
			}

			if allowed {
				result.Action = ActionVacation
				result.VacationFrom = vacation.From
				result.VacationSubj = vacation.Subject
				result.VacationMsg = vacation.Body
				result.VacationIsMime = vacation.IsMime

				// Record that we sent the vacation response
				_ = execPolicy.SendVacationResponse(evalCtx, data, sender, vacation.From, vacation.Subject, vacation.Body, vacation.IsMime)
			}
			break // Only process the first vacation response
		}
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

// ApplyHeaderEdits applies header modifications to raw message bytes (RFC 5293)
// Returns the modified message bytes with header edits applied
func ApplyHeaderEdits(messageBytes []byte, edits []HeaderEdit) ([]byte, error) {
	if len(edits) == 0 {
		return messageBytes, nil
	}

	// Find the header/body boundary
	headerEndIndex := bytes.Index(messageBytes, []byte("\r\n\r\n"))
	if headerEndIndex == -1 {
		// No clear boundary, treat entire message as headers
		headerEndIndex = len(messageBytes)
	}

	headerBytes := messageBytes[:headerEndIndex]
	bodyBytes := messageBytes[headerEndIndex:]

	// Parse headers into a map
	headers := parseHeaders(headerBytes)

	// Apply edits in order
	for _, edit := range edits {
		fieldNameLower := strings.ToLower(edit.FieldName)

		switch edit.Action {
		case "add":
			// Add header (at beginning or end based on Last flag)
			headerLine := edit.FieldName + ": " + edit.Value
			if edit.Last {
				headers[fieldNameLower] = append(headers[fieldNameLower], headerLine)
			} else {
				headers[fieldNameLower] = append([]string{headerLine}, headers[fieldNameLower]...)
			}

		case "delete":
			values := headers[fieldNameLower]
			if len(values) == 0 {
				continue
			}

			if edit.Index > 0 {
				// Delete specific index
				idx := edit.Index - 1
				if edit.Last {
					idx = len(values) - edit.Index
				}
				if idx >= 0 && idx < len(values) {
					headers[fieldNameLower] = append(values[:idx], values[idx+1:]...)
				}
			} else if edit.Value != "" {
				// Delete first matching value
				newValues := make([]string, 0, len(values))
				deleted := false
				for _, line := range values {
					// Extract value part after ": "
					colonIdx := strings.Index(line, ": ")
					if colonIdx == -1 {
						newValues = append(newValues, line)
						continue
					}
					lineValue := line[colonIdx+2:]
					if !deleted && lineValue == edit.Value {
						deleted = true
						continue
					}
					newValues = append(newValues, line)
				}
				headers[fieldNameLower] = newValues
			} else {
				// Delete all occurrences
				delete(headers, fieldNameLower)
			}
		}
	}

	// Reconstruct message
	var buf bytes.Buffer

	// Write headers in consistent order (preserving original order where possible)
	// Parse original header order
	originalOrder := extractHeaderOrder(headerBytes)
	written := make(map[string]bool)

	// Write headers in original order first
	for _, fieldName := range originalOrder {
		fieldNameLower := strings.ToLower(fieldName)
		if lines, ok := headers[fieldNameLower]; ok {
			for _, line := range lines {
				buf.WriteString(line)
				buf.WriteString("\r\n")
			}
			written[fieldNameLower] = true
		}
	}

	// Write any new headers that weren't in original
	for fieldNameLower, lines := range headers {
		if !written[fieldNameLower] {
			for _, line := range lines {
				buf.WriteString(line)
				buf.WriteString("\r\n")
			}
		}
	}

	// Write body
	buf.Write(bodyBytes)

	return buf.Bytes(), nil
}

// parseHeaders parses raw header bytes into a map[lowercase-name][]header-lines
func parseHeaders(headerBytes []byte) map[string][]string {
	headers := make(map[string][]string)
	lines := bytes.Split(headerBytes, []byte("\r\n"))

	var currentFieldName string
	var currentLine string

	for _, line := range lines {
		lineStr := string(line)

		// Check if this is a continuation line (starts with space or tab)
		if len(lineStr) > 0 && (lineStr[0] == ' ' || lineStr[0] == '\t') {
			if currentFieldName != "" {
				currentLine += "\r\n" + lineStr
			}
			continue
		}

		// Save previous header if any
		if currentFieldName != "" {
			fieldNameLower := strings.ToLower(currentFieldName)
			headers[fieldNameLower] = append(headers[fieldNameLower], currentLine)
		}

		// Parse new header
		colonIdx := strings.Index(lineStr, ":")
		if colonIdx == -1 {
			currentFieldName = ""
			currentLine = ""
			continue
		}

		currentFieldName = lineStr[:colonIdx]
		currentLine = lineStr
	}

	// Save last header
	if currentFieldName != "" {
		fieldNameLower := strings.ToLower(currentFieldName)
		headers[fieldNameLower] = append(headers[fieldNameLower], currentLine)
	}

	return headers
}

// extractHeaderOrder extracts the order of header field names from raw header bytes
func extractHeaderOrder(headerBytes []byte) []string {
	var order []string
	seen := make(map[string]bool)
	lines := bytes.Split(headerBytes, []byte("\r\n"))

	for _, line := range lines {
		lineStr := string(line)

		// Skip continuation lines
		if len(lineStr) > 0 && (lineStr[0] == ' ' || lineStr[0] == '\t') {
			continue
		}

		colonIdx := strings.Index(lineStr, ":")
		if colonIdx == -1 {
			continue
		}

		fieldName := lineStr[:colonIdx]
		if !seen[fieldName] {
			order = append(order, fieldName)
			seen[fieldName] = true
		}
	}

	return order
}
