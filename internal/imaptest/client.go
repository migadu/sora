package imaptest

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client is a single IMAP session. Commands on one client are serialized; use
// distinct clients for multi-connection tests and Pipeline for command batches.
type Client struct {
	Capabilities map[string]bool
	conn         net.Conn
	reader       *bufio.Reader
	ctx          context.Context
	cfg          Config
	tag          uint64
	mu           sync.Mutex
	stop         func() bool
	traceID      uint64
}

var nextTraceID atomic.Uint64

// Quote serializes an IMAP quoted string. Callers constructing commands must
// keep CR, LF, and NUL out of string arguments; Command rejects them as well.
func Quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func validString(s string) bool { return !strings.ContainsAny(s, "\r\n\x00") }

// Dial establishes the selected TLS transport, authenticates, and refreshes
// capabilities after authentication. It deliberately does not ENABLE IMAP4rev2.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	return dial(ctx, cfg, true)
}

// DialUnauthenticated leaves the connection in its greeting state for tests of
// commands that must also work before authentication, including ID and LOGOUT.
func DialUnauthenticated(ctx context.Context, cfg Config) (*Client, error) {
	return dial(ctx, cfg, false)
}

func dial(ctx context.Context, cfg Config, authenticate bool) (*Client, error) {
	if !validString(cfg.Username) || !validString(cfg.Password) {
		return nil, errors.New("username and password must not contain CR, LF, or NUL")
	}
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 30 * time.Second
	}
	if cfg.TLSMode == "" {
		cfg.TLSMode = "implicit"
	}
	if cfg.TLSMode != "implicit" && cfg.TLSMode != "starttls" && cfg.TLSMode != "none" {
		return nil, errors.New("TLS mode must be implicit, starttls, or none")
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, errors.New("IMAP address must contain host and port")
	}
	var tlsConfig *tls.Config
	if cfg.TLSMode != "none" {
		tlsConfig, err = clientTLSConfig(cfg, host)
		if err != nil {
			return nil, err
		}
	}
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("connect to IMAP endpoint: %w", err)
	}
	c := &Client{conn: raw, ctx: ctx, cfg: cfg, Capabilities: make(map[string]bool), traceID: nextTraceID.Add(1)}
	c.stop = context.AfterFunc(ctx, func() { _ = raw.Close() })
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	if err := c.deadline(); err != nil {
		return nil, err
	}
	if cfg.TLSMode == "implicit" {
		secured := tls.Client(raw, tlsConfig)
		if err := secured.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("IMAP TLS handshake: %w", err)
		}
		c.conn = secured
	}
	c.reader = bufio.NewReader(c.conn)
	tag, greeting, err := c.read(false)
	if err != nil {
		return nil, fmt.Errorf("read IMAP greeting: %w", err)
	}
	if tag != "*" || (greeting.Status != "OK" && greeting.Status != "PREAUTH") {
		return nil, errors.New("IMAP server did not greet with untagged OK or PREAUTH")
	}
	preauth := greeting.Status == "PREAUTH"
	if cfg.TLSMode == "starttls" {
		if preauth {
			return nil, errors.New("cannot STARTTLS after a PREAUTH greeting")
		}
		if err := c.refreshCapabilities(); err != nil {
			return nil, err
		}
		if !c.Capabilities["STARTTLS"] {
			return nil, errors.New("IMAP endpoint does not advertise STARTTLS")
		}
		if _, err := c.OK("STARTTLS"); err != nil {
			return nil, fmt.Errorf("IMAP STARTTLS: %w", err)
		}
		if c.reader.Buffered() != 0 {
			return nil, errors.New("unexpected cleartext data after STARTTLS completion")
		}
		if err := c.deadline(); err != nil {
			return nil, err
		}
		secured := tls.Client(raw, tlsConfig)
		if err := secured.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("IMAP STARTTLS handshake: %w", err)
		}
		c.conn = secured
		c.reader = bufio.NewReader(secured)
		c.Capabilities = make(map[string]bool)
	}
	if err := c.refreshCapabilities(); err != nil {
		return nil, err
	}
	if !preauth && authenticate {
		if c.Capabilities["LOGINDISABLED"] {
			return nil, errors.New("IMAP endpoint advertises LOGINDISABLED for this transport")
		}
		response, err := c.Command("LOGIN " + Quote(cfg.Username) + " " + Quote(cfg.Password))
		if err != nil {
			return nil, fmt.Errorf("IMAP authentication: %w", err)
		}
		if response.Status != "OK" {
			code := ""
			if len(response.Completion.code) > 0 {
				candidate := strings.ToUpper(response.Completion.code[0].Text)
				switch candidate {
				case "AUTHENTICATIONFAILED", "AUTHORIZATIONFAILED", "UNAVAILABLE", "PRIVACYREQUIRED", "EXPIRED", "INUSE", "CONTACTADMIN", "LIMIT", "SERVERBUG", "CLIENTBUG", "CANNOT":
					code = " [" + candidate + "]"
				}
			}
			return nil, fmt.Errorf("IMAP LOGIN rejected with %s%s", response.Status, code)
		}
		if err := c.refreshCapabilities(); err != nil {
			return nil, err
		}
	}
	ok = true
	return c, nil
}

func clientTLSConfig(cfg Config, host string) (*tls.Config, error) {
	name := cfg.ServerName
	if name == "" {
		name = host
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, InsecureSkipVerify: cfg.Insecure} // #nosec G402 -- explicit test CLI option
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read IMAP CA file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("IMAP CA file contains no usable certificates")
		}
		tlsConfig.RootCAs = roots
	}
	return tlsConfig, nil
}

func (c *Client) refreshCapabilities() error {
	response, err := c.OK("CAPABILITY")
	if err != nil {
		return fmt.Errorf("discover IMAP capabilities: %w", err)
	}
	caps := make(map[string]bool)
	for _, reply := range response.Data("CAPABILITY") {
		for _, value := range reply.Values[1:] {
			if value.IsList || value.IsNil || value.Text == "" {
				return errors.New("malformed CAPABILITY response")
			}
			caps[strings.ToUpper(value.Text)] = true
		}
	}
	for _, value := range response.Code("CAPABILITY") {
		caps[strings.ToUpper(value.Text)] = true
	}
	if len(caps) == 0 {
		return errors.New("CAPABILITY returned no capabilities")
	}
	c.Capabilities = caps
	return nil
}

func (c *Client) deadline() error {
	return c.commandDeadline(c.ctx)
}

// A socket deadline can fire just before context's timer goroutine publishes
// Err. Honor the actual deadline in that small scheduling window too.
func contextStateError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *Client) commandDeadline(ctx context.Context) error {
	end := time.Now().Add(c.cfg.CommandTimeout)
	for _, current := range []context.Context{c.ctx, ctx} {
		if current == nil {
			continue
		}
		if err := contextStateError(current); err != nil {
			return err
		}
		if d, ok := current.Deadline(); ok && d.Before(end) {
			end = d
		}
	}
	return c.conn.SetDeadline(end)
}

func (c *Client) safe(s string) string {
	quotedPassword := Quote(c.cfg.Password)
	for _, secret := range []string{
		c.cfg.Password,
		quotedPassword[1 : len(quotedPassword)-1],
		base64.StdEncoding.EncodeToString([]byte("\x00" + c.cfg.Username + "\x00" + c.cfg.Password)),
		base64.StdEncoding.EncodeToString([]byte(c.cfg.Username + "\x00" + c.cfg.Username + "\x00" + c.cfg.Password)),
	} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	return s
}

func traceValue(value Value) string {
	if value.IsLiteral {
		return fmt.Sprintf("<%d literal bytes>", len(value.Text))
	}
	if value.IsList {
		parts := make([]string, len(value.List))
		for i, child := range value.List {
			parts[i] = traceValue(child)
		}
		return "(" + strings.Join(parts, " ") + ")"
	}
	return value.String()
}

func (c *Client) trace(direction, message string) {
	if c.cfg.Trace != nil {
		_, _ = fmt.Fprintf(c.cfg.Trace, "[%04d] %s: %s\n", c.traceID, direction, c.safe(message))
	}
}

func (c *Client) read(sensitive bool) (string, Reply, error) {
	tag, reply, err := readReply(c.reader)
	if err != nil {
		if contextErr := contextStateError(c.ctx); contextErr != nil {
			return "", Reply{}, contextErr
		}
		return "", Reply{}, err
	}
	reply.Text = c.safe(reply.Text)
	if !sensitive {
		parts := []string{tag}
		for _, value := range reply.Values {
			parts = append(parts, traceValue(value))
		}
		if reply.Text != "" {
			parts = append(parts, reply.Text)
		}
		c.trace("S", strings.Join(parts, " "))
	}
	return tag, reply, nil
}

func sensitiveCommand(command string) bool {
	words := strings.Fields(command)
	return len(words) > 0 && (strings.EqualFold(words[0], "LOGIN") || strings.EqualFold(words[0], "AUTHENTICATE"))
}

func (c *Client) write(data []byte) error {
	for len(data) > 0 {
		n, err := c.conn.Write(data)
		if err != nil {
			if contextErr := contextStateError(c.ctx); contextErr != nil {
				return contextErr
			}
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (c *Client) nextTag() string {
	c.tag++
	return fmt.Sprintf("S%06d", c.tag)
}

// Command returns the server's tagged status unchanged, allowing negative tests.
func (c *Client) Command(command string) (Response, error) {
	return c.CommandContext(c.ctx, command)
}

// CommandContext additionally bounds a command by a caller's shorter deadline.
// Canceling that context interrupts current I/O without closing a healthy
// connection after the command has completed.
func (c *Client) CommandContext(ctx context.Context, command string) (response Response, commandErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if !validString(command) || strings.TrimSpace(command) == "" {
		return Response{}, errors.New("IMAP command must be one nonempty line without NUL")
	}
	if err := c.commandDeadline(ctx); err != nil {
		return Response{}, err
	}
	interrupted := make(chan struct{})
	stopInterrupt := context.AfterFunc(ctx, func() {
		_ = c.conn.SetDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		// A callback already running must finish before the next command can
		// install its deadline. Holding mu until then avoids a late interrupt.
		if !stopInterrupt() {
			<-interrupted
		}
		if err := contextStateError(ctx); err != nil {
			response, commandErr = Response{}, err
		}
	}()
	tag := c.nextTag()
	sensitive := sensitiveCommand(command)
	if !sensitive {
		c.trace("C", tag+" "+command)
	}
	if err := c.write([]byte(tag + " " + command + "\r\n")); err != nil {
		return Response{}, err
	}
	return c.completion(tag, nil, sensitive, strings.EqualFold(strings.TrimSpace(command), "LOGOUT"))
}

func (c *Client) completion(tag string, untagged []Reply, sensitive, logout bool) (Response, error) {
	size := 0
	for _, reply := range untagged {
		size += reply.size
	}
	for {
		replyTag, reply, err := c.read(sensitive)
		if err != nil {
			return Response{}, err
		}
		size += reply.size
		if size > maxResponseBytes {
			return Response{}, errors.New("IMAP command response exceeds size limit")
		}
		switch replyTag {
		case "*":
			untagged = append(untagged, reply)
			if reply.Status == "BYE" && !logout {
				return Response{}, errors.New("IMAP server closed the session with BYE")
			}
		case "+":
			return Response{}, errors.New("unexpected IMAP continuation")
		case tag:
			if reply.Status != "OK" && reply.Status != "NO" && reply.Status != "BAD" {
				return Response{}, errors.New("invalid IMAP command completion status")
			}
			return Response{Tag: tag, Status: reply.Status, Text: reply.Text, Untagged: untagged, Completion: reply}, nil
		default:
			return Response{}, errors.New("IMAP completion has an unexpected command tag")
		}
	}
}

// OK is Command with a required OK completion.
func (c *Client) OK(command string) (Response, error) {
	response, err := c.Command(command)
	if err != nil {
		return response, err
	}
	if response.Status != "OK" {
		verb, _, _ := strings.Cut(strings.TrimSpace(command), " ")
		return response, &AssertionError{Message: fmt.Sprintf("%s returned %s: %s", strings.ToUpper(verb), response.Status, response.Text)}
	}
	return response, nil
}

// Append uses a synchronizing literal and requires a successful completion.
func (c *Client) Append(mailbox string, flags []string, internalDate string, data []byte) (Response, error) {
	return c.append(mailbox, flags, internalDate, data, false, false)
}

// AppendBinary sends RFC 3516 literal8 data without treating NUL as a terminator.
func (c *Client) AppendBinary(mailbox string, flags []string, internalDate string, data []byte) (Response, error) {
	if !c.Capabilities["BINARY"] {
		return Response{}, errors.New("binary APPEND requires BINARY")
	}
	return c.append(mailbox, flags, internalDate, data, false, true)
}

// AppendNonSync tests LITERAL+ (or the size-limited LITERAL- form).
func (c *Client) AppendNonSync(mailbox string, flags []string, internalDate string, data []byte) (Response, error) {
	if !c.Capabilities["LITERAL+"] && !(c.Capabilities["LITERAL-"] && len(data) <= 4096) {
		return Response{}, errors.New("non-synchronizing APPEND requires LITERAL+ or LITERAL- within 4096 bytes")
	}
	return c.append(mailbox, flags, internalDate, data, true, false)
}

func (c *Client) append(mailbox string, flags []string, internalDate string, data []byte, nonSync, binary bool) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !validString(mailbox) || !validString(internalDate) {
		return Response{}, errors.New("APPEND arguments must not contain CR, LF, or NUL")
	}
	command := "APPEND " + Quote(mailbox)
	if len(flags) > 0 {
		for _, flag := range flags {
			if flag == "" || strings.ContainsAny(flag, " \t\r\n\x00(){}\"") {
				return Response{}, errors.New("invalid APPEND flag")
			}
		}
		command += " (" + strings.Join(flags, " ") + ")"
	}
	if internalDate != "" {
		command += " " + Quote(internalDate)
	}
	marker := fmt.Sprintf("{%d}", len(data))
	if nonSync {
		marker = fmt.Sprintf("{%d+}", len(data))
	}
	if binary {
		marker = "~" + marker
	}
	if err := c.deadline(); err != nil {
		return Response{}, err
	}
	tag := c.nextTag()
	c.trace("C", tag+" "+command+" "+marker)
	if err := c.write([]byte(tag + " " + command + " " + marker + "\r\n")); err != nil {
		return Response{}, err
	}
	var untagged []Reply
	if !nonSync {
		size := 0
		for {
			replyTag, reply, err := c.read(false)
			if err != nil {
				return Response{}, err
			}
			size += reply.size
			if size > maxResponseBytes {
				return Response{}, errors.New("IMAP APPEND response exceeds size limit")
			}
			if replyTag == "+" {
				break
			}
			if replyTag == "*" {
				if reply.Status == "BYE" {
					return Response{}, errors.New("IMAP server closed the session with BYE")
				}
				untagged = append(untagged, reply)
				continue
			}
			if replyTag == tag && (reply.Status == "NO" || reply.Status == "BAD") {
				response := Response{Tag: tag, Status: reply.Status, Text: reply.Text, Untagged: untagged, Completion: reply}
				return response, &AssertionError{Message: fmt.Sprintf("APPEND returned %s: %s", reply.Status, reply.Text)}
			}
			return Response{}, errors.New("expected APPEND continuation or refusal")
		}
	}
	c.trace("C", fmt.Sprintf("<%d literal bytes>", len(data)))
	if err := c.write(data); err != nil {
		return Response{}, err
	}
	if err := c.write([]byte("\r\n")); err != nil {
		return Response{}, err
	}
	response, err := c.completion(tag, untagged, false, false)
	if err == nil && response.Status != "OK" {
		err = &AssertionError{Message: fmt.Sprintf("APPEND returned %s: %s", response.Status, response.Text)}
	}
	return response, err
}

// Pipeline returns completions in command order, regardless of arrival order.
// Untagged replies belong to the entire pipeline group and are attached to every
// result; their attribution to individual commands is not encoded by IMAP.
func (c *Client) Pipeline(commands ...string) ([]Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(commands) == 0 {
		return nil, errors.New("empty IMAP pipeline")
	}
	for _, command := range commands {
		if !validString(command) || strings.TrimSpace(command) == "" || sensitiveCommand(command) {
			return nil, errors.New("pipeline requires nonempty single-line commands without authentication")
		}
	}
	if err := c.deadline(); err != nil {
		return nil, err
	}
	responses := make([]Response, len(commands))
	pending := make(map[string]int, len(commands))
	var batch strings.Builder
	for i, command := range commands {
		tag := c.nextTag()
		responses[i].Tag = tag
		pending[tag] = i
		batch.WriteString(tag + " " + command + "\r\n")
		c.trace("C", tag+" "+command)
	}
	if err := c.write([]byte(batch.String())); err != nil {
		return nil, err
	}
	var untagged []Reply
	size := 0
	for len(pending) > 0 {
		tag, reply, err := c.read(false)
		if err != nil {
			return nil, err
		}
		size += reply.size
		if size > maxResponseBytes {
			return nil, errors.New("IMAP pipeline response exceeds size limit")
		}
		if tag == "*" {
			if reply.Status == "BYE" {
				return nil, errors.New("IMAP server closed the session with BYE")
			}
			untagged = append(untagged, reply)
			continue
		}
		i, ok := pending[tag]
		if !ok || (reply.Status != "OK" && reply.Status != "NO" && reply.Status != "BAD") {
			return nil, errors.New("unexpected IMAP pipeline completion or continuation")
		}
		responses[i].Status = reply.Status
		responses[i].Text = reply.Text
		responses[i].Completion = reply
		delete(pending, tag)
	}
	for i := range responses {
		responses[i].Untagged = untagged
	}
	return responses, nil
}

// Close tears down the transport immediately; it does not issue LOGOUT.
func (c *Client) Close() error {
	if c.stop != nil {
		c.stop()
	}
	return c.conn.Close()
}
