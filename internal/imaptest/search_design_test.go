package imaptest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
)

// searchDesignPeer supplies the documented search policy over the real client
// transport. It parses the messages that the actual case functions APPEND, so
// Subject and body expectations are exercised rather than copied from tables.
type searchDesignPeer struct {
	messages   []searchDesignMessage
	alter      func(string, []uint64) []uint64
	mu         sync.Mutex
	queries    []string
	keywordNIL bool
}

type searchDesignMessage struct {
	header mail.Header
	body   string
}

func searchDesignSession(t *testing.T, alter func(string, []uint64) []uint64) (*Session, *searchDesignPeer) {
	t.Helper()
	local, remote := net.Pipe()
	client := &Client{conn: local, reader: bufio.NewReader(local), ctx: context.Background(), cfg: Config{CommandTimeout: time.Second}}
	peer := &searchDesignPeer{alter: alter}
	done := make(chan error, 1)
	go func() {
		defer remote.Close()
		_ = remote.SetDeadline(time.Now().Add(15 * time.Second))
		done <- peer.serve(remote)
	}()
	t.Cleanup(func() {
		_ = client.Close()
		_ = remote.Close()
		if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("search design peer: %v", err)
		}
	})
	return &Session{Client: client, prefix: "sora-imaptest-design-", mailboxes: map[string]bool{}, cfg: Config{FTSTimeout: 100 * time.Millisecond}}, peer
}

func (p *searchDesignPeer) serve(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	for {
		tag, command, err := wireReadCommand(reader)
		if err != nil {
			return err
		}
		verb, arguments, _ := strings.Cut(command, " ")
		switch strings.ToUpper(verb) {
		case "CREATE":
		case "APPEND":
			marker := strings.LastIndexByte(command, '{')
			if marker < 0 || !strings.HasSuffix(command, "}") {
				return errors.New("APPEND did not use a literal")
			}
			size, err := strconv.Atoi(command[marker+1 : len(command)-1])
			if err != nil || size < 0 || size > 1<<20 {
				return errors.New("invalid APPEND literal length")
			}
			if _, err := io.WriteString(conn, "+ Send message\r\n"); err != nil {
				return err
			}
			data := make([]byte, size+2)
			if _, err := io.ReadFull(reader, data); err != nil {
				return err
			}
			if !bytes.HasSuffix(data, []byte("\r\n")) {
				return errors.New("APPEND omitted command terminator")
			}
			message, err := mail.ReadMessage(bytes.NewReader(data[:size]))
			if err != nil {
				return err
			}
			body, err := io.ReadAll(message.Body)
			if err != nil {
				return err
			}
			p.messages = append(p.messages, searchDesignMessage{header: message.Header, body: string(body)})
		case "SELECT":
			if _, err := fmt.Fprintf(conn, "* %d EXISTS\r\n", len(p.messages)); err != nil {
				return err
			}
			if _, err := io.WriteString(conn, "* OK [PERMANENTFLAGS (\\*)] keywords supported\r\n"); err != nil {
				return err
			}
		case "LIST":
		case "STORE":
			if !strings.EqualFold(arguments, "1 +FLAGS NIL") {
				return fmt.Errorf("unexpected fixture STORE: %s", arguments)
			}
			p.keywordNIL = true
		case "FETCH":
			if !strings.EqualFold(arguments, "1 FLAGS") {
				return fmt.Errorf("unexpected fixture FETCH: %s", arguments)
			}
			flags := ""
			if p.keywordNIL {
				flags = "NIL"
			}
			if _, err := fmt.Fprintf(conn, "* 1 FETCH (FLAGS (%s))\r\n", flags); err != nil {
				return err
			}
		case "SEARCH":
			p.mu.Lock()
			p.queries = append(p.queries, strings.ToLower(arguments))
			p.mu.Unlock()
			values, err := (&valueParser{data: []byte(arguments)}).sequence(0, 0)
			if err != nil {
				return err
			}
			var hits []uint64
			for i, message := range p.messages {
				match, err := searchDesignMatches(message, values)
				if err != nil {
					return err
				}
				if match {
					hits = append(hits, uint64(i+1))
				}
			}
			if p.alter != nil {
				hits = p.alter(strings.ToLower(arguments), hits)
			}
			var reply strings.Builder
			reply.WriteString("* SEARCH")
			for _, seq := range hits {
				fmt.Fprintf(&reply, " %d", seq)
			}
			reply.WriteString("\r\n")
			if _, err := io.WriteString(conn, reply.String()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected search-case command %q", verb)
		}
		if _, err := fmt.Fprintf(conn, "%s OK complete\r\n", tag); err != nil {
			return err
		}
	}
}

func searchDesignMatches(message searchDesignMessage, values []Value) (bool, error) {
	matched, rest, err := searchDesignPrefix(message, values)
	if err == nil && len(rest) != 0 {
		err = errors.New("unexpected trailing SEARCH criterion")
	}
	return matched, err
}

func searchDesignPrefix(message searchDesignMessage, values []Value) (bool, []Value, error) {
	if len(values) == 0 {
		return false, nil, errors.New("empty SEARCH criterion")
	}
	key := strings.ToUpper(values[0].Text)
	if key == "OR" {
		left, rest, err := searchDesignPrefix(message, values[1:])
		if err != nil {
			return false, nil, err
		}
		right, rest, err := searchDesignPrefix(message, rest)
		return left || right, rest, err
	}
	if key == "NOT" {
		match, rest, err := searchDesignPrefix(message, values[1:])
		return !match, rest, err
	}
	if key == "HEADER" {
		if len(values) < 3 {
			return false, nil, errors.New("invalid HEADER criterion")
		}
		if !strings.EqualFold(values[1].Text, "Subject") {
			return false, values[3:], nil // Arbitrary non-indexed headers are deliberately not searchable.
		}
		_, present := message.header[textproto.CanonicalMIMEHeaderKey(values[1].Text)]
		return present && strings.Contains(strings.ToLower(message.header.Get("Subject")), strings.ToLower(values[2].Text)), values[3:], nil
	}
	if len(values) < 2 {
		return false, nil, errors.New("invalid string SEARCH criterion")
	}
	term := strings.ToLower(values[1].Text)
	subject := strings.ToLower(message.header.Get("Subject"))
	switch key {
	case "SUBJECT":
		_, present := message.header["Subject"]
		return present && strings.Contains(subject, term), values[2:], nil
	case "BODY":
		return searchDesignWholeWord(message.body, term), values[2:], nil
	case "TEXT":
		return searchDesignWholeWord(message.body, term) || strings.Contains(subject, term), values[2:], nil
	default:
		return false, nil, fmt.Errorf("unexpected SEARCH criterion %q", key)
	}
}

func searchDesignWholeWord(body, term string) bool {
	// The fixtures use ASCII words, avoiding unrelated PostgreSQL tokenization
	// details while distinguishing complete words from interior substrings.
	words := strings.FieldsFunc(strings.ToLower(body), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	return slices.Contains(words, term)
}

func (p *searchDesignPeer) searched(criterion string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Contains(p.queries, strings.ToLower(criterion))
}

func TestSearchDesignCasesAcceptDocumentedSoraBehavior(t *testing.T) {
	for _, tc := range []struct {
		name     string
		run      func(*Session) error
		searched []string
	}{
		{"native-header", coreSearchArbitraryHeader, []string{`HEADER X-Sora-Conformance ""`, `NOT HEADER X-Sora-Conformance ""`}},
		{"native-body", coreSearchBody, []string{`BODY "BODYNEEDLE"`, `TEXT "bodyneedle"`}},
		{"upstream-header", portSearchHeader, []string{`SUBJECT "hello beautiful"`, `HEADER SUBJECT ""`, `HEADER X-Extra ""`, `NOT HEADER X-Extra ""`}},
		{"upstream-body", portSearchBody, []string{`TEXT asdfghjkl`, `BODY asdfghjkl`, `TEXT qwertyuiop`, `TEXT wertyuio`, `BODY wertyuio`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, peer := searchDesignSession(t, nil)
			if err := tc.run(session); err != nil {
				t.Fatal(err)
			}
			for _, criterion := range tc.searched {
				if !peer.searched(criterion) {
					t.Errorf("case omitted its %s check", criterion)
				}
			}
		})
	}
}

func TestSearchDesignRetainsSupportedPositiveChecks(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*Session) error
	}{
		{"subject", portSearchHeader},
		{"full-word-body", portSearchBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, _ := searchDesignSession(t, func(string, []uint64) []uint64 { return nil })
			var assertion *AssertionError
			if err := tc.run(session); !errors.As(err, &assertion) {
				t.Fatalf("missing supported matches must fail an assertion, got %v", err)
			}
		})
	}
}

func TestSearchDesignUnsupportedHeaderNegationStillMatches(t *testing.T) {
	for _, run := range []func(*Session) error{coreSearchArbitraryHeader, portSearchHeader} {
		session, _ := searchDesignSession(t, func(criterion string, result []uint64) []uint64 {
			if strings.HasPrefix(criterion, "not header x-") {
				return nil
			}
			return result
		})
		var assertion *AssertionError
		if err := run(session); !errors.As(err, &assertion) {
			t.Fatalf("incorrect NOT of an unsupported header must fail, got %v", err)
		}
	}
}

func TestSearchDesignRetainsIndexedSubjectSubstring(t *testing.T) {
	session, _ := searchDesignSession(t, func(criterion string, result []uint64) []uint64 {
		if criterion == "text wertyuio" {
			return nil
		}
		return result
	})
	var assertion *AssertionError
	if err := portSearchBody(session); !errors.As(err, &assertion) {
		t.Fatalf("missing indexed Subject substring match must fail, got %v", err)
	}
}

func TestSearchDesignRejectsUnintendedBodySubstringMatches(t *testing.T) {
	session, _ := searchDesignSession(t, func(criterion string, result []uint64) []uint64 {
		if criterion == `body "bodyneedle"` {
			return []uint64{1}
		}
		return result
	})
	var assertion *AssertionError
	if err := coreSearchBody(session); !errors.As(err, &assertion) {
		t.Fatalf("body substring match contradicting Sora's design must fail, got %v", err)
	}
}

func TestSearchBodyWaitsForAllFixtureMessagesBeforeAssertions(t *testing.T) {
	var probes atomic.Int32
	session, peer := searchDesignSession(t, func(criterion string, result []uint64) []uint64 {
		if strings.HasPrefix(criterion, "or body asdfghjkl ") && probes.Add(1) == 1 {
			return []uint64{1, 2}
		}
		return result
	})
	session.cfg.FTSTimeout = 7 * time.Second
	if err := portSearchBody(session); err != nil {
		t.Fatal(err)
	}
	if probes.Load() < 2 || !peer.searched("body qwertyuiop") || !peer.searched("text wertyuio") {
		t.Fatal("case did not wait for the entire fixture and then run its normal assertions")
	}
}

func TestSearchNilWaitsForIndexingAndRetainsKeywordChecks(t *testing.T) {
	var probes atomic.Int32
	session, peer := searchDesignSession(t, func(criterion string, result []uint64) []uint64 {
		if (criterion == "body nil" || criterion == `body "nil"`) && probes.Add(1) == 1 {
			return nil
		}
		return result
	})
	session.cfg.FTSTimeout = 7 * time.Second
	if err := portMIMENil(session); err != nil {
		t.Fatal(err)
	}
	if probes.Load() < 3 || !peer.searched("subject nil") {
		t.Fatal("NIL case did not wait and then repeat its positive assertion")
	}
}

func TestSearchNilReadinessDoesNotReplaceBodyAssertion(t *testing.T) {
	var probes atomic.Int32
	session, _ := searchDesignSession(t, func(criterion string, result []uint64) []uint64 {
		if (criterion == "body nil" || criterion == `body "nil"`) && probes.Add(1) > 1 {
			return nil
		}
		return result
	})
	var assertion *AssertionError
	if err := portMIMENil(session); !errors.As(err, &assertion) {
		t.Fatalf("body regression after readiness must fail: %v", err)
	}
}
