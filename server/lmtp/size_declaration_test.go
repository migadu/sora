package lmtp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// RFC 1870 section 3 defines the SIZE parameter of MAIL as "size-value ::= 1*20DIGIT",
// and section 6.1 (2) answers a declaration above the fixed maximum with 552. A declared
// size of 4 GiB or more must be compared with the limit LHLO advertises, never refused as
// a syntax error, as go-smtp did when it parsed the value as a 32-bit number (#471).
func TestMailSizeDeclarationBeyond32Bits(t *testing.T) {
	const declared = 5000000000 // above 2^32
	for _, tc := range []struct {
		name           string
		maxMessageSize int64
	}{
		{"default limit", DefaultMaxMessageSize},
		{"limit beyond 32 bits", 8 << 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := startSizeTestBackend(t, tc.maxMessageSize)
			conn := dialUntilListening(t, addr)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(conn)

			if line := readReplyLine(t, r); !strings.HasPrefix(line, "220 ") {
				t.Fatalf("greeting %q, want 220", line)
			}
			io.WriteString(conn, "LHLO client.example.org\r\n")
			var sizeCap string // the SIZE keyword as LHLO advertises it
			var limit int64    // its fixed maximum; 0 when none is in force or none is given
			for {
				line := readReplyLine(t, r)
				if len(line) < 4 || !strings.HasPrefix(line, "250") {
					t.Fatalf("LHLO reply line %q, want 250", line)
				}
				if kw := line[4:]; kw == "SIZE" || strings.HasPrefix(kw, "SIZE ") {
					sizeCap = kw
					if v, ok := strings.CutPrefix(kw, "SIZE "); ok {
						n, err := strconv.ParseInt(v, 10, 64)
						if err != nil {
							t.Fatalf("LHLO advertises %q: %v", kw, err)
						}
						limit = n
					}
				}
				if line[3] == ' ' {
					break
				}
			}

			want := "250 "
			if limit > 0 && declared > limit {
				want = "552 5.3.4 "
			}
			fmt.Fprintf(conn, "MAIL FROM:<sender@example.org> SIZE=%d\r\n", declared)
			if got := readReplyLine(t, r); !strings.HasPrefix(got, want) {
				t.Fatalf("MAIL SIZE=%d after LHLO advertised %q: %q, want %q", declared, sizeCap, got, want)
			}
		})
	}
}

// startSizeTestBackend starts an LMTP backend (no database) that trusts the loopback
// peer and has the given maximum message size, and returns its address.
func startSizeTestBackend(t *testing.T, maxMessageSize int64) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	b, err := New(ctx, "size-test", "localhost", addr, nil, nil, nil, LMTPServerOptions{
		TrustedNetworks: []string{"127.0.0.0/8"},
		MaxMessageSize:  maxMessageSize,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go b.Start(make(chan error, 1))
	t.Cleanup(func() { b.Close() })
	return addr
}
