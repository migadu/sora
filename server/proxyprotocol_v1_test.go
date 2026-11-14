package server

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

// The PROXY v1 line must match the HAProxy PROXY protocol specification
// (doc/proxy-protocol.txt) section 2.1 exactly: protocol TCP4, TCP6 or UNKNOWN,
// addresses of the advertised family, decimal ports in [0..65535] without
// heading zeroes, CRLF within 107 characters. "Any sequence which does not
// exactly match the protocol must be discarded and cause the receiver to abort
// the connection." The source address becomes the session's client address
// (logs, per-IP limits, auth rate limiting, remote lookup), so it is stored in
// one canonical spelling.
func TestParseProxyV1Rejects(t *testing.T) {
	r := &ProxyProtocolReader{}
	for _, tt := range []struct {
		name, line string
	}{
		{"source not an IP", "PROXY TCP4 not-an-ip 192.0.2.10 51000 143\r\n"},
		{"destination not an IP", "PROXY TCP4 192.0.2.1 not-an-ip 51000 143\r\n"},
		{"IPv6 source under TCP4", "PROXY TCP4 2001:db8::1 192.0.2.10 51000 143\r\n"},
		{"IPv6 destination under TCP4", "PROXY TCP4 192.0.2.1 2001:db8::10 51000 143\r\n"},
		{"mapped IPv4 under TCP4", "PROXY TCP4 ::ffff:192.0.2.1 192.0.2.10 51000 143\r\n"},
		{"IPv4 source under TCP6", "PROXY TCP6 192.0.2.1 2001:db8::10 51000 143\r\n"},
		{"IPv4 destination under TCP6", "PROXY TCP6 2001:db8::1 192.0.2.10 51000 143\r\n"},
		{"IPv6 zone", "PROXY TCP6 fe80::1%eth0 2001:db8::10 51000 143\r\n"},
		{"IPv4 octet with heading zero", "PROXY TCP4 192.0.2.01 192.0.2.10 51000 143\r\n"},
		{"IPv4 with three octets", "PROXY TCP4 192.0.2 192.0.2.10 51000 143\r\n"},
		{"unknown protocol", "PROXY FOO 192.0.2.1 192.0.2.10 51000 143\r\n"},
		{"UDP4 protocol", "PROXY UDP4 192.0.2.1 192.0.2.10 51000 143\r\n"},
		{"lower-case protocol", "PROXY tcp4 192.0.2.1 192.0.2.10 51000 143\r\n"},
		{"negative source port", "PROXY TCP4 192.0.2.1 192.0.2.10 -1 143\r\n"},
		{"destination port above 65535", "PROXY TCP4 192.0.2.1 192.0.2.10 51000 99999\r\n"},
		{"port 65536", "PROXY TCP4 192.0.2.1 192.0.2.10 65536 143\r\n"},
		{"signed port", "PROXY TCP4 192.0.2.1 192.0.2.10 +51000 143\r\n"},
		{"port with heading zero", "PROXY TCP4 192.0.2.1 192.0.2.10 51000 0143\r\n"},
		{"port of zeroes", "PROXY TCP4 192.0.2.1 192.0.2.10 00 143\r\n"},
		{"two spaces", "PROXY TCP4  192.0.2.1 192.0.2.10 51000 143\r\n"},
		{"missing field", "PROXY TCP4 192.0.2.1 192.0.2.10 51000\r\n"},
		{"extra field", "PROXY TCP4 192.0.2.1 192.0.2.10 51000 143 x\r\n"},
		{"bare LF", "PROXY TCP4 192.0.2.1 192.0.2.10 51000 143\n"},
		{"CR before CRLF", "PROXY TCP4 192.0.2.1 192.0.2.10 51000 143\r\r\n"},
		{"no CRLF", "PROXY TCP4 192.0.2.1 192.0.2.10 51000 143"},
		{"no protocol", "PROXY\r\n"},
		{"longer than 107 characters", "PROXY UNKNOWN " + strings.Repeat("a", 60) + " " + strings.Repeat("b", 60) + " 1 2\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			info, err := r.parseProxyV1(bufio.NewReader(strings.NewReader(tt.line)))
			if err == nil {
				t.Fatalf("%q accepted: %+v", tt.line, info)
			}
		})
	}
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// A line is invalid once it runs past 107 characters without a CRLF, so a peer
// that keeps sending must not make the parser buffer whatever arrives before the
// PROXY timeout: the read stops at the bufio.Reader's buffer.
func TestParseProxyV1ReadIsBounded(t *testing.T) {
	src := &countingReader{r: io.MultiReader(
		strings.NewReader("PROXY TCP4 "),
		strings.NewReader(strings.Repeat("1", 1<<20)),
		strings.NewReader("\r\n"),
	)}
	reader := bufio.NewReader(src)
	if info, err := (&ProxyProtocolReader{}).parseProxyV1(reader); err == nil {
		t.Fatalf("a 1 MiB line was accepted: %+v", info)
	}
	if src.n > reader.Size() {
		t.Errorf("the parser read %d bytes of the line, want at most its %d-byte buffer", src.n, reader.Size())
	}
}

func TestParseProxyV1Accepts(t *testing.T) {
	r := &ProxyProtocolReader{}
	ffff := "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	for _, tt := range []struct {
		name, line         string
		protocol, src, dst string
		srcPort, dstPort   int
	}{
		{"TCP4", "PROXY TCP4 192.0.2.1 192.0.2.10 51000 143\r\n", "TCP4", "192.0.2.1", "192.0.2.10", 51000, 143},
		{"TCP4 longest", "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n", "TCP4", "255.255.255.255", "255.255.255.255", 65535, 65535},
		{"TCP4 zeroes", "PROXY TCP4 0.0.0.0 0.0.0.0 0 0\r\n", "TCP4", "0.0.0.0", "0.0.0.0", 0, 0},
		{"TCP6", "PROXY TCP6 2001:db8::1 2001:db8::10 51000 143\r\n", "TCP6", "2001:db8::1", "2001:db8::10", 51000, 143},
		{"TCP6 canonicalised", "PROXY TCP6 2001:0DB8:0000::0001 2001:DB8::A 51000 143\r\n", "TCP6", "2001:db8::1", "2001:db8::a", 51000, 143},
		// HAProxy sends TCP6 with the IPv4 side mapped when the two sides differ in family.
		{"TCP6 mapped IPv4 source", "PROXY TCP6 ::ffff:192.0.2.1 2001:db8::10 51000 143\r\n", "TCP6", "192.0.2.1", "2001:db8::10", 51000, 143},
		{"TCP6 longest", "PROXY TCP6 " + ffff + " " + ffff + " 65535 65535\r\n", "TCP6", ffff, ffff, 65535, 65535},
		// Section 2.1: for UNKNOWN "the rest of the line before the CRLF may be omitted
		// by the sender, and the receiver must ignore anything presented before the CRLF".
		{"UNKNOWN short form", "PROXY UNKNOWN\r\n", "UNKNOWN", "", "", 0, 0},
		{"UNKNOWN with ignored fields", "PROXY UNKNOWN 192.0.2.1 192.0.2.10 51000 143\r\n", "UNKNOWN", "", "", 0, 0},
		{"UNKNOWN worst case (107 characters)", "PROXY UNKNOWN " + ffff + " " + ffff + " 65535 65535\r\n", "UNKNOWN", "", "", 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.line + "A1 CAPABILITY\r\n"))
			info, err := r.parseProxyV1(reader)
			if err != nil {
				t.Fatalf("%q rejected: %v", tt.line, err)
			}
			if info.Version != 1 || info.Protocol != tt.protocol || info.SrcIP != tt.src || info.DstIP != tt.dst ||
				info.SrcPort != tt.srcPort || info.DstPort != tt.dstPort {
				t.Errorf("%q parsed as %+v, want protocol %s, %s:%d -> %s:%d",
					tt.line, info, tt.protocol, tt.src, tt.srcPort, tt.dst, tt.dstPort)
			}
			// The header, and nothing after it, is consumed.
			if rest, _ := io.ReadAll(reader); string(rest) != "A1 CAPABILITY\r\n" {
				t.Errorf("after the header the connection reads %q", rest)
			}
		})
	}
}
