package server

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

// proxyV2Header builds a PROXY v2 header: signature, version/command byte,
// family/transport byte, the big-endian length and the address block.
func proxyV2Header(verCmd, famProto byte, block []byte) []byte {
	h := append([]byte{}, proxyV2Sig...)
	h = append(h, verCmd, famProto, byte(len(block)>>8), byte(len(block)))
	return append(h, block...)
}

var (
	// 192.0.2.1:51000 -> 192.0.2.10:143
	proxyV2IPv4Block = []byte{192, 0, 2, 1, 192, 0, 2, 10, 0xC7, 0x38, 0x00, 0x8F}
	// [2001:db8::1]:51000 -> [2001:db8::10]:143
	proxyV2IPv6Block = []byte{
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
		0xC7, 0x38, 0x00, 0x8F,
	}
)

// The lowest 4 bits of the 14th byte are the transport protocol. haproxy
// doc/proxy-protocol.txt section 2.2 defines UNSPEC (0x0), STREAM (0x1) and DGRAM
// (0x2); "other values are unspecified and must not be emitted in version 2 of
// this protocol and must be rejected as invalid by receivers".
func TestParseProxyV2RejectsInvalidTransport(t *testing.T) {
	r := &ProxyProtocolReader{}
	for _, tt := range []struct {
		name     string
		famProto byte
		block    []byte
	}{
		{"AF_INET transport 0x3", 0x13, proxyV2IPv4Block},
		{"AF_INET transport 0xF", 0x1F, proxyV2IPv4Block},
		{"AF_INET6 transport 0x3", 0x23, proxyV2IPv6Block},
		{"AF_INET6 transport 0xF", 0x2F, proxyV2IPv6Block},
		{"AF_UNSPEC transport 0x3", 0x03, nil},
		{"AF_UNSPEC transport 0xF", 0x0F, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := proxyV2Header(0x21, tt.famProto, tt.block)
			info, err := r.parseProxyV2(bufio.NewReader(bytes.NewReader(h)))
			if err == nil {
				t.Fatalf("family/transport 0x%02X accepted: %+v", tt.famProto, info)
			}
		})
	}
}

// For an UNSPEC transport (or family) "the receiver should ignore address
// information" (section 2.2): the session keeps the real connection's endpoints,
// as for LOCAL, so no source address may come out of the header. STREAM and
// DGRAM over AF_INET/AF_INET6 carry the addresses.
func TestParseProxyV2Accepts(t *testing.T) {
	r := &ProxyProtocolReader{}
	for _, tt := range []struct {
		name             string
		verCmd, famProto byte
		block            []byte
		command          string
		protocol         string
		src, dst         string
		srcPort, dstPort int
	}{
		{"AF_INET UNSPEC ignores addresses", 0x21, 0x10, proxyV2IPv4Block, "UNKNOWN", "UNKNOWN", "", "", 0, 0},
		{"AF_INET6 UNSPEC ignores addresses", 0x21, 0x20, proxyV2IPv6Block, "UNKNOWN", "UNKNOWN", "", "", 0, 0},
		{"AF_UNSPEC UNSPEC", 0x21, 0x00, nil, "UNKNOWN", "UNKNOWN", "", "", 0, 0},
		{"AF_UNSPEC STREAM ignores addresses", 0x21, 0x01, proxyV2IPv4Block, "UNKNOWN", "UNKNOWN", "", "", 0, 0},
		{"TCP over IPv4", 0x21, 0x11, proxyV2IPv4Block, "PROXY", "TCP4", "192.0.2.1", "192.0.2.10", 51000, 143},
		{"UDP over IPv4", 0x21, 0x12, proxyV2IPv4Block, "PROXY", "UDP4", "192.0.2.1", "192.0.2.10", 51000, 143},
		{"TCP over IPv6", 0x21, 0x21, proxyV2IPv6Block, "PROXY", "TCP6", "2001:db8::1", "2001:db8::10", 51000, 143},
		{"UDP over IPv6", 0x21, 0x22, proxyV2IPv6Block, "PROXY", "UDP6", "2001:db8::1", "2001:db8::10", 51000, 143},
		// LOCAL: "discard the protocol block including the family which is ignored".
		{"LOCAL ignores the family byte", 0x20, 0x1F, proxyV2IPv4Block, "LOCAL", "", "", "", 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := proxyV2Header(tt.verCmd, tt.famProto, tt.block)
			reader := bufio.NewReader(bytes.NewReader(append(h, "A1 CAPABILITY\r\n"...)))
			info, err := r.parseProxyV2(reader)
			if err != nil {
				t.Fatalf("family/transport 0x%02X rejected: %v", tt.famProto, err)
			}
			if info.Version != 2 || info.Command != tt.command || info.Protocol != tt.protocol ||
				info.SrcIP != tt.src || info.DstIP != tt.dst || info.SrcPort != tt.srcPort || info.DstPort != tt.dstPort {
				t.Errorf("family/transport 0x%02X parsed as %+v, want command %s protocol %q, %q:%d -> %q:%d",
					tt.famProto, info, tt.command, tt.protocol, tt.src, tt.srcPort, tt.dst, tt.dstPort)
			}
			// The header, and nothing after it, is consumed.
			if rest, _ := io.ReadAll(reader); string(rest) != "A1 CAPABILITY\r\n" {
				t.Errorf("after the header the connection reads %q", rest)
			}
		})
	}
}
