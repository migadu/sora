package helpers

import (
	"strconv"
	"strings"
)

const (
	// DeliveredToHeader records the address a message was delivered to. It is the
	// standard (Postfix/qmail-style) mail-loop breaker: if a message about to be
	// delivered to an address already carries a Delivered-To for that address, it
	// has looped back to us and delivery is refused.
	DeliveredToHeader = "Delivered-To"

	// RedirectLoopHeader counts how many times Sora has redirected a message. It is
	// a backstop for loops that Delivered-To misses (chains that never repeat a local
	// recipient, or forwarders that strip Delivered-To).
	RedirectLoopHeader = "X-Sora-Loop"

	// DefaultMaxRedirectHops is the default cap on how many times one message may be
	// redirected by Sora before further redirects are suppressed (mail-loop backstop).
	// Configurable per server via [servers.*.limits] max_redirect_hops.
	DefaultMaxRedirectHops = 2
)

// HeaderGetter adapts a header map (e.g. go-message Header.Map()) into a
// case-insensitive accessor returning all values for a header name.
func HeaderGetter(m map[string][]string) func(string) []string {
	return func(name string) []string {
		for k, v := range m {
			if strings.EqualFold(k, name) {
				return v
			}
		}
		return nil
	}
}

// DeliveredToLoop reports whether the message already carries a Delivered-To
// header for addr (case-insensitive) — i.e. it has already been delivered to that
// recipient and has looped back.
func DeliveredToLoop(headerValues func(string) []string, addr string) bool {
	want := strings.ToLower(strings.TrimSpace(addr))
	if want == "" {
		return false
	}
	for _, v := range headerValues(DeliveredToHeader) {
		if strings.ToLower(strings.TrimSpace(v)) == want {
			return true
		}
	}
	return false
}

// RedirectHopCount returns how many times Sora has already redirected this
// message, read from the X-Sora-Loop header (0 if absent/unparseable). The highest
// value across (possibly multiple) headers is used, defensively.
func RedirectHopCount(headerValues func(string) []string) int {
	maxN := 0
	for _, v := range headerValues(RedirectLoopHeader) {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > maxN {
			maxN = n
		}
	}
	return maxN
}

// IsRedirectLoop reports whether the message is in a Sora redirect loop: it has been
// redirected by Sora at least once (the Sora-specific X-Sora-Loop marker is present)
// AND already carries a Delivered-To for this recipient. Gating on our own X-Sora-Loop
// marker avoids false-positives on legitimately forwarded inbound mail that an upstream
// stamped with Delivered-To:<recipient> but that Sora never redirected.
func IsRedirectLoop(headerValues func(string) []string, recipient string) bool {
	return RedirectHopCount(headerValues) > 0 && DeliveredToLoop(headerValues, recipient)
}

// PrependHeaderLine returns msg with a single "name: value\r\n" header line
// inserted at the very top of the header block (valid per RFC 5322 — order of
// distinct header fields is not significant, and Delivered-To/Received are
// conventionally prepended). CR/LF are stripped from name and value to prevent
// header injection from an untrusted caller.
func PrependHeaderLine(msg []byte, name, value string) []byte {
	name = stripCRLF(name)
	value = stripCRLF(value)
	line := []byte(name + ": " + value + "\r\n")
	out := make([]byte, 0, len(line)+len(msg))
	out = append(out, line...)
	out = append(out, msg...)
	return out
}

// stripCRLF removes CR and LF so a value cannot inject extra header lines.
func stripCRLF(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// ReceivedFrom formats the "from" clause of a Received header from a HELO/EHLO name and
// client IP. Either may be empty. Inputs are CRLF-stripped (a hostile HELO must not
// inject headers).
func ReceivedFrom(helo, ip string) string {
	helo, ip = stripCRLF(helo), stripCRLF(ip)
	switch {
	case helo != "" && ip != "":
		return helo + " ([" + ip + "])"
	case ip != "":
		return "[" + ip + "]"
	default:
		return helo
	}
}

// BuildReceivedHeader builds an RFC 5321 §4.4 "Received:" trace header (the final
// delivery hop, as an MDA/LMTP receiver such as Dovecot would add). All variable inputs
// are CRLF-stripped to prevent header injection; empty from/for/id clauses are omitted.
// The result is folded and has no trailing CRLF — prepend it with PrependRawHeader.
func BuildReceivedHeader(from, byHost, with, forAddr, id, date string) string {
	from, byHost, with = stripCRLF(from), stripCRLF(byHost), stripCRLF(with)
	forAddr, id, date = stripCRLF(forAddr), stripCRLF(id), stripCRLF(date)
	var b strings.Builder
	b.WriteString("Received: ")
	if from != "" {
		b.WriteString("from ")
		b.WriteString(from)
		b.WriteString("\r\n\t")
	}
	b.WriteString("by ")
	b.WriteString(byHost)
	b.WriteString(" with ")
	b.WriteString(with)
	if id != "" {
		b.WriteString(" id ")
		b.WriteString(id)
	}
	if forAddr != "" {
		b.WriteString("\r\n\tfor <")
		b.WriteString(forAddr)
		b.WriteString(">")
	}
	b.WriteString("; ")
	b.WriteString(date)
	return b.String()
}

// PrependRawHeader prepends a complete, already-formatted (and already-sanitized) header
// field — which may be folded across continuation lines — to the top of the header block.
func PrependRawHeader(msg []byte, header string) []byte {
	line := []byte(header + "\r\n")
	out := make([]byte, 0, len(line)+len(msg))
	out = append(out, line...)
	out = append(out, msg...)
	return out
}
