package server

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// atextClass is the body of a character class matching one atext character of a
// dot-string local part. It is the full ASCII set of RFC 5322 §3.2.3:
//
//	"!" "#" "$" "%" "&" "'" "*" "+" "-" "/" "=" "?" "^" "_" "`" "{" "|" "}" "~"
//
// plus ALPHA and DIGIT — in particular "/" and "`" (\x60) must be allowed: many ESPs use
// base64/VERP-style reverse-paths (e.g. Constant Contact) whose local part contains "/",
// and rejecting them bounces legitimate mail — extended with UTF8-non-ascii as RFC 6531
// §3.3 does (SMTPUTF8): every non-ASCII code point is atext, while the ASCII graphics and
// controls RFC 5321 excludes stay excluded. NewAddress rejects malformed UTF-8 before the
// regex runs; Go's regexp would otherwise match the replacement rune for each bad byte.
const atextClass = `a-z0-9!#$%&'*+/=?^_\x60\{\|\}~\x{80}-\x{10FFFF}-`

// LocalPartRegex is the RFC 5321 Dot-string with the RFC 6531 atext extension.
const LocalPartRegex = `^(?i)(?:[` + atextClass + `])+(?:\.(?:[` + atextClass + `])+)*$`
const DomainNameRegex = `^(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`

// Precompiled once at package init — NewAddress is on the hot path for every
// LMTP MAIL/RCPT, so avoid recompiling the regexes on each call.
var (
	localPartRe  = regexp.MustCompile(LocalPartRegex)
	domainNameRe = regexp.MustCompile(DomainNameRegex)
)

// Length limits for email addresses
// Note: RFC 5321 specifies 64 for local part, but SRS (Sender Rewriting Scheme)
// and other address rewriting mechanisms routinely produce longer local parts.
// We use 256 to accommodate these real-world addresses while still providing a bound.
const (
	MaxLocalPartLength = 256 // Maximum length for local part (before @)
	MaxDomainLength    = 255 // Maximum length for domain part (after @)
	MaxAddressLength   = 512 // Maximum total length (256 + 1 + 255)
)

// Separator constant for master authentication
const (
	// SuffixSeparator is used for master username and remotelookup tokens
	// Format: user@domain@SUFFIX (where SUFFIX can be master username or remotelookup token)
	// Used by both backends and proxies:
	// - If SUFFIX matches configured master username: validated locally
	// - Otherwise: treated as remotelookup token and sent to remotelookup service
	SuffixSeparator = "@"
)

type Address struct {
	fullAddress string
	localPart   string
	domain      string
	detail      string
	suffix      string // Suffix after second @ (can be master username or remotelookup token): user@domain.com@SUFFIX
}

func (a Address) FullAddress() string {
	return a.fullAddress
}

func (a Address) LocalPart() string {
	return a.localPart
}

func (a Address) Domain() string {
	return a.domain
}

func (a Address) Detail() string {
	return a.detail
}

// BaseLocalPart returns the local part without the detail (everything before the "+")
func (a Address) BaseLocalPart() string {
	if plusIndex := strings.Index(a.localPart, "+"); plusIndex != -1 {
		return a.localPart[:plusIndex]
	}
	return a.localPart
}

// BaseAddress returns the address without the detail part (e.g., "user@domain.com" from "user+detail@domain.com")
func (a Address) BaseAddress() string {
	return a.BaseLocalPart() + "@" + a.domain
}

// MasterAddress returns the base address with suffix (without +detail)
// The suffix can be a master username or remotelookup token
// Examples:
//   - "user+tag@domain.com@TOKEN" -> "user@domain.com@TOKEN"
//   - "user+tag@domain.com" -> "user@domain.com"
//   - "user@domain.com@TOKEN" -> "user@domain.com@TOKEN"
func (a Address) MasterAddress() string {
	baseAddr := a.BaseAddress()
	if a.suffix != "" {
		return baseAddr + "@" + a.suffix
	}
	return baseAddr
}

// Suffix returns the suffix after the second @ if present (from syntax like user@domain.com@SUFFIX)
// The suffix can be either a master username or a remotelookup token depending on context
func (a Address) Suffix() string {
	return a.suffix
}

// HasSuffix returns true if the address contains a suffix after the second @
func (a Address) HasSuffix() bool {
	return a.suffix != ""
}

// ParseAddressWithMasterToken parses an email address that may contain a suffix using @ separator
// The suffix uses the syntax: user@domain.com@SUFFIX
// The SUFFIX can be:
// - A master username (for master password authentication) - validated locally if it matches config
// - A remotelookup token (for HTTP remotelookup authentication) - sent to remotelookup if it doesn't match
// Returns the parsed Address with proper validation, stripping +detail for authentication
func ParseAddressWithMasterToken(input string) (Address, error) {
	return NewAddress(input)
}

// NewAddress is an alias for ParseAddressWithMasterToken for backward compatibility.
// Every error it returns matches ErrInvalidAddress.
func NewAddress(input string) (Address, error) {
	addr, err := parseAddress(input)
	if err != nil {
		return Address{}, addressError{err}
	}
	return addr, nil
}

// addressError is a NewAddress failure. Its text is the reason alone, and it matches
// ErrInvalidAddress, so a caller several layers up (the Admin API, the database circuit
// breaker) tells an address that does not parse from a failure without matching text.
type addressError struct{ error }

func (e addressError) Unwrap() error        { return e.error }
func (e addressError) Is(target error) bool { return target == ErrInvalidAddress }

func parseAddress(input string) (Address, error) {
	// Normalize: trim (but don't lowercase yet - need to preserve suffix case)
	input = strings.TrimSpace(input)

	// RFC 6531 admits UTF-8 and nothing else beyond ASCII; checked before anything
	// else because strings.ToLower rewrites invalid bytes.
	if !utf8.ValidString(input) {
		return Address{}, fmt.Errorf("address is not valid UTF-8: %q", input)
	}

	// Check for internal whitespace (after trimming)
	if strings.ContainsAny(input, " \t\n\r") {
		return Address{}, fmt.Errorf("address contains whitespace: '%s'", input)
	}

	// Empty check
	if input == "" {
		return Address{}, fmt.Errorf("address is empty")
	}

	// Parse suffix BEFORE lowercasing (to preserve case for master username/token)
	// Format: localpart@domain or localpart@domain@SUFFIX (where SUFFIX may contain @)
	var suffix string
	var emailPart string

	// Find first @ (required for email)
	firstAt := strings.Index(input, "@")
	if firstAt == -1 {
		return Address{}, fmt.Errorf("address missing @: '%s'", input)
	}

	// Find second @ after the first one (optional, marks start of suffix)
	remainingAfterFirstAt := input[firstAt+1:]
	secondAt := strings.Index(remainingAfterFirstAt, "@")

	if secondAt == -1 {
		// No suffix: user@domain.com
		emailPart = input
		suffix = ""
	} else {
		// Suffix present: user@domain.com@SUFFIX
		// The email part is everything up to the second @
		emailPart = input[:firstAt+1+secondAt]
		// The suffix is everything after the second @ (may contain more @)
		// IMPORTANT: Preserve original case for suffix (for master username/token comparison)
		suffix = input[firstAt+1+secondAt+1:]
	}

	// NOW lowercase the email part for validation
	emailPart = strings.ToLower(emailPart)

	// Validate the email part (without suffix)
	emailParts := strings.Split(emailPart, "@")
	if len(emailParts) != 2 {
		return Address{}, fmt.Errorf("invalid email format: '%s'", emailPart)
	}

	localPart := emailParts[0]
	domain := emailParts[1]

	// Validate local part length (RFC 5321)
	if len(localPart) > MaxLocalPartLength {
		return Address{}, fmt.Errorf("local part exceeds maximum length of %d characters: '%s'", MaxLocalPartLength, localPart)
	}

	// Validate local part format
	if !localPartRe.MatchString(localPart) {
		return Address{}, fmt.Errorf("unacceptable local part: '%s'", localPart)
	}

	// RFC 6531 §3.2: an internationalized domain name (U-label) is looked up and stored in
	// its A-label form, so fold it here; everything past this point sees an ASCII domain.
	// The ASCII path is untouched: IDNA mapping applies only to a domain that needs it.
	if !IsASCII(domain) {
		ascii, err := idna.Lookup.ToASCII(domain)
		if err != nil {
			return Address{}, fmt.Errorf("unacceptable domain: '%s': %w", domain, err)
		}
		domain = ascii
	}

	// Validate domain length (RFC 5321)
	if len(domain) > MaxDomainLength {
		return Address{}, fmt.Errorf("domain exceeds maximum length of %d characters: '%s'", MaxDomainLength, domain)
	}

	// Validate domain format
	if !domainNameRe.MatchString(domain) {
		return Address{}, fmt.Errorf("unacceptable domain: '%s'", domain)
	}

	// Validate total address length (RFC 5321)
	totalLength := len(localPart) + 1 + len(domain) // +1 for @ sign
	if totalLength > MaxAddressLength {
		return Address{}, fmt.Errorf("email address exceeds maximum length of %d characters (got %d): '%s'", MaxAddressLength, totalLength, emailPart)
	}

	// Parse detail part from local part (plus addressing)
	detail := ""
	if plusIndex := strings.Index(localPart, "+"); plusIndex != -1 {
		detail = localPart[plusIndex+1:]
	}

	// Reconstruct full address with lowercased email part (and the domain in its
	// A-label form) and case-preserved suffix
	emailPart = localPart + "@" + domain
	var fullAddr string
	if suffix != "" {
		fullAddr = emailPart + "@" + suffix
	} else {
		fullAddr = emailPart
	}

	return Address{
		fullAddress: fullAddr, // Lowercased email + case-preserved suffix
		localPart:   localPart,
		domain:      domain,
		detail:      detail,
		suffix:      suffix,
	}, nil
}

// IsASCII reports whether s consists of 7-bit characters only. An envelope address that
// is not ASCII makes the mail transaction an internationalized one (RFC 6531).
func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// NewForwardPath parses the forward-path of RCPT TO as go-smtp hands it to a session.
// It is NewAddress without the master-token suffix: a recipient is an envelope address,
// not a login name, and a second "@" in it comes from a quoted local part such as
// `"a@b.example"@example.com` (go-smtp unquotes it), which no account here has. Read
// with the suffix rule it would be delivered to a@b.example (#1938).
func NewForwardPath(input string) (Address, error) {
	addr, err := NewAddress(input)
	if err != nil {
		return Address{}, err
	}
	if addr.HasSuffix() {
		return Address{}, addressError{fmt.Errorf("recipient has more than one @: %q", input)}
	}
	return addr, nil
}

// Reverse-path syntax that NewReversePath accepts beyond NewAddress. A lenient dot-string
// is atext and dots in any arrangement (go-smtp's dot-string, which takes leading,
// trailing and consecutive dots on purpose). A lenient domain is a name of one or more
// labels, so a dotless one such as "localhost" too, or an RFC 5321 §4.1.3 address
// literal: "[" 1*dcontent "]" with dcontent = %d33-90 / %d94-126.
var (
	lenientDotStringRe = regexp.MustCompile(`^(?i)[.` + atextClass + `]+$`)
	lenientDomainRe    = regexp.MustCompile(`^(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	addressLiteralRe   = regexp.MustCompile(`^\[[\x21-\x5a\x5e-\x7e]+\]$`)
)

// NewReversePath parses the reverse-path of MAIL FROM: the mailbox between the angle
// brackets. The null reverse-path ("") is the caller's to handle; it is refused here.
//
// A quoted local part is read in either of its forms: as go-smtp hands it to a session,
// already unquoted ("john doe@example.com"), or as written (`"john doe"@example.com`,
// which is how the Admin API passes it on). A local part that is one whole Quoted-string
// is read as one, the way go-smtp reads it; the rare go-smtp mailbox whose unquoted
// local part is itself such a string is read the same way.
//
// The suffix (user@domain@SUFFIX) belongs to login names, not to envelope addresses: a
// second "@" can only come from a quoted local part, so "a@b.example@example.com" is
// the sender `"a@b.example"@example.com` (#1938). The sender is read as leniently as
// go-smtp's own parser reads it, which is what Postfix does with
// strict_rfc821_envelopes = no: leading, trailing and consecutive dots in the local part
// (older mobile carrier addresses), a quoted local part, a dotless domain and an address
// literal. Refusing them would bounce mail the MTA was right to send (#1907). Forward-paths
// stay with NewAddress.
//
// What is returned is the mailbox replies and redirects are sent to, so the local part
// keeps the case it was sent with (RFC 5321 §2.4: SMTP implementations "MUST take care
// to preserve the case of mailbox local-parts", #2101); only the domain is lower-cased,
// and a non-ASCII domain is folded to its A-label. Compare or key senders in lower case.
// It is safe to write into a command or a header: no control character survives (CR and
// LF included), the length limits of NewAddress apply to the form returned, and a local
// part that is not a dot-string is returned quoted once (RFC 5321 §4.1.2 Quoted-string,
// with "\" and `"` escaped, the minimum quoting possible), so FullAddress is the mailbox
// in the form a MAIL FROM, RCPT TO or To: field takes it.
func NewReversePath(input string) (Address, error) {
	addr, err := parseReversePath(input)
	if err != nil {
		return Address{}, addressError{err}
	}
	return addr, nil
}

func parseReversePath(input string) (Address, error) {
	if !utf8.ValidString(input) {
		return Address{}, fmt.Errorf("address is not valid UTF-8: %q", input)
	}
	for _, r := range input {
		if r < 0x20 || r == 0x7f {
			return Address{}, fmt.Errorf("address contains a control character: %q", input)
		}
	}

	// A quoted local part may hold "@"; a domain never does.
	at := strings.LastIndexByte(input, '@')
	if at <= 0 || at == len(input)-1 {
		return Address{}, fmt.Errorf("invalid email format: %q", input)
	}
	localPart := input[:at]
	if unquoted, ok := unquoteLocalPart(localPart); ok {
		localPart = unquoted
	}
	domain := strings.ToLower(input[at+1:])

	detail := ""
	if lenientDotStringRe.MatchString(localPart) {
		if plusIndex := strings.Index(localPart, "+"); plusIndex != -1 {
			detail = localPart[plusIndex+1:]
		}
	} else {
		// Every printable character may stand in a quoted string once "\" and `"` are
		// escaped (RFC 5321 §4.1.2 qtextSMTP and quoted-pairSMTP; UTF8-non-ascii by RFC
		// 6531 §3.3). A quoted local part has no detail.
		localPart = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(localPart) + `"`
	}
	if len(localPart) > MaxLocalPartLength {
		return Address{}, fmt.Errorf("local part exceeds maximum length of %d characters: %q", MaxLocalPartLength, localPart)
	}

	if !IsASCII(domain) {
		ascii, err := idna.Lookup.ToASCII(domain)
		if err != nil {
			return Address{}, fmt.Errorf("unacceptable domain: %q: %w", domain, err)
		}
		domain = ascii
	}
	if len(domain) > MaxDomainLength {
		return Address{}, fmt.Errorf("domain exceeds maximum length of %d characters: %q", MaxDomainLength, domain)
	}
	if !lenientDomainRe.MatchString(domain) && !addressLiteralRe.MatchString(domain) {
		return Address{}, fmt.Errorf("unacceptable domain: %q", domain)
	}

	fullAddress := localPart + "@" + domain
	if len(fullAddress) > MaxAddressLength {
		return Address{}, fmt.Errorf("email address exceeds maximum length of %d characters (got %d): %q", MaxAddressLength, len(fullAddress), fullAddress)
	}
	return Address{
		fullAddress: fullAddress,
		localPart:   localPart,
		domain:      domain,
		detail:      detail,
	}, nil
}

// unquoteLocalPart returns the content of s when s is one non-empty quoted string as
// go-smtp reads a quoted local part: between the double quotes, "\" quotes the next
// character and a bare `"` cannot stand (RFC 5321 §4.1.2 Quoted-string).
func unquoteLocalPart(s string) (string, bool) {
	if len(s) < 3 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", false
	}
	inner := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch c {
		case '"':
			return "", false
		case '\\':
			i++
			if i == len(inner) {
				// The closing quote is escaped: the string does not end.
				return "", false
			}
			c = inner[i]
		}
		b.WriteByte(c)
	}
	return b.String(), true
}
