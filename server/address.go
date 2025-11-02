package server

import (
	"fmt"
	"regexp"
	"strings"
)

// RFC 5322 compliant email validation regex
// This allows for more valid email addresses than the previous regex
const LocalPartRegex = `^(?i)(?:[a-z0-9!#$%&'*+/=?^_\{\|\}~-])+(?:\.(?:[a-z0-9!#$%&'*+/=?^_\{\|\}~-])+)*$`
const DomainNameRegex = `^(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`

// Separator constants for master authentication
const (
	// BackendMasterTokenSeparator is used by backend servers for master username and prelookup tokens
	// Format: user@domain@SUFFIX (where SUFFIX can be master username or prelookup token)
	BackendMasterTokenSeparator = "@"

	// ProxyMasterUsernameSeparator is used by proxy servers for CLIENT→PROXY master username authentication
	// Format: user@domain*MASTER_USERNAME
	// Using * avoids confusion with @ in email addresses
	ProxyMasterUsernameSeparator = "*"
)

type Address struct {
	fullAddress string
	localPart   string
	domain      string
	detail      string
	suffix      string // Suffix after second @ (can be master username or prelookup token): user@domain.com@SUFFIX
}

func NewAddress(address string) (Address, error) {
	// Delegate to ParseAddressWithMasterToken for comprehensive validation
	// This handles master tokens, +detail addressing, whitespace, etc.
	return ParseAddressWithMasterToken(address)
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
// The suffix can be a master username or prelookup token
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

// MasterToken returns the suffix if present (from syntax like user@domain.com@SUFFIX)
// Note: This is kept for backward compatibility. The suffix can be either:
// - A master username (for master password authentication)
// - A prelookup token (for HTTP prelookup authentication)
func (a Address) MasterToken() string {
	return a.suffix
}

// Suffix returns the suffix after the second @ if present (from syntax like user@domain.com@SUFFIX)
// The suffix can be either a master username or a prelookup token depending on context
func (a Address) Suffix() string {
	return a.suffix
}

// HasMasterToken returns true if the address contains a suffix
// Note: Kept for backward compatibility, use HasSuffix() for new code
func (a Address) HasMasterToken() bool {
	return a.suffix != ""
}

// HasSuffix returns true if the address contains a suffix after the second @
func (a Address) HasSuffix() bool {
	return a.suffix != ""
}

// ParseAddressWithProxySeparator parses an email address that may contain a suffix using * separator
// The suffix uses the syntax: user@domain.com*SUFFIX
// This is used by PROXIES for client→proxy master username authentication
// The SUFFIX represents the master username for proxy-level authentication
// Returns the parsed Address with proper validation, stripping +detail for authentication
func ParseAddressWithProxySeparator(input string) (Address, error) {
	return parseAddressWithSeparator(input, ProxyMasterUsernameSeparator)
}

// ParseAddressWithMasterToken parses an email address that may contain a suffix using @ separator
// The suffix uses the syntax: user@domain.com@SUFFIX
// This is used by BACKENDS for:
// - A master username (for master password authentication)
// - A prelookup token (for HTTP prelookup authentication)
// Returns the parsed Address with proper validation, stripping +detail for authentication
func ParseAddressWithMasterToken(input string) (Address, error) {
	return parseAddressWithSeparator(input, BackendMasterTokenSeparator)
}

// parseAddressWithSeparator is the internal implementation that handles both @ and * separators
func parseAddressWithSeparator(input string, separator string) (Address, error) {
	// Normalize: trim and lowercase
	input = strings.ToLower(strings.TrimSpace(input))

	// Check for internal whitespace (after trimming)
	if strings.ContainsAny(input, " \t\n\r") {
		return Address{}, fmt.Errorf("address contains whitespace: '%s'", input)
	}

	// Empty check
	if input == "" {
		return Address{}, fmt.Errorf("address is empty")
	}

	// Split on separator to check for suffix (master username or prelookup token)
	// Format depends on separator:
	//   @ separator: localpart@domain or localpart@domain@suffix
	//   * separator: localpart@domain or localpart@domain*suffix
	var suffix string
	var emailPart string

	switch separator {
	case "@":
		// For @ separator, we need to account for the @ in email address (localpart@domain)
		// and then look for an additional @ for the suffix
		// Format: localpart@domain or localpart@domain@SUFFIX (where SUFFIX may contain @)

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
			suffix = input[firstAt+1+secondAt+1:]
		}

	case "*":
		// For * separator, split only on FIRST occurrence
		// Format: localpart@domain or localpart@domain*SUFFIX (where SUFFIX may contain *)
		starIndex := strings.Index(input, "*")

		if starIndex == -1 {
			// No suffix: user@domain.com
			emailPart = input
			suffix = ""
		} else {
			// Suffix format: user@domain.com*SUFFIX
			emailPart = input[:starIndex]
			// Everything after first * is the suffix (may contain more *)
			suffix = input[starIndex+1:]
		}

	default:
		return Address{}, fmt.Errorf("unsupported separator: '%s'", separator)
	}

	// Validate the email part (without suffix)
	emailParts := strings.Split(emailPart, "@")
	if len(emailParts) != 2 {
		return Address{}, fmt.Errorf("invalid email format: '%s'", emailPart)
	}

	localPart := emailParts[0]
	domain := emailParts[1]

	// Validate local part
	if !regexp.MustCompile(LocalPartRegex).MatchString(localPart) {
		return Address{}, fmt.Errorf("unacceptable local part: '%s'", localPart)
	}

	// Validate domain
	if !regexp.MustCompile(DomainNameRegex).MatchString(domain) {
		return Address{}, fmt.Errorf("unacceptable domain: '%s'", domain)
	}

	// Parse detail part from local part (plus addressing)
	detail := ""
	if plusIndex := strings.Index(localPart, "+"); plusIndex != -1 {
		detail = localPart[plusIndex+1:]
	}

	return Address{
		fullAddress: input, // Store original input with suffix
		localPart:   localPart,
		domain:      domain,
		detail:      detail,
		suffix:      suffix,
	}, nil
}
