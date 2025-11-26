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

// NewAddress is an alias for ParseAddressWithMasterToken for backward compatibility
func NewAddress(input string) (Address, error) {
	// Normalize: trim (but don't lowercase yet - need to preserve suffix case)
	input = strings.TrimSpace(input)

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

	// Reconstruct full address with lowercased email part and case-preserved suffix
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
