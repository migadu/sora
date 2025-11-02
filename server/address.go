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

// ParseAddressWithMasterToken parses an email address that may contain a suffix
// The suffix uses the syntax: user@domain.com@SUFFIX
// The SUFFIX can be either:
// - A master username (for master password authentication)
// - A prelookup token (for HTTP prelookup authentication)
// Returns the parsed Address with proper validation, stripping +detail for authentication
func ParseAddressWithMasterToken(input string) (Address, error) {
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

	// Split on @ to check for suffix (master username or prelookup token)
	// Format: localpart@domain or localpart@domain@suffix
	parts := strings.Split(input, "@")

	// Need at least 2 parts (localpart@domain)
	if len(parts) < 2 {
		return Address{}, fmt.Errorf("address missing @: '%s'", input)
	}

	var suffix string
	var emailPart string

	if len(parts) == 2 {
		// Standard format: user@domain.com
		emailPart = input
		suffix = ""
	} else if len(parts) == 3 {
		// Suffix format: user@domain.com@SUFFIX (master username or token)
		emailPart = parts[0] + "@" + parts[1]
		suffix = parts[2]
	} else {
		// Too many @ symbols (more than 2)
		return Address{}, fmt.Errorf("too many @ symbols in address: '%s'", input)
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
