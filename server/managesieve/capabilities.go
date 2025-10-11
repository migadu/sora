package managesieve

import (
	"fmt"
	"strings"
)

// BuiltinSieveCapabilities lists the SIEVE extensions that are always available
// without additional configuration. These are the core RFC-standardized extensions
// that most SIEVE implementations support.
//
// Additional extensions (like vacation, regex) should be explicitly configured
// via the supported_extensions configuration option.
var BuiltinSieveCapabilities = []string{
	"fileinto",                   // RFC 5228 - Store messages in specified mailbox
	"reject",                     // RFC 5429 - Reject messages with custom message
	"envelope",                   // RFC 5228 - Test envelope addresses
	"encoded-character",          // RFC 5228 - Encoded character support
	"subaddress",                 // RFC 5233 - Subaddress (user+detail) support
	"comparator-i;ascii-numeric", // RFC 4790 - ASCII numeric comparator
	"relational",                 // RFC 5231 - Relational tests (gt, lt, etc.)
	"imap4flags",                 // RFC 5232 - IMAP flag manipulation
	"copy",                       // RFC 3894 - Copy messages without implicit keep
	"include",                    // RFC 6609 - Include other scripts
	"variables",                  // RFC 5229 - Variable support
	"body",                       // RFC 5173 - Body content tests
	"enotify",                    // RFC 5435 - Email notifications
	"environment",                // RFC 5183 - Environment variable access
	"mailbox",                    // RFC 5490 - Mailbox existence tests
	"date",                       // RFC 5260 - Date/time tests
	"index",                      // RFC 5260 - Index extension
	"ihave",                      // RFC 5463 - Conditional script compilation
	"duplicate",                  // RFC 7352 - Duplicate message detection
	"mime",                       // RFC 5703 - MIME part tests
	"foreverypart",               // RFC 5703 - Iterate over MIME parts
	"extracttext",                // RFC 5703 - Extract text from MIME parts
}

// AvailableAdditionalExtensions lists SIEVE extensions that can be optionally
// enabled via configuration. These extensions may require additional implementation
// or external dependencies.
var AvailableAdditionalExtensions = []string{
	"vacation",   // RFC 5230 - Vacation auto-responder
	"regex",      // RFC 5229 - Regular expression support (draft)
	"editheader", // RFC 5293 - Header manipulation
	"spamtest",   // RFC 5235 - Spam test interface
	"virustest",  // RFC 5235 - Virus test interface
}

// ValidateExtensions checks if the provided extensions are valid (either builtin or available).
// Returns an error listing any invalid extensions.
func ValidateExtensions(extensions []string) error {
	if len(extensions) == 0 {
		return nil
	}

	// Build map of all valid extensions
	validExtensions := make(map[string]bool)
	for _, ext := range BuiltinSieveCapabilities {
		validExtensions[ext] = true
	}
	for _, ext := range AvailableAdditionalExtensions {
		validExtensions[ext] = true
	}

	// Check for invalid extensions
	var invalid []string
	for _, ext := range extensions {
		if !validExtensions[ext] {
			invalid = append(invalid, ext)
		}
	}

	if len(invalid) > 0 {
		return fmt.Errorf("invalid SIEVE extensions: %s (available: %s)",
			strings.Join(invalid, ", "),
			strings.Join(AvailableAdditionalExtensions, ", "))
	}

	return nil
}

// GetSieveCapabilities returns the complete list of SIEVE capabilities
// by combining builtin capabilities with configured additional extensions.
// It filters out duplicates (extensions already in builtin list).
func GetSieveCapabilities(additionalExtensions []string) []string {
	// Build set of builtin capabilities for fast lookup
	builtinSet := make(map[string]bool)
	for _, cap := range BuiltinSieveCapabilities {
		builtinSet[cap] = true
	}

	// Start with builtin capabilities
	capabilities := make([]string, 0, len(BuiltinSieveCapabilities)+len(additionalExtensions))
	capabilities = append(capabilities, BuiltinSieveCapabilities...)

	// Add additional extensions that aren't already builtin
	for _, ext := range additionalExtensions {
		if !builtinSet[ext] {
			capabilities = append(capabilities, ext)
		}
	}

	return capabilities
}
