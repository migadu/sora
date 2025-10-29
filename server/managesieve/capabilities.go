package managesieve

import (
	"fmt"
	"strings"
)

// GoSieveSupportedExtensions lists all SIEVE extensions that the underlying
// go-sieve library (github.com/migadu/go-sieve) can validate and execute.
//
// This is the authoritative list of what can be configured in supported_extensions.
// Extensions not in this list will cause script validation to fail.
//
// NOTE: Core RFC 5228 commands (require, if/elsif/else, stop, redirect, keep, discard)
// are always available and don't need to be in this list.
//
// Based on: github.com/migadu/go-sieve@v0.0.0-20250924160026-17d8f94a0a43/interp/load.go
var GoSieveSupportedExtensions = []string{
	// Core extensions from RFC 5228
	"fileinto",          // RFC 5228 - Store messages in specified mailbox
	"envelope",          // RFC 5228 - Test envelope addresses
	"encoded-character", // RFC 5228 - Encoded character support

	// Comparators
	"comparator-i;octet",           // RFC 4790 - Octet comparator
	"comparator-i;ascii-casemap",   // RFC 4790 - ASCII case-insensitive
	"comparator-i;ascii-numeric",   // RFC 4790 - ASCII numeric
	"comparator-i;unicode-casemap", // RFC 4790 - Unicode case-insensitive

	// Common extensions
	"imap4flags", // RFC 5232 - IMAP flag manipulation
	"variables",  // RFC 5229 - Variable support
	"relational", // RFC 5231 - Relational tests (gt, lt, etc.)
	"vacation",   // RFC 5230 - Vacation auto-responder
	"copy",       // RFC 3894 - Copy extension for redirect and fileinto
	"regex",      // draft-murchison-sieve-regex - Regular expression match type
}

// CommonlyUsedExtensions provides a recommended default list of extensions
// for production use. This is what gets configured in config.toml.example.
var CommonlyUsedExtensions = []string{
	"fileinto",
	"vacation",
	"envelope",
	"imap4flags",
	"variables",
	"relational",
	"copy",
	"regex",
}

// ValidateExtensions checks if the provided extensions are supported by go-sieve.
// Returns an error listing any invalid extensions.
func ValidateExtensions(extensions []string) error {
	if len(extensions) == 0 {
		return nil
	}

	// Build map of all supported extensions
	supportedMap := make(map[string]bool)
	for _, ext := range GoSieveSupportedExtensions {
		supportedMap[ext] = true
	}

	// Check for invalid extensions
	var invalid []string
	for _, ext := range extensions {
		if !supportedMap[ext] {
			invalid = append(invalid, ext)
		}
	}

	if len(invalid) > 0 {
		return fmt.Errorf("invalid SIEVE extensions: %s (go-sieve supports: %s)",
			strings.Join(invalid, ", "),
			strings.Join(GoSieveSupportedExtensions, ", "))
	}

	return nil
}

// GetSieveCapabilities returns the SIEVE capabilities that should be advertised
// to clients. This is simply the configured supported_extensions list.
//
// NOTE: This used to combine a "builtin" list with additional extensions, but that
// was incorrect. We should only advertise what's explicitly configured, because
// go-sieve validates against the enabled extensions list during script upload.
func GetSieveCapabilities(supportedExtensions []string) []string {
	// Return a copy to prevent external modification
	capabilities := make([]string, len(supportedExtensions))
	copy(capabilities, supportedExtensions)
	return capabilities
}
