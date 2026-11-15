package helpers

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// sizeRe matches a size: a decimal number, optional whitespace, and an
// optional unit (b, kb, mb, gb or tb, in any case).
var sizeRe = regexp.MustCompile(`(?i)^(\d+)\s*([kmgt]?b)?$`)

// ParseSize parses a human-readable size string (e.g., "1gb", "512MB", "1024kb", "2048")
// and returns the size in bytes as an int64.
// It supports units: b (bytes), kb, mb, gb and tb (powers of 1024). A bare
// number is bytes. The units are case-insensitive.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("cannot parse empty size string")
	}

	matches := sizeRe.FindStringSubmatch(s)
	if matches == nil {
		return 0, fmt.Errorf("invalid size format: '%s'. Expected format like '1024b', '5mb', '1gb'", s)
	}

	size, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size format: failed to parse number '%s': %w", matches[1], err)
	}

	var shift uint
	switch strings.ToLower(matches[2]) {
	case "", "b":
		shift = 0
	case "kb":
		shift = 10
	case "mb":
		shift = 20
	case "gb":
		shift = 30
	case "tb":
		shift = 40
	}
	if size > math.MaxInt64>>shift {
		return 0, fmt.Errorf("invalid size: '%s' exceeds the maximum of %d bytes", s, int64(math.MaxInt64))
	}
	return size << shift, nil
}

// ParseDuration extends time.ParseDuration to support "d" for days.
// It specifically handles strings of the format "[+/-]Nd" (e.g., "14d", "-7d", "+5d")
// by converting them to hours (e.g., "14d" becomes "336h", "-7d" becomes "-168h")
// before passing to time.ParseDuration. Other formats are passed directly to
// time.ParseDuration.
func ParseDuration(durationStr string) (time.Duration, error) {
	originalInput := durationStr // Keep original for context in errors

	s := durationStr
	isNegative := false
	if strings.HasPrefix(s, "-") {
		isNegative = true
		s = s[1:] // Process without the sign for now
	} else if strings.HasPrefix(s, "+") {
		s = s[1:] // Process without the sign
	}

	if strings.HasSuffix(s, "d") {
		daysPart := strings.TrimSuffix(s, "d")
		if daysPart == "" {
			return 0, fmt.Errorf("helpers.ParseDuration: invalid duration format, missing day value in '%s'", originalInput)
		}

		days, err := strconv.ParseUint(daysPart, 10, 64)
		if err == nil {
			// Successfully parsed an integer number of days.
			// This implies the input string was of the form "[<sign>]<number>d".
			if days > uint64(math.MaxInt64/int64(24*time.Hour)) {
				return 0, fmt.Errorf("helpers.ParseDuration: duration '%s' overflows time.Duration", originalInput)
			}
			hours := int64(days) * 24
			if isNegative {
				hours = -hours
			}
			return time.ParseDuration(fmt.Sprintf("%dh", hours))
		}
		// If strconv.Atoi(daysPart) failed, fall through to standard parsing.
	}

	return time.ParseDuration(originalInput)
}
