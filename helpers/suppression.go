package helpers

import (
	"fmt"
	"strings"
)

// ShouldSuppressAuto implements RFC 5230 §4.5 mandatory suppression rules for
// auto-replies (like vacation) or redirects, returning a non-empty reason if the action
// must NOT be performed:
//   - null/empty sender (MAIL FROM:<>): bounce/DSN messages never trigger loops
//   - Auto-Submitted (not "no"): messages from other auto-responders -> loop risk
//   - Precedence bulk/junk/list: mailing lists / mass mailings
//   - List-Id present (RFC 2919): additional mailing-list safety net
func ShouldSuppressAuto(envFrom string, headerGet func(string) []string) string {
	if envFrom == "" {
		return "null or empty sender (bounce message)"
	}

	if autoVals := headerGet("Auto-Submitted"); len(autoVals) > 0 && autoVals[0] != "" {
		val := autoVals[0]
		if strings.ToLower(strings.TrimSpace(val)) != "no" {
			return fmt.Sprintf("Auto-Submitted: %s", val)
		}
	}

	if precVals := headerGet("Precedence"); len(precVals) > 0 && precVals[0] != "" {
		p := strings.ToLower(strings.TrimSpace(precVals[0]))
		if p == "bulk" || p == "junk" || p == "list" {
			return fmt.Sprintf("Precedence: %s", precVals[0])
		}
	}

	if listIDVals := headerGet("List-Id"); len(listIDVals) > 0 && listIDVals[0] != "" {
		return fmt.Sprintf("List-Id: %s", listIDVals[0])
	}

	return ""
}
