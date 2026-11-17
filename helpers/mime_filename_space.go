package helpers

import (
	stdmime "mime"
	"strings"
)

// quoteUnquotedFilename repairs the narrow, common defect of an unquoted
// Content-Disposition filename containing spaces. It only quotes ASCII MIME
// token words separated by SP, and never changes the original header. The
// caller must fully reparse the temporary copy before accepting the repair.
//
// Recovery requires one plain filename and no filename* forms: guessing among
// duplicate, extended or continued alternatives could change which filename
// wins. Comments outside quoted strings and incomplete quote/escape scopes
// also prevent recovery. Already-valid headers bypass this helper entirely.
func quoteUnquotedFilename(value string) (string, bool) {
	filenameSeen := false
	filenameStart, filenameEnd := -1, -1
	parameterStart := -1
	quoted := false

	checkParameter := func(start, end int) bool {
		parameter := value[start:end]
		if strings.Trim(parameter, " \t") == "" {
			// Leave the existing parser to decide whether dangling separators
			// are acceptable; never fix an interior empty parameter ourselves.
			return true
		}
		equals := strings.IndexByte(parameter, '=')
		if equals < 0 {
			return false
		}
		key := strings.Trim(parameter[:equals], " \t")
		if key == "" {
			return false
		}
		for i := 0; i < len(key); i++ {
			if !mimeTokenByte(key[i]) {
				return false
			}
		}
		if len(key) > len("filename") && strings.EqualFold(key[:len("filename")], "filename") && key[len("filename")] == '*' {
			return false
		}
		if !strings.EqualFold(key, "filename") {
			return true
		}
		if filenameSeen {
			return false
		}
		filenameSeen = true
		start += equals + 1
		for start < end && (value[start] == ' ' || value[start] == '\t') {
			start++
		}
		for end > start && (value[end-1] == ' ' || value[end-1] == '\t') {
			end--
		}
		if start == end {
			return false
		}
		hasSpace := false
		for i := start; i < end; i++ {
			if value[i] == ' ' {
				hasSpace = true
			} else if !mimeTokenByte(value[i]) {
				return false
			}
		}
		if !hasSpace {
			return false
		}
		filenameStart, filenameEnd = start, end
		return true
	}

	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < ' ' && c != '\t' || c == 127 {
			return "", false
		}
		if quoted {
			if c == '\\' {
				i++
				if i == len(value) || value[i] < ' ' && value[i] != '\t' || value[i] == 127 {
					return "", false
				}
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '(', ')':
			return "", false
		case '"':
			quoted = true
		case ';':
			if parameterStart >= 0 && !checkParameter(parameterStart, i) {
				return "", false
			}
			parameterStart = i + 1
		}
	}
	if quoted || parameterStart < 0 || !checkParameter(parameterStart, len(value)) || filenameStart < 0 {
		return "", false
	}
	return value[:filenameStart] + `"` + value[filenameStart:filenameEnd] + `"` + value[filenameEnd:], true
}

// validateRecoveredFilename follows go-message's strict media-parameter parse,
// including its existing tolerance of trailing separators, before the raw
// scanner may turn a recovered filename into attachment evidence.
func validateRecoveredFilename(raw string) (string, bool) {
	repaired, ok := quoteUnquotedFilename(raw)
	if !ok {
		return "", false
	}
	if _, _, err := stdmime.ParseMediaType(repaired); err == nil {
		return repaired, true
	}
	trimmed := strings.TrimRight(strings.TrimSpace(repaired), "; \t")
	if trimmed != repaired {
		if _, _, err := stdmime.ParseMediaType(trimmed); err == nil {
			return trimmed, true
		}
	}
	return "", false
}
