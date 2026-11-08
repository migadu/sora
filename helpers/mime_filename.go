package helpers

import (
	"net/url"
	"strconv"
	"strings"
)

type mimeParameter struct {
	value   string
	present bool
	valid   bool
}

// parameterForms resolves independent legacy, extended, and continued forms.
// RFC 2231 values need byte unescaping, not charset decoding, for attachment
// detection. A bad alternative cannot erase a valid nonempty filename.
func (h mimeHeaderValue) parameterForms(name string) (plain, extended, continued mimeParameter) {
	plain.value, plain.present = h.params[name]
	plain.present = plain.present || h.invalid[name]
	plain.valid = !h.invalid[name]
	extended.value, extended.present = h.params[name+"*"]
	extended.present = extended.present || h.invalid[name+"*"]
	extended.valid = !h.invalid[name+"*"]
	if extended.present && extended.valid {
		extended.value, extended.valid = mimeParameterBytes(extended.value, true)
	}

	keys := make(map[string]bool)
	for key := range h.params {
		if strings.HasPrefix(key, name+"*") && key != name+"*" {
			keys[key] = true
		}
	}
	for key := range h.invalid {
		if strings.HasPrefix(key, name+"*") && key != name+"*" {
			keys[key] = true
		}
	}
	continued.present, continued.valid = len(keys) > 0, true
	var joined strings.Builder
	// Bound the loop by the number of attributes, never a supplied index.
	for i := 0; i < len(keys); i++ {
		key := name + "*" + strconv.Itoa(i)
		value, hasPlain := h.params[key]
		encoded, hasEncoded := h.params[key+"*"]
		if hasPlain == hasEncoded || h.invalid[key] || h.invalid[key+"*"] {
			continued.valid = false
			break
		}
		if hasEncoded {
			var ok bool
			value, ok = mimeParameterBytes(encoded, i == 0)
			if !ok {
				continued.valid = false
				break
			}
		}
		joined.WriteString(value)
	}
	continued.value = joined.String()
	return plain, extended, continued
}

func mimeFilename(h mimeHeaderValue, name string) attachmentResult {
	plain, extended, continued := h.parameterForms(name)
	unknown := false
	for _, form := range []mimeParameter{plain, extended, continued} {
		if form.present && form.valid && form.value != "" {
			return attachmentFound
		}
		unknown = unknown || (form.present && !form.valid)
	}
	if unknown {
		return attachmentUnknown
	}
	return attachmentNone
}

// boundary follows the extended > continued > legacy preference of the MIME
// parser. An invalid selected form must not guess a different delimiter.
func (h mimeHeaderValue) boundary() (string, bool) {
	plain, extended, continued := h.parameterForms("boundary")
	for _, form := range []mimeParameter{extended, continued, plain} {
		if form.present {
			return form.value, form.valid && validMIMEBoundary(form.value)
		}
	}
	return "", false
}

func validMIMEBoundary(value string) bool {
	// RFC 2046 §5.1.1 bchars: spaces are permitted except at the end.
	if len(value) == 0 || len(value) > 70 || value[len(value)-1] == ' ' {
		return false
	}
	for _, c := range []byte(value) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if !strings.ContainsRune("'()+_,-./:=? ", rune(c)) {
			return false
		}
	}
	return true
}

func mimeParameterBytes(value string, first bool) (string, bool) {
	if first {
		// charset'language'encoded-value; either prefix may be unspecified.
		_, rest, ok := strings.Cut(value, "'")
		if !ok {
			return "", false
		}
		_, value, ok = strings.Cut(rest, "'")
		if !ok {
			return "", false
		}
	}
	decoded, err := url.PathUnescape(value)
	return decoded, err == nil
}
