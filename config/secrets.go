package config

import (
	"errors"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

// SecretMask replaces a secret setting's value in output meant to be read or shared.
const SecretMask = "***MASKED***"

// MaskSecrets replaces, in place, every non-empty string setting of cfg that is tagged
// `secret:"true"`, or sits under such a field, with SecretMask, through nested blocks,
// pointers, interfaces, maps and lists. An unset secret stays empty, so the output still
// tells it apart from a set one. Mark a new secret setting with the tag rather than
// masking it at a call site; TestConfigDumpMasksEverySecretField in cmd/sora-admin fails
// for one that looks like a secret and is left untagged.
// URL credentials are also masked in otherwise public strings (see maskURLCredentials),
// keeping the endpoint's scheme, host and path useful for debugging.
func MaskSecrets(cfg *Config) {
	maskSecrets(reflect.ValueOf(cfg).Elem(), false)
}

func maskSecrets(v reflect.Value, secret bool) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			maskSecrets(v.Elem(), secret)
		}
	case reflect.Interface:
		if !v.IsNil() {
			elem := v.Elem()
			cp := reflect.New(elem.Type()).Elem()
			cp.Set(elem)
			maskSecrets(cp, secret)
			if v.CanSet() {
				v.Set(cp)
			}
		}
	case reflect.Struct:
		typ := v.Type()
		for i := 0; i < typ.NumField(); i++ {
			if f := typ.Field(i); f.IsExported() {
				maskSecrets(v.Field(i), secret || f.Tag.Get("secret") == "true")
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			maskSecrets(v.Index(i), secret)
		}
	case reflect.Map:
		for iter := v.MapRange(); iter.Next(); {
			val := iter.Value()
			cp := reflect.New(val.Type()).Elem()
			cp.Set(val)
			maskSecrets(cp, secret)
			v.SetMapIndex(iter.Key(), cp)
		}
	case reflect.String:
		if secret && v.String() != "" {
			v.SetString(SecretMask)
		} else {
			v.SetString(maskURLCredentials(v.String()))
		}
	}
}

// MaskEndpointURL returns an endpoint setting (an http_url, a lookup URL, an
// smtp_host) as a log record or an error may show it: masked as the config dump
// masks it (see maskURLCredentials), keeping its scheme, host, port and path. A value
// without a scheme, which the URL masker cannot take apart, is masked whole if it may
// carry userinfo or a query.
func MaskEndpointURL(value string) string {
	if !strings.Contains(value, "://") && strings.ContainsAny(value, "?@") {
		return SecretMask
	}
	return maskURLCredentials(value)
}

// MaskURLError masks, in place, the URL that the *url.Error in err's chain quotes,
// as MaskEndpointURL masks it. Call it on an error owned by this request before it
// is published or logged. Display wrappers preserve the original error chain,
// including when fmt.Errorf has already copied the URL into its own text.
// net/http quotes the request URL in its errors with the user name and the query
// (it replaces only the password, with "***"), and url.Parse quotes the whole string
// it refuses. Such a string's reason quotes a piece of it too, `invalid port ":pass"
// after host` for "https://user:pass/word@host/", so when the string carries
// credentials the quoted parts of its reason are masked as well.
func MaskURLError(err error) error {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}
	masked := MaskEndpointURL(urlErr.URL)
	if urlErr.Err != nil {
		reason := urlErr.Err.Error()
		shown := maskURLErrorText(reason)
		if masked != urlErr.URL && urlErr.Op == "parse" {
			shown = maskQuoted(shown)
		}
		if shown != reason {
			urlErr.Err = &maskedURLCause{cause: urlErr.Err, text: shown}
		}
	}
	urlErr.URL = masked
	if err != urlErr {
		text := err.Error()
		if shown := maskURLErrorText(text); shown != text {
			return &maskedURLCause{cause: err, text: shown}
		}
	}
	return err
}

// A redirect's malformed Location is quoted inside Client.Do's source error,
// before CheckRedirect can refuse it. When a reason contains a credential URL,
// mask quoted parts too: its parser may quote only part of the password as an
// invalid port. Keep the category text, and mask any unquoted URLs as well.
func maskURLErrorText(text string) string {
	if shown := maskURLCredentials(text); shown != text {
		return maskURLCredentials(maskQuoted(text))
	}
	// Location can also be a network-path or relative reference, with no "://"
	// for maskURLCredentials to find. net/http quotes that reference with %q.
	for rest := text; ; {
		i := strings.IndexByte(rest, '"')
		if i < 0 {
			break
		}
		quoted, err := strconv.QuotedPrefix(rest[i:])
		if err != nil {
			if MaskEndpointURL(rest[i:]) != rest[i:] {
				return maskURLCredentials(maskQuoted(text))
			}
			break
		}
		value, _ := strconv.Unquote(quoted)
		if MaskEndpointURL(value) != value {
			return maskURLCredentials(maskQuoted(text))
		}
		rest = rest[i+len(quoted):]
	}
	return text
}

type maskedURLCause struct {
	cause error
	text  string
}

func (e *maskedURLCause) Error() string { return e.text }
func (e *maskedURLCause) Unwrap() error { return e.cause }
func (e *maskedURLCause) Timeout() bool {
	var timeout interface{ Timeout() bool }
	return errors.As(e.cause, &timeout) && timeout.Timeout()
}
func (e *maskedURLCause) Temporary() bool {
	var temporary interface{ Temporary() bool }
	return errors.As(e.cause, &temporary) && temporary.Temporary()
}

// maskQuoted replaces every Go-quoted string in s with a quoted SecretMask.
func maskQuoted(s string) string {
	var out strings.Builder
	for {
		i := strings.IndexByte(s, '"')
		if i < 0 {
			out.WriteString(s)
			return out.String()
		}
		out.WriteString(s[:i])
		out.WriteString(strconv.Quote(SecretMask))
		quoted, err := strconv.QuotedPrefix(s[i:])
		if err != nil {
			return out.String() // unterminated: the rest is quoted text
		}
		s = s[i+len(quoted):]
	}
}

// maskURLCredentials masks the credentials any URL in value can carry: its userinfo
// (HTTP Basic) and the value of every query parameter. Endpoint APIs authenticate with
// query parameters of any name (api_key, token, sig, ...), so no name tells a credential
// from a routing parameter. Sub-scheme prefixes (jdbc:postgresql://...), leading slashes
// or whitespace, embedded URLs in paths/fragments, and comma- or space-separated URLs
// preserve their surrounding text, scheme, host, port, path and fragment; a malformed
// credential-bearing URL is replaced whole with SecretMask.
func maskURLCredentials(value string) string {
	if !strings.Contains(value, "://") {
		return value
	}

	var out strings.Builder
	s := value
	for {
		colonSlash := strings.Index(s, "://")
		if colonSlash < 0 {
			out.WriteString(s)
			break
		}
		schemeStart := schemeStartAt(s, colonSlash)
		afterColonSlash := colonSlash + 3
		urlEnd := findURLEnd(s, schemeStart, afterColonSlash)

		if schemeStart == colonSlash {
			// No valid RFC 3986 scheme precedes "://": fail closed if the candidate
			// carries userinfo or query parameters, otherwise leave it unchanged.
			candidate := s[afterColonSlash:urlEnd]
			authority := candidate
			if end := strings.IndexAny(authority, "/?#"); end >= 0 {
				authority = authority[:end]
			}
			beforeFragment, _, _ := strings.Cut(candidate, "#")
			if strings.Contains(authority, "@") || strings.Contains(beforeFragment, "?") {
				return SecretMask
			}
			out.WriteString(s[:afterColonSlash])
			s = s[afterColonSlash:]
			continue
		}

		out.WriteString(s[:schemeStart])
		masked, failed := maskSingleURL(s[schemeStart:urlEnd])
		if failed {
			return SecretMask
		}
		out.WriteString(masked)
		s = s[urlEnd:]
	}
	return out.String()
}

func maskSingleURL(value string) (string, bool) {
	start := strings.Index(value, "://")
	if start < 0 {
		return value, false
	}
	rest := value[start+3:]
	authority := rest
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	beforeFragment, _, _ := strings.Cut(value, "#")
	hasQuery := strings.Contains(beforeFragment, "?")
	// A second "://" with no query before it means findURLEnd saw no path, fragment,
	// query, or list separator before that "://" (e.g. unencoded "://" in userinfo).
	if strings.Contains(rest, "://") && !hasQuery {
		return SecretMask, true
	}
	// An unencoded "/", "?" or "#" in the password ends the authority early, leaving
	// the "@" in the path, query or fragment, and the parser takes the start of the
	// password for a port and refuses the URL. So any "@" after the scheme is checked here.
	if !strings.Contains(rest, "@") && !hasQuery {
		return value, false
	}
	u, err := url.Parse(value)
	if err != nil {
		// The dump accepts unvalidated endpoint strings. Do not print credentials
		// just because another part of their URL has an invalid escape or port.
		return SecretMask, true
	}
	// Unless that start of the password is a number, or empty: then it is a valid
	// port and the URL parses, with the rest of the password and its "@" in the path,
	// query or fragment. Mask such a URL whole too, as the parser cannot tell it from
	// a host with a port and an "@" in its path, query or fragment.
	if u.User == nil && hasPortSeparator(u.Host) &&
		(strings.Contains(u.EscapedPath(), "@") || strings.Contains(u.RawQuery, "@") || strings.Contains(u.EscapedFragment(), "@")) {
		return SecretMask, true
	}
	if u.User == nil && u.RawQuery == "" {
		if strings.Contains(authority, "@") {
			return SecretMask, true
		}
		if _, query, ok := strings.Cut(beforeFragment, "?"); ok && query != "" {
			return SecretMask, true
		}
		return value, false
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword(SecretMask, SecretMask)
		} else {
			u.User = url.User(SecretMask)
		}
	}
	u.RawQuery = maskQueryValues(u.RawQuery)
	return u.String(), false
}

// hasPortSeparator reports whether a URL host ("host:port", "[v6]:port", or with an
// empty port) has a ":" before its port.
func hasPortSeparator(host string) bool {
	i := strings.LastIndexByte(host, ':')
	return i >= 0 && i > strings.LastIndexByte(host, ']')
}

// findURLEnd returns the end offset in s of the URL whose scheme starts at schemeStart
// and whose "://" ends at afterColonSlash.
func findURLEnd(s string, schemeStart, afterColonSlash int) int {
	urlEnd := len(s)
	searchFrom := afterColonSlash
	for searchFrom < len(s) {
		rel := strings.Index(s[searchFrom:], "://")
		if rel < 0 {
			break
		}
		nextColon := searchFrom + rel
		nextScheme := afterColonSlash + schemeStartAt(s[afterColonSlash:], nextColon-afterColonSlash)
		between := s[afterColonSlash:nextScheme]

		if hashIdx := strings.IndexByte(between, '#'); hashIdx >= 0 {
			urlEnd = afterColonSlash + hashIdx
			break
		}
		if qIdx := strings.IndexByte(between, '?'); qIdx >= 0 {
			// If whitespace separates a standalone second URL (with no '&' continuing
			// an outer query after it), end at that whitespace; otherwise keep the
			// whole query so maskQueryValues masks every parameter, stopping only if a
			// later #fragment itself embeds another URL.
			if wsIdx := strings.IndexFunc(between[qIdx:], func(r rune) bool {
				return r == ' ' || r == '\t' || r == '\r' || r == '\n'
			}); wsIdx >= 0 && !strings.Contains(s[nextScheme:], "&") {
				urlEnd = afterColonSlash + qIdx + wsIdx
				break
			}
			if hashAfter := strings.IndexByte(s[nextScheme:], '#'); hashAfter >= 0 && strings.Contains(s[nextScheme+hashAfter:], "://") {
				urlEnd = nextScheme + hashAfter
			}
			break
		}

		// No '#' or '?' before nextScheme: check for a list separator or path boundary.
		end := nextScheme
		if end > afterColonSlash && s[end-1] == ':' {
			sub := afterColonSlash + schemeStartAt(s[afterColonSlash:], end-1-afterColonSlash)
			if sub < end-1 && sub > afterColonSlash && isURLListSep(s[sub-1]) {
				end = sub
			}
		}
		for end > afterColonSlash && isURLListSep(s[end-1]) {
			end--
		}
		if end < nextScheme {
			urlEnd = end
			break
		}
		if slashIdx := strings.LastIndexByte(between, '/'); slashIdx >= 0 {
			urlEnd = afterColonSlash + slashIdx + 1
			break
		}

		// Still inside authority with no boundary (e.g. unencoded "://" in userinfo):
		// keep together so maskSingleURL fails closed.
		searchFrom = nextColon + 3
	}

	for urlEnd > schemeStart && isASCIIWhitespace(s[urlEnd-1]) {
		urlEnd--
	}
	return urlEnd
}

func schemeStartAt(s string, colonSlash int) int {
	start := colonSlash
	for start > 0 && isSchemeChar(s[start-1]) {
		start--
	}
	for start < colonSlash && !isASCIILetter(s[start]) {
		start++
	}
	return start
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isSchemeChar(b byte) bool {
	return isASCIILetter(b) || (b >= '0' && b <= '9') || b == '+' || b == '-' || b == '.'
}

func isASCIIWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func isURLListSep(b byte) bool {
	return isASCIIWhitespace(b) || b == ',' || b == ';'
}

// urlTemplates are the query values remote lookup replaces per request
// (server/proxy/http_remotelookup.go): placeholders, never credentials.
var urlTemplates = map[string]bool{"$email": true, "$ip": true}

// maskQueryValues masks every non-empty value of a raw query, as written, so a
// percent-encoded value is masked whole. Only "&" separates parameters: a ";" stays
// inside the masked value. A component without "=" is masked whole, since it may
// be a bare token.
func maskQueryValues(rawQuery string) string {
	params := strings.Split(rawQuery, "&")
	for i, param := range params {
		prefix, value := "", param
		if name, v, ok := strings.Cut(param, "="); ok {
			prefix, value = name+"=", v
		}
		if value != "" && !urlTemplates[value] {
			params[i] = prefix + SecretMask
		}
	}
	return strings.Join(params, "&")
}
