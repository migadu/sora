package config

import (
	"net/url"
	"reflect"
	"strings"
)

// SecretMask replaces a secret setting's value in output meant to be read or shared.
const SecretMask = "***MASKED***"

// MaskSecrets replaces, in place, every non-empty string setting of cfg that is tagged
// `secret:"true"`, or sits under such a field, with SecretMask, through nested blocks,
// pointers and lists. An unset secret stays empty, so the output still tells it apart
// from a set one. Mark a new secret setting with the tag rather than masking it at a
// call site; TestConfigDumpMasksEverySecretField in cmd/sora-admin fails for one that
// looks like a secret and is left untagged.
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
	case reflect.String:
		if secret && v.String() != "" {
			v.SetString(SecretMask)
		} else {
			v.SetString(maskURLCredentials(v.String()))
		}
	}
}

// maskURLCredentials masks the credentials a URL can carry: its userinfo (HTTP Basic)
// and the value of every query parameter. Endpoint APIs authenticate with query
// parameters of any name (api_key, token, sig, ...), so no name tells a credential
// from a routing parameter. Parameter names, scheme, host, port, path and fragment
// are kept; a value that is not a URL is returned unchanged.
func maskURLCredentials(value string) string {
	start := strings.Index(value, "://")
	if start < 0 {
		return value
	}
	authority := value[start+3:]
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	beforeFragment, _, _ := strings.Cut(value, "#")
	if !strings.Contains(authority, "@") && !strings.Contains(beforeFragment, "?") {
		return value
	}
	u, err := url.Parse(value)
	if err != nil {
		// The dump accepts unvalidated endpoint strings. Do not print credentials
		// just because another part of their URL has an invalid escape or port.
		return SecretMask
	}
	if u.User == nil && u.RawQuery == "" {
		return value
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword(SecretMask, SecretMask)
		} else {
			u.User = url.User(SecretMask)
		}
	}
	u.RawQuery = maskQueryValues(u.RawQuery)
	return u.String()
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
