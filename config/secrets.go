package config

import "reflect"

// SecretMask replaces a secret setting's value in output meant to be read or shared.
const SecretMask = "***MASKED***"

// MaskSecrets replaces, in place, every non-empty string setting of cfg that is tagged
// `secret:"true"`, or sits under such a field, with SecretMask, through nested blocks,
// pointers and lists. An unset secret stays empty, so the output still tells it apart
// from a set one. Mark a new secret setting with the tag rather than masking it at a
// call site; TestConfigDumpMasksEverySecretField in cmd/sora-admin fails for one that
// looks like a secret and is left untagged.
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
		}
	}
}
