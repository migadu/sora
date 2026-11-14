package config

import (
	"bytes"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

const twoDays = 48 * time.Hour

var durationType = reflect.TypeOf(time.Duration(0))

// Every auth_rate_limit duration takes the syntax of the other duration keys,
// whole days included. The toml package parsed these time.Duration fields with
// time.ParseDuration, so "2d" failed to load the whole file (#417).
func TestAuthRateLimitDurationsAcceptDays(t *testing.T) {
	typ := reflect.TypeOf(AuthRateLimiterConfig{})
	n := 0
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Type != durationType {
			continue
		}
		n++
		key := tomlKey(field)
		var cfg Config
		if _, err := toml.Decode("[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \":143\"\n[server.auth_rate_limit]\n"+key+" = \"2d\"\n", &cfg); err != nil {
			t.Errorf("%s = \"2d\": %v", key, err)
			continue
		}
		if got := reflect.ValueOf(*cfg.DynamicServers[0].AuthRateLimit).Field(i).Interface(); got != twoDays {
			t.Errorf("%s = \"2d\" decoded to %v, want %v", key, got, twoDays)
		}
	}
	if n != 8 {
		t.Errorf("found %d duration fields in AuthRateLimiterConfig, want 8", n)
	}
}

// A bare integer has no unit. The toml package took it as nanoseconds, so
// ip_block_duration = 900 blocked an address for 900ns; like an unparsable
// value, it is now an error that names the key.
func TestAuthRateLimitInvalidDurationsRejected(t *testing.T) {
	for _, value := range []string{"900", `"15 minutes"`, `"1w"`} {
		var cfg Config
		_, err := toml.Decode("[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \":143\"\n[server.auth_rate_limit]\nip_block_duration = "+value+"\n", &cfg)
		if err == nil {
			t.Errorf("ip_block_duration = %s: accepted as %v", value, cfg.DynamicServers[0].AuthRateLimit.IPBlockDuration)
			continue
		}
		if !strings.Contains(err.Error(), "ip_block_duration") {
			t.Errorf("ip_block_duration = %s: error %q does not name the key", value, err)
		}
	}
}

// The error names the key and a line of the file, not of the table as
// UnmarshalTOML re-encodes it.
func TestAuthRateLimitInvalidDurationErrorPosition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	content := "[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \":143\"\n\n[server.auth_rate_limit]\nenabled = true\nmax_delay = \"30 seconds\"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	err := LoadConfigFromFile(path, &cfg)
	if err == nil {
		t.Fatal(`max_delay = "30 seconds" loaded without error`)
	}
	msg := err.Error()
	if n := strings.Count(msg, "line "); n != 1 {
		t.Errorf("error names %d lines, want only the file's: %s", n, msg)
	}
	if !strings.Contains(msg, "max_delay") {
		t.Errorf("error does not name the key: %s", msg)
	}
}

// Decoding the table by hand must keep the other keys' behaviour: values of
// every type land in their fields, the dotted form used by config.toml.example
// works, and a misspelt key is still reported.
func TestAuthRateLimitTableDecodesEveryField(t *testing.T) {
	var cfg Config
	if _, err := toml.Decode(`
[[server]]
type = "imap"
name = "imap"
addr = ":143"
auth_rate_limit.enabled = true
auth_rate_limit.max_attempts_per_ip = 7
auth_rate_limit.ip_block_duration = "1d"
auth_rate_limit.delay_multiplier = 1.5
auth_rate_limit.exempt_networks = ["192.0.2.0/24"]
`, &cfg); err != nil {
		t.Fatal(err)
	}
	got := cfg.DynamicServers[0].AuthRateLimit
	want := &AuthRateLimiterConfig{
		Enabled:          true,
		MaxAttemptsPerIP: 7,
		IPBlockDuration:  24 * time.Hour,
		DelayMultiplier:  1.5,
		ExemptNetworks:   []string{"192.0.2.0/24"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decoded %+v, want %+v", *got, *want)
	}

	// exempt_networks = [] (exempt nobody) stays distinct from an absent key.
	var empty Config
	if _, err := toml.Decode("[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \":143\"\n[server.auth_rate_limit]\nexempt_networks = []\n", &empty); err != nil {
		t.Fatal(err)
	}
	if nets := empty.DynamicServers[0].AuthRateLimit.ExemptNetworks; nets == nil || len(nets) != 0 {
		t.Errorf("exempt_networks = [] decoded to %#v, want an empty non-nil list", nets)
	}

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \":143\"\n[server.auth_rate_limit]\nip_blok_duration = \"1d\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	var typo Config
	if err := LoadConfigFromFile(path, &typo); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ip_blok_duration") {
		t.Errorf("unknown auth_rate_limit key not reported; log:\n%s", buf.String())
	}
}

// LoadConfigFromFile trims every string it decodes, so " 2d " is a valid
// lookup_cache duration. The auth_rate_limit durations are parsed while the file
// is decoded, before that trim, and take the same value.
func TestAuthRateLimitDurationIsTrimmed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	content := "[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \":143\"\n\n[server.lookup_cache]\npositive_ttl = \" 2d \"\n\n[server.auth_rate_limit]\nip_block_duration = \" 2d \"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := LoadConfigFromFile(path, &cfg); err != nil {
		t.Fatal(err)
	}
	srv := cfg.DynamicServers[0]
	if got, err := srv.LookupCache.GetPositiveTTL(); err != nil || got != twoDays {
		t.Fatalf(`positive_ttl = " 2d ": got %v, %v; want %v`, got, err, twoDays)
	}
	if got := srv.AuthRateLimit.IPBlockDuration; got != twoDays {
		t.Errorf(`ip_block_duration = " 2d ": got %v, want %v`, got, twoDays)
	}
}

// The lookup_cache durations take days too, and an unparsable value falls back
// to the key's absent default with a WARN naming the key and the server whose
// [server.lookup_cache] it is: every server has its own table (#417, #399).
func TestLookupCacheDurationsAcceptDays(t *testing.T) {
	days := LookupCacheConfig{PositiveTTL: "2d", NegativeTTL: "2d", CleanupInterval: "2d", PositiveRevalidationWindow: "2d"}
	absent := LookupCacheConfig{}
	invalid := LookupCacheConfig{PositiveTTL: "5 min", NegativeTTL: "1w", CleanupInterval: "hourly", PositiveRevalidationWindow: "30"}

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for key, get := range map[string]struct {
		parse       func(*LookupCacheConfig) (time.Duration, error)
		withDefault func(*LookupCacheConfig, string) time.Duration
	}{
		"positive_ttl":                 {(*LookupCacheConfig).GetPositiveTTL, (*LookupCacheConfig).GetPositiveTTLWithDefault},
		"negative_ttl":                 {(*LookupCacheConfig).GetNegativeTTL, (*LookupCacheConfig).GetNegativeTTLWithDefault},
		"cleanup_interval":             {(*LookupCacheConfig).GetCleanupInterval, (*LookupCacheConfig).GetCleanupIntervalWithDefault},
		"positive_revalidation_window": {(*LookupCacheConfig).GetPositiveRevalidationWindow, (*LookupCacheConfig).GetPositiveRevalidationWindowWithDefault},
	} {
		if got, err := get.parse(&days); err != nil || got != twoDays {
			t.Errorf("%s = \"2d\": got %v, %v; want %v", key, got, err, twoDays)
		}
		want, err := get.parse(&absent)
		if err != nil {
			t.Fatalf("absent %s: %v", key, err)
		}
		buf.Reset()
		if got := get.withDefault(&invalid, "imap-backend"); got != want {
			t.Errorf("invalid %s = %v, want the absent-key default %v", key, got, want)
		}
		if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "lookup_cache."+key) || !strings.Contains(out, "imap-backend") {
			t.Errorf("invalid %s: logged %q, want a WARN record naming it and the server", key, out)
		}
	}
}

// Every duration key goes through helpers.ParseDuration. A time.ParseDuration
// call in application code is a key that does not take days (#417); the
// lookup_cache getters, their copies in the backends, the PROXY header timeout
// and the Let's Encrypt windows all were.
func TestDurationsParsedWithHelpersParseDuration(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`\btime\.ParseDuration\(`)
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || rel == filepath.Join("helpers", "parsers.go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(content), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "//") && call.MatchString(line) {
				offenders = append(offenders, rel+":"+strconv.Itoa(i+1)+": "+trimmed)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("time.ParseDuration does not take days; parse durations with helpers.ParseDuration:\n%s", strings.Join(offenders, "\n"))
	}
}

// The toml package decodes a time.Duration field itself, with time.ParseDuration
// and a bare integer as nanoseconds. A struct with such a field must decode its
// table with an UnmarshalTOML method (decodeTable, as AuthRateLimiterConfig
// does) so the field takes the same syntax as every other duration key.
func TestNoDurationFieldDecodedByTheTOMLPackage(t *testing.T) {
	unmarshaler := reflect.TypeOf((*toml.Unmarshaler)(nil)).Elem()
	seen := map[reflect.Type]bool{}
	var walk func(path string, typ reflect.Type)
	walk = func(path string, typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		decodesItself := reflect.PointerTo(typ).Implements(unmarshaler)
		for i := range typ.NumField() {
			field := typ.Field(i)
			key := tomlKey(field)
			if !field.IsExported() || key == "-" {
				continue
			}
			if field.Type == durationType {
				if decodesItself {
					continue
				}
				t.Errorf("%s.%s (%s.%s) is a time.Duration the toml package decodes: it takes neither days nor a unitless-integer check", path, key, typ.Name(), field.Name)
				continue
			}
			walk(path+"."+key, field.Type)
		}
	}
	walk("config", reflect.TypeOf(Config{}))
}
