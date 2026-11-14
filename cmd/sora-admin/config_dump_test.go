package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/config"
)

const (
	configDumpHelperEnv       = "SORA_ADMIN_CONFIG_DUMP_HELPER_PATH"
	configDumpHelperFormatEnv = "SORA_ADMIN_CONFIG_DUMP_HELPER_FORMAT"
)

// TestConfigDumpCommandHelper is not a test: it is `sora-admin config dump`, run by the
// config dump tests in a process of its own because the command exits on failure.
func TestConfigDumpCommandHelper(t *testing.T) {
	path := os.Getenv(configDumpHelperEnv)
	if path == "" {
		t.Skip("helper process for the config dump tests")
	}
	os.Args = []string{"sora-admin", "--config", path, "config", "dump", "--format", os.Getenv(configDumpHelperFormatEnv)}
	handleConfigDump(context.Background())
}

// runConfigDump runs `sora-admin config dump --format format` on a file holding content
// and returns everything the command wrote.
func runConfigDump(t *testing.T, content []byte, format string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestConfigDumpCommandHelper$")
	cmd.Env = append(os.Environ(), configDumpHelperEnv+"="+path, configDumpHelperFormatEnv+"="+format)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("config dump --format %s failed: %v\n%s", format, err, out)
	}
	return string(out)
}

// TestConfigDumpMasksSecrets: `sora-admin config dump` masks [admin_cli] api_key and
// every auth_token, and still prints the settings next to them (#356).
func TestConfigDumpMasksSecrets(t *testing.T) {
	content := []byte(`
[admin_cli]
addr = "https://admin.example.com:8080"
api_key = "example-admin-key"

[relay]
type = "http"
http_url = "https://relay.example.com/send"
auth_token = "example-relay-token"

[spam_training]
endpoint = "https://spam.example.com/train"
auth_token = "example-spam-token"

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:0"

[server.remote_lookup]
enabled = true
url = "https://lookup.example.com/lookup"
auth_token = "example-lookup-token"
`)
	for _, format := range []string{"toml", "json"} {
		t.Run(format, func(t *testing.T) {
			out := runConfigDump(t, content, format)
			for _, secret := range []string{"example-admin-key", "example-relay-token", "example-spam-token", "example-lookup-token"} {
				if strings.Contains(out, secret) {
					t.Errorf("dump prints the secret %q in clear", secret)
				}
			}
			for _, kept := range []string{"https://admin.example.com:8080", "https://relay.example.com/send", "https://spam.example.com/train", "https://lookup.example.com/lookup"} {
				if !strings.Contains(out, kept) {
					t.Errorf("dump lacks %q, which is not a secret", kept)
				}
			}
		})
	}
}

// secretKey matches the config keys that may hold a secret. A string setting under such a
// key is filled by TestConfigDumpMasksEverySecretField unless notSecretKeys lists it, so
// the test fails when one is added without the `secret:"true"` tag that masks it.
var secretKey = regexp.MustCompile(`(?i)password|passwd|secret|token|key|credential|private`)

// notSecretKeys match secretKey but hold no secret.
var notSecretKeys = map[string]bool{
	"key_file":                          true, // path of a key file
	"tls_key_file":                      true, // path of a key file
	"smtp_tls_key_file":                 true, // path of a key file
	"server_side_encryption_kms_key_id": true, // names a KMS key, is not one
	"token_duration":                    true,
	"token_issuer":                      true,
}

// fillSecrets sets every string setting reachable from v that is tagged `secret:"true"`
// (or sits under such a field) or whose key matches secretKey to a value of its own,
// recorded in filled by key path. Nil pointers are allocated and empty lists get one
// element, so every block is reached.
func fillSecrets(t *testing.T, v reflect.Value, path, key string, secret bool, filled map[string]string) {
	t.Helper()
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		fillSecrets(t, v.Elem(), path, key, secret, filled)
	case reflect.Struct:
		typ := v.Type()
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
			if !f.IsExported() || name == "-" { // "-": internal, never read from the file
				continue
			}
			if name == "" {
				name = f.Name
			}
			fillSecrets(t, v.Field(i), path+"."+name, name, secret || f.Tag.Get("secret") == "true", filled)
		}
	case reflect.Slice:
		if v.Len() == 0 {
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		}
		for i := 0; i < v.Len(); i++ {
			fillSecrets(t, v.Index(i), fmt.Sprintf("%s[%d]", path, i), key, secret, filled)
		}
	case reflect.Map:
		t.Fatalf("%s: neither config.MaskSecrets nor this test walk maps; teach both", path)
	case reflect.String:
		if secret || (secretKey.MatchString(key) && !notSecretKeys[key]) {
			value := fmt.Sprintf("dump-leak-%03d", len(filled))
			v.SetString(value)
			filled[path] = value
		}
	}
}

// TestConfigDumpMasksEverySecretField fills every secret setting of the configuration
// with a value of its own and fails when `sora-admin config dump` prints one of them, so a
// secret setting added later without the `secret:"true"` tag fails here (#356).
func TestConfigDumpMasksEverySecretField(t *testing.T) {
	cfg := config.NewDefaultConfig()
	filled := map[string]string{}
	fillSecrets(t, reflect.ValueOf(&cfg).Elem(), "", "", false, filled)

	// The walk reached the secrets of every kind of block.
	for _, path := range []string{
		".database.write.password", ".database.read.password",
		".s3.access_key", ".s3.secret_key", ".s3.encryption_key",
		".tls.letsencrypt.s3.access_key", ".tls.letsencrypt.s3.secret_key",
		".cluster.secret_key",
		".relay.auth_token", ".spam_training.auth_token", ".admin_cli.api_key",
		".server[0].api_key", ".server[0].read_only_api_key", ".server[0].jwt_secret",
		".server[0].master_password", ".server[0].master_sasl_password",
		".server[0].remote_lookup.auth_token",
	} {
		if _, ok := filled[path]; !ok {
			t.Errorf("secret %s was not filled", path)
		}
	}

	var file bytes.Buffer
	if err := toml.NewEncoder(&file).Encode(cfg); err != nil {
		t.Fatalf("encoding the filled config: %v", err)
	}
	paths := make([]string, 0, len(filled))
	for path, value := range filled {
		if !strings.Contains(file.String(), value) {
			t.Fatalf("secret %s is not written to the config file", path)
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, format := range []string{"toml", "json"} {
		t.Run(format, func(t *testing.T) {
			out := runConfigDump(t, file.Bytes(), format)
			for _, path := range paths {
				if strings.Contains(out, filled[path]) {
					t.Errorf("dump prints %s in clear", path)
				}
			}
		})
	}
}
