package config

import (
	"bytes"
	"go/parser"
	"go/token"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every warning the config package logs is a WARN record (#398). logger.Initialize
// makes the server's logger slog's default, which bridges the standard log package
// to it at INFO: a log.Printf("WARNING: ...") line was an INFO record, and with
// [logging] level = "warn" it was not written at all.

// captureWarnings makes slog's default logger write WARN and above to the returned
// buffer, as the server's logger does with level = "warn".
func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevDefault, prevOut, prevFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() {
		slog.SetDefault(prevDefault)
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

func TestInvalidValueDefaultsLogAtWarn(t *testing.T) {
	buf := captureWarnings(t)

	srv := ServerConfig{
		Type:           "imap",
		Name:           "imap",
		AppendLimit:    "50 megabytes",
		MaxScriptSize:  "16 kilobytes",
		MaxMessageSize: "50 megabytes",
		ConnectTimeout: "30 sec",
	}
	cleanup := CleanupConfig{
		GracePeriod:               "two weeks",
		WakeInterval:              "hourly",
		MaxAgeRestriction:         "a year",
		FTSRetention:              "forever",
		HealthStatusRetention:     "a month",
		InstanceLivenessThreshold: "a week",
		PurgePollInterval:         "30 sec",
	}
	nonPositive := CleanupConfig{InstanceLivenessThreshold: "-1h"}
	cache := LocalCacheConfig{
		Capacity:         "1 gigabyte",
		MaxObjectSize:    "5 megabytes",
		PurgeInterval:    "twice a day",
		OrphanCleanupAge: "a month",
		MetricsInterval:  "5 min",
		MetricsRetention: "a month",
	}
	uploader := UploaderConfig{RetryInterval: "30 sec"}

	for _, tt := range []struct {
		key      string // the setting the record must name
		fallback func()
	}{
		{"append limit", func() { srv.GetAppendLimitWithDefault() }},
		{"max script size", func() { srv.GetMaxScriptSizeWithDefault() }},
		{"max message size", func() { srv.GetMaxMessageSizeWithDefault() }},
		{"connect timeout", func() { srv.GetConnectTimeoutWithDefault() }},
		{"grace_period", func() { cleanup.GetGracePeriodWithDefault() }},
		{"wake_interval", func() { cleanup.GetWakeIntervalWithDefault() }},
		{"max_age_restriction", func() { cleanup.GetMaxAgeRestrictionWithDefault() }},
		{"fts_retention", func() { cleanup.GetFTSRetentionWithDefault() }},
		{"health_status_retention", func() { cleanup.GetHealthStatusRetentionWithDefault() }},
		{"instance_liveness_threshold", func() { cleanup.GetInstanceLivenessThresholdWithDefault() }},
		{"instance_liveness_threshold", func() { nonPositive.GetInstanceLivenessThresholdWithDefault() }},
		{"purge_poll_interval", func() { cleanup.GetPurgePollIntervalWithDefault() }},
		{"cache size", func() { cache.GetCapacityWithDefault() }},
		{"cache max object size", func() { cache.GetMaxObjectSizeWithDefault() }},
		{"cache purge interval", func() { cache.GetPurgeIntervalWithDefault() }},
		{"cache orphan cleanup age", func() { cache.GetOrphanCleanupAgeWithDefault() }},
		{"metrics_interval", func() { cache.GetMetricsIntervalWithDefault() }},
		{"metrics_retention", func() { cache.GetMetricsRetentionWithDefault() }},
		{"retry_interval", func() { uploader.GetRetryIntervalWithDefault() }},
	} {
		buf.Reset()
		tt.fallback()
		if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, tt.key) {
			t.Errorf("invalid %s: logged %q, want a WARN record naming it", tt.key, out)
		}
	}
}

// What LoadConfigFromFile reports about the file is a WARN record too, at start-up
// and on a SIGHUP reload.
func TestLoadConfigWarningsLogAtWarn(t *testing.T) {
	for _, tt := range []struct {
		name string
		toml string
		want []string // what the WARN records name
	}{
		{
			name: "unknown key",
			toml: "[cleanup]\ngrace_periood = \"7d\"\n",
			want: []string{"cleanup.grace_periood"},
		},
		{
			name: "unknown key in a table decoded on its own",
			toml: "[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \":1143\"\n\n[server.lookup_cache]\npositive_tll = \"5m\"\n",
			want: []string{"lookup_cache.positive_tll"},
		},
		{
			name: "duplicate key",
			toml: "[cleanup]\ngrace_period = \"7d\"\ngrace_period = \"14d\"\n",
			want: []string{"duplicate", "cleanup.grace_period"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			buf := captureWarnings(t)
			var cfg Config
			if err := LoadServerConfig(path, &cfg); err != nil {
				t.Fatalf("LoadServerConfig: %v", err)
			}
			out := buf.String()
			for _, want := range tt.want {
				if !strings.Contains(out, "level=WARN") || !strings.Contains(out, want) {
					t.Errorf("logged %q, want a WARN record naming %q", out, want)
				}
			}
		})
	}
}

// The standard log package reaches the server log only at INFO, so config logs
// through slog's default logger (warnf) instead.
func TestConfigPackageDoesNotImportStdlibLog(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == "log" {
				t.Errorf("%s imports the standard log package; log through warnf (slog) so a warning is a WARN record", name)
			}
		}
	}
}
