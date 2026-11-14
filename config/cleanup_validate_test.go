package config

import (
	"strings"
	"testing"
)

// A negative [cleanup] duration parses, and the server used to start with one without a
// word. fts_retention: delivery then stages a search row only for mail sent after a cutoff
// in the future (none) and the cleaner never prunes (#284). grace_period: every threshold
// lies in the future, so expunged mail and soft-deleted accounts are hard-deleted at the
// next cycle. max_age_restriction and health_status_retention: the cleaner acts only on a
// positive value, so the restriction is off and health rows are never pruned (#667).
// instance_liveness_threshold must be positive: at 0 or below every uploader instance
// would count as gone. Each is refused at start-up. A value that does not parse keeps
// falling back to the absent-key default, like every other duration key.
func TestCleanupConfigValidate(t *testing.T) {
	type tcase struct {
		value   string
		wantErr string // "" = accepted; else a substring of the error
	}
	notNegative := func(key string) []tcase {
		return []tcase{
			{value: ""},
			{value: "0"},
			{value: "0d"},
			{value: "180d"},
			{value: "4320h"},
			{value: "notaduration"},
			{value: "-30d", wantErr: key + ` must not be negative, got "-30d"`},
			{value: "-1h", wantErr: key + ` must not be negative, got "-1h"`},
			{value: "-1s", wantErr: key + ` must not be negative, got "-1s"`},
		}
	}
	for _, k := range []struct {
		key   string
		set   func(*CleanupConfig, string)
		cases []tcase
	}{
		{"grace_period", func(c *CleanupConfig, v string) { c.GracePeriod = v }, notNegative("grace_period")},
		{"max_age_restriction", func(c *CleanupConfig, v string) { c.MaxAgeRestriction = v }, notNegative("max_age_restriction")},
		{"fts_retention", func(c *CleanupConfig, v string) { c.FTSRetention = v }, notNegative("fts_retention")},
		{"health_status_retention", func(c *CleanupConfig, v string) { c.HealthStatusRetention = v }, notNegative("health_status_retention")},
		{"instance_liveness_threshold", func(c *CleanupConfig, v string) { c.InstanceLivenessThreshold = v }, []tcase{
			{value: ""},
			{value: "1s"},
			{value: "7d"},
			{value: "168h"},
			{value: "notaduration"},
			{value: "0", wantErr: `instance_liveness_threshold must be positive, got "0"`},
			{value: "0d", wantErr: `instance_liveness_threshold must be positive, got "0d"`},
			{value: "-7d", wantErr: `instance_liveness_threshold must be positive, got "-7d"`},
			{value: "-1s", wantErr: `instance_liveness_threshold must be positive, got "-1s"`},
		}},
	} {
		for _, tc := range k.cases {
			var c CleanupConfig
			k.set(&c, tc.value)
			err := c.Validate()
			switch {
			case tc.wantErr != "" && err == nil:
				t.Errorf("%s = %q accepted", k.key, tc.value)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("%s = %q: error %q, want it to contain %q", k.key, tc.value, err, tc.wantErr)
			case tc.wantErr == "" && err != nil:
				t.Errorf("%s = %q rejected: %v", k.key, tc.value, err)
			}
		}
	}

	defaults := NewDefaultConfig().Cleanup
	if err := defaults.Validate(); err != nil {
		t.Fatalf("default [cleanup] config rejected: %v", err)
	}
}
