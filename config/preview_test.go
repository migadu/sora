package config

import (
	"testing"

	"github.com/BurntSushi/toml"
)

func TestPreviewS3BurstDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, limits string
		want         int
	}{
		{"unset", "", 200},
		{"lower per-minute budget", "preview_s3_per_min = 10", 10},
		{"higher per-minute budget", "preview_s3_per_min = 500", 200},
		{"explicit burst", "preview_s3_per_min = 10\npreview_s3_burst = 30", 30},
		{"zero burst uses bounded default", "preview_s3_per_min = 10\npreview_s3_burst = 0", 10},
		{"negative burst uses bounded default", "preview_s3_per_min = 10\npreview_s3_burst = -1", 10},
		{"unlimited rate", "preview_s3_per_min = 0", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg ServerConfig
			if _, err := toml.Decode("[limits]\n"+tc.limits, &cfg); err != nil {
				t.Fatal(err)
			}
			if got := cfg.GetPreviewS3Burst(); got != tc.want {
				t.Errorf("GetPreviewS3Burst() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPreviewS3MaxSizeDefaults(t *testing.T) {
	const cacheMaxSize = 12 << 20
	for _, tc := range []struct {
		name, size string
		want       int64
		wantErr    bool
	}{
		{name: "unset", want: cacheMaxSize},
		{name: "zero inherits cache maximum", size: "0", want: cacheMaxSize},
		{name: "zero with unit inherits cache maximum", size: "0mb", want: cacheMaxSize},
		{name: "custom", size: "2mb", want: 2 << 20},
		{name: "invalid", size: "invalid", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ServerConfig{Limits: &ServerLimitsConfig{PreviewS3MaxSize: tc.size}}
			got, err := cfg.GetPreviewS3MaxSize(cacheMaxSize)
			if (err != nil) != tc.wantErr || (!tc.wantErr && got != tc.want) {
				t.Errorf("GetPreviewS3MaxSize() = %d, %v; want %d, error=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
