package config

import "testing"

func TestQuotaConfigDefaultStorage(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    int64 // 0 means unlimited (nil)
		wantErr bool
	}{
		{in: ""},
		{in: "   "},
		{in: "10gb", want: 10 << 30},
		{in: "512MB", want: 512 << 20},
		{in: "2048", want: 2048},
		{in: "0", wantErr: true},
		{in: "0gb", wantErr: true},
		{in: "ten gigs", wantErr: true},
	} {
		got, err := QuotaConfig{DefaultStorageQuota: tc.in}.DefaultStorage()
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: want an error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		switch {
		case tc.want == 0 && got != nil:
			t.Errorf("%q: want unlimited, got %d", tc.in, *got)
		case tc.want != 0 && (got == nil || *got != tc.want):
			t.Errorf("%q: want %d, got %v", tc.in, tc.want, got)
		}
	}
}

func TestConfigValidateReportsQuota(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.Quota.DefaultStorageQuota = "0"
	for _, p := range cfg.Validate() {
		if p.Section == "[quota]" {
			return
		}
	}
	t.Fatal("Validate did not report a zero default_storage_quota under [quota]")
}
