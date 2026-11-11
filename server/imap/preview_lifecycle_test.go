package imap

import (
	"context"
	"testing"

	goimap "github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

func TestPreviewServerLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name         string
		enabled      bool
		disabledCaps []string
		wantActive   bool
	}{
		{name: "disabled", enabled: false, wantActive: false},
		{name: "enabled", enabled: true, wantActive: true},
		{name: "disabled_via_disabled_caps", enabled: true, disabledCaps: []string{"PREVIEW"}, wantActive: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			s, err := New(ctx, t.Name(), "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, nil, nil, IMAPServerOptions{
				LookupCache:  &config.LookupCacheConfig{Enabled: false},
				DisabledCaps: tc.disabledCaps,
				Preview:      PreviewOptions{Enabled: tc.enabled, S3PerMin: 300, S3Burst: 200, S3NodePerMin: 3000},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			p := s.preview
			if p != nil {
				// Ensure a failing lifecycle regression cannot leave its timers
				// alive for the remainder of the test process.
				t.Cleanup(func() {
					p.accountLimit.Stop()
					p.nodeLimit.Stop()
				})
			}
			if got := s.caps.Has(goimap.CapPreview); got != tc.wantActive {
				t.Errorf("PREVIEW advertised = %v, want %v", got, tc.wantActive)
			}
			if !tc.wantActive {
				if p != nil {
					t.Error("inactive PREVIEW initialized cache and limiter state")
				}
				return
			}
			if p == nil || p.accountLimit == nil || p.nodeLimit == nil {
				t.Fatal("enabled PREVIEW has no configured download limiters")
			}
			s.Close()
			// closeOnce is also the idempotence guard for stopping both limiter
			// timers. Observe server.Close's wiring without counting goroutines
			// or adding an exported limiter API solely for tests.
			missedClose := false
			p.closeOnce.Do(func() { missedClose = true })
			if missedClose {
				t.Error("server.Close did not close PREVIEW state")
			}
			s.Close()
		})
	}
}
