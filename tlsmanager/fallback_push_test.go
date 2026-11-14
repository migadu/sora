package tlsmanager

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestCertificateStoredWhileS3FailsReachesS3: a certificate written while S3 refuses
// writes lands only in the local fallback directory. Until it reaches S3 the other
// nodes never see it - for a new domain their handshakes fail, for a renewal they
// keep the old certificate until it expires - so the sync worker must push it.
func TestCertificateStoredWhileS3FailsReachesS3(t *testing.T) {
	const domain = "mail.example.com"
	ctx := context.Background()

	cases := []struct {
		name  string
		inS3  []byte // what S3 holds before the write fails
		local []byte // what the node then stores
	}{
		{
			name:  "new certificate",
			local: certCacheEntry(t, domain, 2, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)),
		},
		{
			name:  "renewed certificate",
			inS3:  certCacheEntry(t, domain, 1, time.Now().Add(-80*24*time.Hour), time.Now().Add(10*24*time.Hour)),
			local: certCacheEntry(t, domain, 2, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub, endpoint := newStubS3(t)
			m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
				le.FallbackDir = t.TempDir()
			})
			shared := newStubS3Cache(t, endpoint)
			if tc.inS3 != nil {
				if err := shared.Put(ctx, domain, tc.inS3); err != nil {
					t.Fatalf("seeding S3: %v", err)
				}
			}

			stub.failPuts(http.StatusForbidden)
			if err := m.autocertMgr.Cache.Put(ctx, domain, tc.local); err != nil {
				t.Fatalf("storing certificate while S3 fails: %v", err)
			}
			stub.failPuts(0)

			if err := m.syncCertificateFromS3(ctx, domain); err != nil {
				t.Fatalf("certificate sync: %v", err)
			}

			got, err := shared.Get(ctx, domain)
			if err != nil {
				t.Fatalf("certificate stored while S3 failed is not in S3 after a sync: %v", err)
			}
			if !bytes.Equal(got, tc.local) {
				t.Error("S3 holds an older certificate than the one stored while S3 failed")
			}
		})
	}
}
