package main

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/tlsmanager"
)

func TestTLSCleanRetriesHistoricalPurgeWithoutRemovingRenewal(t *testing.T) {
	const name = "mail.example.com"
	ctx := context.Background()
	stub, endpoint := newVersionedTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	key := "/certs/" + tlsmanager.S3ObjectKey(name)
	expired := tlsCleanAutocertEntry(t, name, false, time.Now().Add(-time.Hour))
	putServerEntry(t, cfg, name, expired)
	stub.failDeletes(http.StatusForbidden)
	if err := cleanTLSCertificates(ctx, cfg, t.TempDir(), false, true); err == nil {
		t.Fatal("historical purge failure was hidden")
	}
	stub.mu.Lock()
	raw := append([]byte(nil), stub.objects[key]...)
	stub.mu.Unlock()
	pending, _, err := tlsmanager.PendingCertificateCleanup(raw)
	_, absent, decodeErr := tlsmanager.DecodeCertificateCacheData(raw)
	if err != nil || decodeErr != nil || !pending || !absent {
		t.Fatalf("failed purge lost its vacancy/intent: pending=%v absent=%v err=%v/%v", pending, absent, err, decodeErr)
	}
	// A genuinely valid outage renewal is allowed without changing the CLEAN generation.
	renewal := tlsCleanAutocertEntry(t, name, false, time.Now().Add(60*24*time.Hour))
	putServerEntry(t, cfg, name, renewal)
	stub.failDeletes(0)
	if err := cleanTLSCertificates(ctx, cfg, t.TempDir(), false, true); err != nil {
		t.Fatal(err)
	}
	stub.mu.Lock()
	raw = append([]byte(nil), stub.objects[key]...)
	versions := append([]tlsStubVersion(nil), stub.versions[key]...)
	stub.mu.Unlock()
	got, absent, err := tlsmanager.DecodeCertificateCacheData(raw)
	pending, _, pendingErr := tlsmanager.PendingCertificateCleanup(raw)
	if err != nil || pendingErr != nil || absent || pending || !bytes.Equal(got, renewal) {
		t.Fatalf("retry lost renewal or intent: bytes=%d absent=%v pending=%v err=%v/%v", len(got), absent, pending, err, pendingErr)
	}
	for _, v := range versions {
		if bytes.Equal(v.data, expired) {
			t.Fatal("expired immutable history survived successful retry")
		}
	}
}
