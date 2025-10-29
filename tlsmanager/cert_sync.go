package tlsmanager

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/acme/autocert"
)

// CertificateInfo holds parsed certificate information for comparison
type CertificateInfo struct {
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	Subject      string
}

// parseCertificate parses a PEM-encoded certificate and extracts key information
func parseCertificate(certData []byte) (*CertificateInfo, error) {
	// Find the certificate PEM block
	var certPEM *pem.Block
	remaining := certData

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certPEM = block
			break
		}
		remaining = rest
	}

	if certPEM == nil {
		return nil, fmt.Errorf("no certificate PEM block found")
	}

	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertificateInfo{
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Subject:      cert.Subject.String(),
	}, nil
}

// shouldUpdateCertificate determines if the S3 certificate should replace the local one
func shouldUpdateCertificate(localInfo, s3Info *CertificateInfo) bool {
	// If S3 certificate is newer (later NotBefore), update
	if s3Info.NotBefore.After(localInfo.NotBefore) {
		return true
	}

	// If S3 certificate has later expiry (renewed), update
	if s3Info.NotAfter.After(localInfo.NotAfter) {
		return true
	}

	// If different serial numbers and same/older dates, don't update
	// (prevents unnecessary updates)
	return false
}

// extractFallbackCache unwraps cache layers to find the FallbackCache
func extractFallbackCache(cache autocert.Cache) *FallbackCache {
	// Direct check
	if fc, ok := cache.(*FallbackCache); ok {
		return fc
	}

	// Check through FailoverAwareCache wrapper
	if failoverCache, ok := cache.(*FailoverAwareCache); ok {
		// Check if underlying is ClusterAwareCache
		if clusterCache, ok := failoverCache.underlying.(*ClusterAwareCache); ok {
			if fc, ok := clusterCache.underlying.(*FallbackCache); ok {
				return fc
			}
		}
		// Check if underlying is directly FallbackCache
		if fc, ok := failoverCache.underlying.(*FallbackCache); ok {
			return fc
		}
	}

	// Check through ClusterAwareCache wrapper (without FailoverAwareCache)
	if clusterCache, ok := cache.(*ClusterAwareCache); ok {
		if fc, ok := clusterCache.underlying.(*FallbackCache); ok {
			return fc
		}
	}

	return nil
}

// syncCertificateFromS3 checks if a certificate needs updating from S3 and updates if needed
func (m *Manager) syncCertificateFromS3(ctx context.Context, domain string) error {
	// Only sync if we have a fallback cache (which means we have both S3 and local)
	fallbackCache := extractFallbackCache(m.autocertMgr.Cache)
	if fallbackCache == nil {
		// No fallback cache setup, skip sync
		return nil
	}

	// Try to get certificate from local cache
	localData, err := fallbackCache.fallback.Get(ctx, domain)
	if err != nil {
		// No local certificate, try to fetch from S3
		if err == autocert.ErrCacheMiss {
			logger.Debugf("[CertSync] No local certificate for %s, checking S3", domain)
			s3Data, s3Err := fallbackCache.primary.Get(ctx, domain)
			if s3Err == nil {
				// Found in S3, store locally
				if putErr := fallbackCache.fallback.Put(ctx, domain, s3Data); putErr != nil {
					logger.Warnf("[CertSync] Failed to sync certificate from S3 to local cache for %s: %v", domain, putErr)
					return putErr
				}
				logger.Infof("[CertSync] Synced certificate from S3 to local cache: %s", domain)
				return nil
			}
			// Not in S3 either, skip
			return nil
		}
		// Other error reading local cache
		logger.Debugf("[CertSync] Error reading local cache for %s: %v", domain, err)
		return err
	}

	// Try to get certificate from S3
	s3Data, err := fallbackCache.primary.Get(ctx, domain)
	if err != nil {
		if err == autocert.ErrCacheMiss {
			// Not in S3, local is fine
			return nil
		}
		// S3 error, but local works, so not critical
		logger.Debugf("[CertSync] Error reading S3 for %s: %v (local certificate still valid)", domain, err)
		return err
	}

	// Parse both certificates for comparison
	localInfo, err := parseCertificate(localData)
	if err != nil {
		logger.Warnf("[CertSync] Failed to parse local certificate for %s: %v (will update from S3)", domain, err)
		// Can't parse local, assume S3 is better
		if putErr := fallbackCache.fallback.Put(ctx, domain, s3Data); putErr != nil {
			logger.Warnf("[CertSync] Failed to update local certificate from S3 for %s: %v", domain, putErr)
			return putErr
		}
		logger.Infof("[CertSync] Updated certificate from S3 (local parse failed): %s", domain)
		return nil
	}

	s3Info, err := parseCertificate(s3Data)
	if err != nil {
		logger.Warnf("[CertSync] Failed to parse S3 certificate for %s: %v (keeping local)", domain, err)
		return err
	}

	// Compare certificates
	if localInfo.SerialNumber == s3Info.SerialNumber {
		// Same certificate, no update needed
		logger.Debugf("[CertSync] Certificate up to date for %s (serial: %s)", domain, localInfo.SerialNumber)
		return nil
	}

	// Different certificates, check if S3 is newer
	if shouldUpdateCertificate(localInfo, s3Info) {
		logger.Infof("[CertSync] Updating certificate from S3 for %s (local serial: %s, expiry: %s -> S3 serial: %s, expiry: %s)",
			domain, localInfo.SerialNumber, localInfo.NotAfter.Format(time.RFC3339),
			s3Info.SerialNumber, s3Info.NotAfter.Format(time.RFC3339))

		if putErr := fallbackCache.fallback.Put(ctx, domain, s3Data); putErr != nil {
			logger.Warnf("[CertSync] Failed to update local certificate from S3 for %s: %v", domain, putErr)
			return putErr
		}

		logger.Infof("[CertSync] Successfully updated certificate from S3: %s", domain)
		return nil
	}

	// S3 certificate is older or same, keep local
	logger.Debugf("[CertSync] Local certificate is newer for %s (keeping local)", domain)
	return nil
}

// startCertificateSyncWorker starts a background worker that periodically syncs certificates from S3
func (m *Manager) startCertificateSyncWorker(interval time.Duration) {
	if m.config.LetsEncrypt == nil || len(m.config.LetsEncrypt.Domains) == 0 {
		return
	}

	logger.Infof("Starting certificate sync worker (interval: %v)", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

			for _, domain := range m.config.LetsEncrypt.Domains {
				if err := m.syncCertificateFromS3(ctx, domain); err != nil {
					logger.Debugf("[CertSync] Sync failed for %s: %v", domain, err)
				}
			}

			cancel()
		}
	}()
}
