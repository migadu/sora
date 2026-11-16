package tlsmanager

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

// cacheWrapper is implemented by the cache layers in this package that wrap another cache
type cacheWrapper interface {
	unwrap() autocert.Cache
}

// extractFallbackCache unwraps cache layers to find the FallbackCache
func extractFallbackCache(cache autocert.Cache) *FallbackCache {
	for {
		switch c := cache.(type) {
		case *FallbackCache:
			return c
		case cacheWrapper:
			cache = c.unwrap()
		default:
			return nil
		}
	}
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
	localData, generation, err := fallbackCache.localSnapshot(ctx, domain)
	if err != nil {
		// No local certificate, try to fetch from S3
		if err == autocert.ErrCacheMiss {
			logger.Debug("CertSync: No local certificate - checking S3", "domain", domain)
			s3Data, s3Generation, s3Err := fallbackCache.primarySnapshot(ctx, domain)
			if s3Err == nil {
				// Found in S3, store locally
				if putErr := fallbackCache.replaceLocalIfSame(ctx, domain, nil, false, s3Data, s3Generation); putErr != nil {
					logger.Warn("CertSync: Failed to sync certificate from S3 to local cache", "domain", domain, "error", putErr)
					return putErr
				}
				logger.Info("CertSync: Synced certificate from S3 to local cache", "domain", domain)
				return nil
			}
			// Not in S3 either, skip
			return nil
		}
		// Other error reading local cache
		logger.Debug("CertSync: Error reading local cache", "domain", domain, "error", err)
		return err
	}

	// Try to get certificate from S3
	s3Data, s3Generation, err := fallbackCache.primarySnapshot(ctx, domain)
	if err != nil {
		if err == autocert.ErrCacheMiss {
			// Only this node has it: it was stored while S3 refused writes.
			return publishLocalSnapshot(ctx, fallbackCache, domain, localData, generation)
		}
		// S3 error, but local works, so not critical
		logger.Debug("CertSync: Error reading S3 (local certificate still valid)", "domain", domain, "error", err)
		return err
	}

	// A successful shared read establishes the current publication generation.
	// Date/serial ordering applies only within that generation: same-second
	// issuance can have identical validity dates on opposite sides of a delete.
	if s3Generation.Known && generation != s3Generation {
		if !generation.Known {
			localFP, _ := certificateFingerprint(localData)
			remoteFP, _ := certificateFingerprint(s3Data)
			if s3Generation.Value == "legacy" {
				chosen := s3Data
				if olderCertificate(s3Data, localData) {
					chosen = localData
				}
				return fallbackCache.replaceLocalIfSame(ctx, domain, localData, true, chosen, s3Generation, generation)
			}
			if localFP != remoteFP {
				if err := fallbackCache.quarantineLocalIfSame(ctx, domain, localData, generation); err != nil {
					return err
				}
				return fallbackCache.replaceLocalIfSame(ctx, domain, nil, false, s3Data, s3Generation)
			}
		}
		return fallbackCache.replaceLocalIfSame(ctx, domain, localData, true, s3Data, s3Generation, generation)
	}

	// Parse both certificates for comparison
	localInfo, err := parseCertificate(localData)
	if err != nil {
		logger.Warn("CertSync: Failed to parse local certificate (will update from S3)", "domain", domain, "error", err)
		// Can't parse local, assume S3 is better
		if putErr := fallbackCache.replaceLocalIfSame(ctx, domain, localData, true, s3Data, s3Generation, generation); putErr != nil {
			logger.Warn("CertSync: Failed to update local certificate from S3", "domain", domain, "error", putErr)
			return putErr
		}
		logger.Info("CertSync: Updated certificate from S3 (local parse failed)", "domain", domain)
		return nil
	}

	s3Info, err := parseCertificate(s3Data)
	if err != nil {
		logger.Warn("CertSync: Failed to parse S3 certificate (keeping local)", "domain", domain, "error", err)
		return err
	}

	// Compare certificates
	if localInfo.SerialNumber == s3Info.SerialNumber {
		// Same certificate, no update needed
		logger.Debug("CertSync: Certificate up to date", "domain", domain, "serial", localInfo.SerialNumber)
		// An exact current shared copy establishes provenance for a legacy local file.
		return fallbackCache.replaceLocalIfSame(ctx, domain, localData, true, s3Data, s3Generation, generation)
	}

	// Different certificates, check if S3 is newer
	if shouldUpdateCertificate(localInfo, s3Info) {
		logger.Info("CertSync: Updating certificate from S3", "domain", domain,
			"local_serial", localInfo.SerialNumber, "local_expiry", localInfo.NotAfter.Format(time.RFC3339),
			"s3_serial", s3Info.SerialNumber, "s3_expiry", s3Info.NotAfter.Format(time.RFC3339))

		if putErr := fallbackCache.replaceLocalIfSame(ctx, domain, localData, true, s3Data, s3Generation, generation); putErr != nil {
			logger.Warn("CertSync: Failed to update local certificate from S3", "domain", domain, "error", putErr)
			return putErr
		}

		logger.Info("CertSync: Successfully updated certificate from S3", "domain", domain)
		return nil
	}

	if shouldUpdateCertificate(s3Info, localInfo) {
		// This node renewed it while S3 refused writes; S3 still holds the old one.
		return publishLocalSnapshot(ctx, fallbackCache, domain, localData, generation)
	}

	logger.Debug("CertSync: Local and S3 certificates differ but neither is newer (keeping both)", "domain", domain)
	return nil
}

// publishLocalCertificate writes a certificate that only this node's local cache holds to
// S3, where the other nodes read it. FallbackCache.Put keeps a certificate locally when S3
// refuses the write and retries S3 once; the sync worker retries every interval after
// that, until the write succeeds.
//
// Publication carries the local entry's original generation through all CAS
// retries. Explicit deletion changes that generation; CLEAN leaves a vacancy in
// the same generation so a valid outage renewal can still publish. Expired or
// revoked snapshots are removed only while both bytes and generation still match.
func publishLocalCertificate(ctx context.Context, fc *FallbackCache, name string, data []byte) error {
	current, g, err := fc.localSnapshot(ctx, name)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, data) {
		return nil
	}
	return publishLocalSnapshot(ctx, fc, name, data, g)
}
func publishLocalSnapshot(ctx context.Context, fc *FallbackCache, name string, data []byte, g publicationGeneration) error {
	if info, err := parseCertificate(data); err == nil && time.Now().After(info.NotAfter) {
		return fc.removeLocalIfSame(ctx, name, data, g)
	}
	if err := fc.primary.Put(generationContext(ctx, g), name, data); err != nil {
		if errors.Is(err, errUnknownCertificateProvenance) {
			return fc.quarantineLocalIfSame(ctx, name, data, g)
		}
		if errors.Is(err, ErrCertificateRevoked) || errors.Is(err, errExpiredCertificate) {
			return fc.removeLocalIfSame(ctx, name, data, g)
		}
		return err
	}
	fc.markS3Available()
	return nil
}

// startCertificateSyncWorker starts a background worker that periodically syncs certificates from S3
func (m *Manager) startCertificateSyncWorker(interval time.Duration) {
	if m.config.LetsEncrypt == nil || len(m.config.LetsEncrypt.Domains) == 0 {
		return
	}

	logger.Info("Starting certificate sync worker", "interval", interval)
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	m.certSyncCancel = cancelWorker
	m.certSyncWG.Add(1)
	go func() {
		defer m.certSyncWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-m.stopCertSync:
				logger.Info("Certificate sync worker stopped")
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(workerCtx, 30*time.Second)

				for _, domain := range m.config.LetsEncrypt.Domains {
					// Sync ECDSA certificate
					if err := m.syncCertificateFromS3(ctx, domain); err != nil {
						logger.Debug("CertSync: Sync failed", "domain", domain, "error", err)
					}
					// Sync RSA certificate
					rsaDomain := domain + "+rsa"
					if err := m.syncCertificateFromS3(ctx, rsaDomain); err != nil {
						logger.Debug("CertSync: Sync failed", "domain", rsaDomain, "error", err)
					}
				}

				cancel()
			}
		}
	}()
}
