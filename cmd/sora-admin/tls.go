package main

// tls.go - Command handlers for TLS certificate management
// Lists certificates from S3 and local cache for debugging

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/storage"
	"github.com/migadu/sora/tlsmanager"
)

func handleTLSCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printTLSUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "list", "ls":
		handleTLSList(ctx)
	case "delete", "del", "rm":
		handleTLSDelete(ctx)
	case "clean":
		handleTLSClean(ctx)
	case "cache", "sync":
		handleTLSCache(ctx)
	case "help", "--help", "-h":
		printTLSUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown tls subcommand: %s\n\n", subcommand)
		printTLSUsage()
		os.Exit(1)
	}
}

func handleTLSList(ctx context.Context) {
	fs := flag.NewFlagSet("tls list", flag.ExitOnError)

	cacheDir := fs.String("cache-dir", "", "Local autocert cache directory (default: from config tls.letsencrypt.fallback_dir or /var/lib/sora/certs)")
	showDetails := fs.Bool("details", false, "Show detailed certificate information")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	fs.Usage = func() {
		fmt.Printf(`List TLS certificates from S3 and local cache

Usage:
  sora-admin tls list [options]

Options:
  --cache-dir string    Local autocert cache directory (default: [tls.letsencrypt] fallback_dir,
                        else /var/lib/sora/certs)
  --details             Show detailed certificate information (expiry, type, etc.)
  --json                Output in JSON format
  --config string       Path to TOML configuration file (required)

This command shows:
  - All certificates stored in S3
  - Whether each certificate is cached locally
  - Certificate type (ECDSA vs RSA)
  - Expiry dates
  - Domain names

Examples:
  sora-admin tls list --config config.toml
  sora-admin tls list --details --config config.toml
  sora-admin tls list --cache-dir /custom/path --config config.toml
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Determine cache directory: flag > config > default
	finalCacheDir := *cacheDir
	if finalCacheDir == "" {
		if globalConfig.TLS.LetsEncrypt != nil && globalConfig.TLS.LetsEncrypt.FallbackDir != "" {
			finalCacheDir = globalConfig.TLS.LetsEncrypt.FallbackDir
		} else {
			finalCacheDir = "/var/lib/sora/certs" // Default
		}
	}

	if err := listTLSCertificates(ctx, globalConfig, finalCacheDir, *showDetails, *jsonOutput); err != nil {
		logger.Fatalf("Failed to list TLS certificates: %v", err)
	}
}

func handleTLSDelete(ctx context.Context) {
	fs := flag.NewFlagSet("tls delete", flag.ExitOnError)

	domain := fs.String("domain", "", "Domain name (e.g., imap.example.com) - deletes both ECDSA and RSA variants")
	s3Key := fs.String("key", "", "S3 key (e.g., autocert/cert-abc123...)")
	cacheDir := fs.String("cache-dir", "", "Local autocert cache directory (default: from config)")
	dryRun := fs.Bool("dry-run", false, "Show what would be deleted without actually deleting")

	fs.Usage = func() {
		fmt.Printf(`Delete a specific TLS certificate

Usage:
  sora-admin tls delete [options]

Options:
  --domain string       Domain name (deletes both ECDSA and RSA variants)
  --key string          S3 key for specific certificate
  --cache-dir string    Local autocert cache directory (default: from config)
  --dry-run             Show what would be deleted without actually deleting
  --config string       Path to TOML configuration file (required)

Examples:
  # Delete both ECDSA and RSA certificates for a domain
  sora-admin tls delete --domain imap.example.com --config config.toml

  # Delete specific certificate by S3 key
  sora-admin tls delete --key autocert/cert-abc123... --config config.toml

  # Dry run to see what would be deleted
  sora-admin tls delete --domain imap.example.com --dry-run --config config.toml

Running servers hold their certificates in their local fallback cache too. The delete
leaves a deletion marker in S3, and at its next certificate sync (sync_interval, default
5m) each server removes its local copy instead of writing it back to S3. A server keeps
serving a certificate it has already loaded until it restarts or renews it.

A replacement is ordered only by a server that may issue (the cluster leader, or each
server without [cluster]) and holds no copy, so restart that server after its next sync.
A server that may not issue and restarts before the replacement is in S3 has no
certificate for the name.
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	if *domain == "" && *s3Key == "" {
		fmt.Fprintln(os.Stderr, "Error: Either --domain or --key must be specified")
		fs.Usage()
		os.Exit(1)
	}

	if *domain != "" && *s3Key != "" {
		fmt.Fprintln(os.Stderr, "Error: Cannot specify both --domain and --key")
		fs.Usage()
		os.Exit(1)
	}

	// Determine cache directory
	finalCacheDir := *cacheDir
	if finalCacheDir == "" {
		if globalConfig.TLS.LetsEncrypt != nil && globalConfig.TLS.LetsEncrypt.FallbackDir != "" {
			finalCacheDir = globalConfig.TLS.LetsEncrypt.FallbackDir
		} else {
			finalCacheDir = "/var/lib/sora/certs"
		}
	}

	if err := deleteTLSCertificate(ctx, globalConfig, finalCacheDir, *domain, *s3Key, *dryRun); err != nil {
		logger.Fatalf("Failed to delete certificate: %v", err)
	}
}

func handleTLSClean(ctx context.Context) {
	fs := flag.NewFlagSet("tls clean", flag.ExitOnError)

	cacheDir := fs.String("cache-dir", "", "Local autocert cache directory (default: from config)")
	dryRun := fs.Bool("dry-run", false, "Show what would be deleted without actually deleting")
	force := fs.Bool("force", false, "Skip confirmation prompt")

	fs.Usage = func() {
		fmt.Printf(`Clean up expired TLS certificates

Usage:
  sora-admin tls clean [options]

Options:
  --cache-dir string    Local autocert cache directory (default: from config)
  --dry-run             Show what would be deleted without actually deleting
  --force               Skip confirmation prompt
  --config string       Path to TOML configuration file (required)

This command deletes only expired certificates from both S3 and local cache.
Running servers do not write expired certificates back to S3.
A certificate a node renews while clean runs is kept: on a bucket that keeps
versions (Backblaze B2 buckets always do) clean deletes only the versions it
found expired, which needs the right to delete object versions. Without a usable
version id, clean requires the object's ETag and conditional DELETE support.
If the object changed it is kept; missing ETags or unsupported conditions fail
safely, without falling back to an unconditional delete.

Examples:
  # Clean expired certificates (with confirmation)
  sora-admin tls clean --config config.toml

  # Dry run to see what would be deleted
  sora-admin tls clean --dry-run --config config.toml

  # Clean without confirmation
  sora-admin tls clean --force --config config.toml
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Determine cache directory
	finalCacheDir := *cacheDir
	if finalCacheDir == "" {
		if globalConfig.TLS.LetsEncrypt != nil && globalConfig.TLS.LetsEncrypt.FallbackDir != "" {
			finalCacheDir = globalConfig.TLS.LetsEncrypt.FallbackDir
		} else {
			finalCacheDir = "/var/lib/sora/certs"
		}
	}

	if err := cleanTLSCertificates(ctx, globalConfig, finalCacheDir, *dryRun, *force); err != nil {
		logger.Fatalf("Failed to clean certificates: %v", err)
	}
}

func handleTLSCache(ctx context.Context) {
	fs := flag.NewFlagSet("tls cache", flag.ExitOnError)

	cacheDir := fs.String("cache-dir", "", "Local autocert cache directory (default: from config)")
	domain := fs.String("domain", "", "Cache specific domain only (defaults to all configured domains)")
	force := fs.Bool("force", false, "Overwrite existing local cache files")

	fs.Usage = func() {
		fmt.Printf(`Sync certificates from S3 to local cache

Usage:
  sora-admin tls cache [options]

Options:
  --cache-dir string    Local autocert cache directory (default: from config)
  --domain string       Cache specific domain only (includes ECDSA and RSA variants)
  --force               Overwrite existing local cache files
  --config string       Path to TOML configuration file (required)

This command downloads certificates from S3 and saves them to the local cache.
Useful for pre-warming cache on new servers or after cache corruption.

Examples:
  # Cache all configured domain certificates
  sora-admin tls cache --config config.toml

  # Cache only a specific domain
  sora-admin tls cache --domain imap.example.com --config config.toml

  # Force overwrite existing cache files
  sora-admin tls cache --force --config config.toml
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Determine cache directory
	finalCacheDir := *cacheDir
	if finalCacheDir == "" {
		if globalConfig.TLS.LetsEncrypt != nil && globalConfig.TLS.LetsEncrypt.FallbackDir != "" {
			finalCacheDir = globalConfig.TLS.LetsEncrypt.FallbackDir
		} else {
			finalCacheDir = "/var/lib/sora/certs"
		}
	}

	if err := cacheTLSCertificates(ctx, globalConfig, finalCacheDir, *domain, *force); err != nil {
		logger.Fatalf("Failed to cache certificates: %v", err)
	}
}

func printTLSUsage() {
	fmt.Printf(`TLS Certificate Management

Usage:
  sora-admin tls <subcommand> [options]

Subcommands:
  list     List certificates from S3 and local cache status
  delete   Delete a specific certificate by domain or S3 key
  clean    Delete expired certificates from S3 and local cache
  cache    Sync certificates from S3 to local cache

Examples:
  sora-admin tls list --config config.toml
  sora-admin tls list --details --config config.toml
  sora-admin tls delete --domain imap.example.com --config config.toml
  sora-admin tls delete --key 9f01dab509f55b97 --config config.toml
  sora-admin tls clean --config config.toml
  sora-admin tls cache --config config.toml

Use 'sora-admin tls <subcommand> --help' for detailed help.
`)
}

type CertificateInfo struct {
	S3Key        string
	Domain       string // display label, e.g. "mail.example.com (RSA)"
	CacheName    string // autocert cache name, "<domain>" or "<domain>+rsa"; "" when unknown
	CertType     string // "ECDSA", "RSA", or "Unknown"
	InLocalCache bool
	LocalPath    string
	Expiry       time.Time
	NotBefore    time.Time
	Subject      string
	Issuer       string
	SerialNumber string
	KeyAlgorithm string
	SigAlgorithm string
}

func listTLSCertificates(ctx context.Context, cfg AdminConfig, cacheDir string, showDetails bool, jsonOutput bool) error {
	// Check TLS configuration
	if cfg.TLS.LetsEncrypt == nil {
		return fmt.Errorf("TLS Let's Encrypt configuration not found (tls.letsencrypt section required)")
	}

	s3cfg := cfg.TLS.LetsEncrypt.S3
	if s3cfg.Bucket == "" {
		return fmt.Errorf("TLS S3 bucket not configured (tls.letsencrypt.s3.bucket required)")
	}

	// Initialize S3 storage using TLS/LetsEncrypt S3 config (NOT the main S3 config)
	endpoint := s3cfg.Endpoint
	if endpoint == "" {
		endpoint = "s3.amazonaws.com"
	}

	// Use default timeout for TLS certificate operations (30 seconds)
	s3Timeout := 30 * time.Second

	s3store, err := storage.New(
		endpoint,
		s3cfg.AccessKey,
		s3cfg.SecretKey,
		s3cfg.Bucket,
		!s3cfg.DisableTLS,
		s3cfg.Debug,
		s3Timeout,
		storage.WithRegion(s3cfg.Region),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 storage: %w", err)
	}

	// List all objects in autocert/ prefix first so legacy autocert/deleted-<hash>
	// markers (which sort after autocert/cert-<hash>) are known before decoding certs.
	prefix := "autocert/"
	objectKeys, knownKeys, err := listAutocertKeys(ctx, s3store)
	if err != nil {
		return fmt.Errorf("error listing S3 objects: %w", err)
	}

	// Collect certificate information
	var certs []CertificateInfo

	for _, key := range objectKeys {
		if err := ctx.Err(); err != nil {
			return err
		}

		logger.Info("Received object from S3", "key", key)

		// Skip non-certificate objects and ACME account private keys
		if !strings.HasPrefix(key, prefix+"cert-") || isACMEAccountKey(key) {
			continue
		}

		certInfo := CertificateInfo{
			S3Key: key,
		}

		// Try to determine domain from key
		// Format: autocert/cert-<sha256(domain)> or autocert/cert-<sha256(domain+rsa)>
		certInfo.Domain, certInfo.CacheName = tryDecodeDomain(key, cfg.TLS.LetsEncrypt.Domains)

		// Download certificate from S3 to parse it
		reader, err := s3store.Get(key)
		if err != nil {
			logger.Warn("Failed to download certificate from S3", "key", key, "error", err)
			certInfo.CertType = "Error"
		} else {
			// Read certificate data
			certData, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				logger.Warn("Failed to read certificate from S3", "key", key, "error", err)
				certInfo.CertType = "Error"
			} else {
				markerData, markerErr := readLegacyDeletionMarker(ctx, s3store, key, certData, knownKeys)
				if markerErr != nil {
					logger.Warn("Failed to read certificate deletion marker from S3", "key", key, "error", markerErr)
					certInfo.CertType = "Error"
				} else {
					decodedData, absent, decodeErr := tlsmanager.DecodeCertificateObjectData(certData, markerData)
					if absent {
						continue
					}
					if decodeErr != nil {
						logger.Warn("Invalid or unproven certificate state in S3", "key", key, "error", decodeErr)
						certInfo.CertType = "Invalid"
					} else {
						parseCertificateData(decodedData, &certInfo)
					}
				}
			}
		}

		// Check if certificate exists in local cache
		certInfo.InLocalCache, certInfo.LocalPath = checkLocalCache(cacheDir, certInfo.CacheName)

		certs = append(certs, certInfo)
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found in S3.")
		return nil
	}

	// Display results
	if jsonOutput {
		return displayCertificatesJSON(certs)
	}

	return displayCertificatesTable(certs, showDetails)
}

// tryDecodeDomain names the object at s3Key by the configured domain (the
// [tls.letsencrypt] domains, loaded as autocert names) whose ECDSA ("<domain>") or RSA
// ("<domain>+rsa") cache entry the server's S3 cache keeps there. It returns the display
// label and that entry's autocert cache name, which is also the name of its file in the
// local fallback cache, so the copy is found even when the object holds no readable
// certificate. The key is a hash of the entry name, so any other object, such as one of
// a domain no longer configured, is labelled by a hash prefix, with no cache name.
func tryDecodeDomain(s3Key string, domains []string) (label, cacheName string) {
	// Extract hash from key: autocert/cert-<hash>
	hash, ok := strings.CutPrefix(s3Key, "autocert/cert-")
	if !ok {
		return "unknown", ""
	}

	for _, domain := range domains {
		switch s3Key {
		case tlsmanager.S3ObjectKey(domain):
			return domain, domain
		case tlsmanager.S3ObjectKey(domain + "+rsa"):
			return domain + " (RSA)", domain + "+rsa"
		}
	}

	// Show at most the first 16 characters. The "..." marks the name as not decoded,
	// even when nothing was cut: parseCertificateData then takes the certificate's own
	// name.
	return hash[:min(len(hash), 16)] + "...", ""
}

// autocertName returns the name autocert caches a domain's certificates under, as the
// server loads its configured domains (config.AutocertName). It refuses names such as
// "." or "..", which must never name the cache directory.
func autocertName(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	name, err := config.AutocertName(domain)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", domain, err)
	}
	return name, nil
}

func parseCertificateData(data []byte, info *CertificateInfo) {
	_ = parseCertificate(data, info)
}

func parseCertificate(data []byte, info *CertificateInfo) error {
	// autocert stores: private key PEM + certificate PEM
	// We need to skip the private key and parse the certificate

	// Try to find certificate PEM block
	var certBlock *pem.Block
	remaining := data

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			certBlock = block
			break
		}

		remaining = rest
	}

	if certBlock == nil {
		info.CertType = "Invalid"
		return errors.New("no CERTIFICATE PEM block found")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		info.CertType = "Parse Error"
		return err
	}

	// Extract information
	info.Expiry = cert.NotAfter
	info.NotBefore = cert.NotBefore
	info.Subject = cert.Subject.String()
	info.Issuer = cert.Issuer.String()
	info.SerialNumber = cert.SerialNumber.String()
	info.KeyAlgorithm = cert.PublicKeyAlgorithm.String()
	info.SigAlgorithm = cert.SignatureAlgorithm.String()
	if info.CacheName == "" {
		// Not a configured domain's entry: find the cache name among the certificate's
		// own names. A configured one is the key's preimage already.
		info.CacheName = autocertCacheName(info.S3Key, cert)
	}

	// Extract actual domain from certificate (if Domain is still a hash)
	if strings.Contains(info.Domain, "...") || info.Domain == "unknown" {
		// Try to get domain from cert.DNSNames (Subject Alternative Names)
		if len(cert.DNSNames) > 0 {
			info.Domain = cert.DNSNames[0]
			// Add RSA suffix if it's an RSA cert
			if cert.PublicKeyAlgorithm == x509.RSA {
				info.Domain += " (RSA)"
			}
		} else if cert.Subject.CommonName != "" {
			// Fallback to CommonName
			info.Domain = cert.Subject.CommonName
			if cert.PublicKeyAlgorithm == x509.RSA {
				info.Domain += " (RSA)"
			}
		}
	}

	// Determine cert type from public key algorithm
	switch cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		info.CertType = "ECDSA"
	case x509.RSA:
		info.CertType = "RSA"
	default:
		info.CertType = cert.PublicKeyAlgorithm.String()
	}

	if info.Expiry.IsZero() {
		return errors.New("certificate has zero expiry")
	}
	return nil
}

// autocertCacheName returns the autocert cache name ("<domain>" or "<domain>+rsa") that
// the certificate stored at s3Key was cached under: the one, among the certificate's own
// names, whose tlsmanager.S3ObjectKey is s3Key. It returns "" when there is none.
func autocertCacheName(s3Key string, cert *x509.Certificate) string {
	for _, domain := range append([]string{cert.Subject.CommonName}, cert.DNSNames...) {
		name, err := config.AutocertName(domain)
		if err != nil {
			continue
		}
		for _, entry := range []string{name, name + "+rsa"} {
			if tlsmanager.S3ObjectKey(entry) == s3Key {
				return entry
			}
		}
	}
	return ""
}

// checkLocalCache reports whether the local fallback cache (an autocert.DirCache, which
// names each file by its cache name) holds the entry cacheName, and its path.
func checkLocalCache(cacheDir string, cacheName string) (bool, string) {
	if cacheName == "" {
		return false, ""
	}
	localPath := filepath.Join(cacheDir, cacheName)
	if _, err := os.Stat(localPath); err != nil {
		return false, ""
	}
	return true, localPath
}

// expiredLocalCopy returns the path of the local fallback cache's entry cacheName, or ""
// when there is none or it holds a certificate still valid at now: the fallback cache
// can hold a renewal that has not reached S3 yet, which clean must keep.
func expiredLocalCopy(cacheDir, cacheName string, now time.Time) (string, error) {
	if cacheName == "" {
		return "", nil
	}
	localPath := filepath.Join(cacheDir, cacheName)
	root, err := os.OpenRoot(cacheDir)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to read local cache file %s: %w", localPath, err)
	}
	defer root.Close()

	var data []byte
	for attempt := 0; attempt < 3; attempt++ {
		linfo, err := root.Lstat(cacheName)
		if os.IsNotExist(err) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("failed to read local cache file %s: %w", localPath, err)
		}
		if !linfo.Mode().IsRegular() {
			return "", fmt.Errorf("failed to read local cache file %s: certificate cache entry %q is not regular", localPath, cacheName)
		}

		f, err := root.OpenFile(cacheName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if os.IsNotExist(err) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("failed to read local cache file %s: %w", localPath, err)
		}
		info, statErr := f.Stat()
		if statErr != nil {
			f.Close()
			return "", fmt.Errorf("failed to read local cache file %s: %w", localPath, statErr)
		}
		if !info.Mode().IsRegular() {
			f.Close()
			return "", fmt.Errorf("failed to read local cache file %s: certificate cache entry %q is not regular", localPath, cacheName)
		}
		if !os.SameFile(linfo, info) {
			f.Close()
			if attempt == 2 {
				return "", fmt.Errorf("failed to read local cache file %s: concurrent entry replacement", localPath)
			}
			continue
		}
		data, err = io.ReadAll(f)
		f.Close()
		if err != nil {
			return "", fmt.Errorf("failed to read local cache file %s: %w", localPath, err)
		}
		break
	}

	var local CertificateInfo
	if err := parseCertificate(data, &local); err != nil {
		return "", fmt.Errorf("failed to parse local cache file %s: %w", localPath, err)
	}
	if !local.Expiry.Before(now) {
		return "", nil
	}
	return localPath, nil
}

func displayCertificatesTable(certs []CertificateInfo, showDetails bool) error {
	fmt.Printf("TLS Certificates\n")
	fmt.Printf("================\n\n")

	if showDetails {
		// Detailed view
		for i, cert := range certs {
			if i > 0 {
				fmt.Println(strings.Repeat("-", 80))
			}

			fmt.Printf("Domain:          %s\n", cert.Domain)
			fmt.Printf("Certificate Type: %s\n", cert.CertType)
			fmt.Printf("S3 Key:          %s\n", cert.S3Key)

			if !cert.Expiry.IsZero() {
				daysUntilExpiry := int(time.Until(cert.Expiry).Hours() / 24)
				expiryStatus := "valid"
				if daysUntilExpiry < 0 {
					expiryStatus = "EXPIRED"
				} else if daysUntilExpiry < 30 {
					expiryStatus = "expiring soon"
				}

				fmt.Printf("Valid From:      %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
				fmt.Printf("Expires:         %s (%d days, %s)\n",
					cert.Expiry.Format("2006-01-02 15:04:05"),
					daysUntilExpiry,
					expiryStatus)
				fmt.Printf("Subject:         %s\n", cert.Subject)
				fmt.Printf("Issuer:          %s\n", cert.Issuer)
				fmt.Printf("Serial Number:   %s\n", cert.SerialNumber)
				fmt.Printf("Key Algorithm:   %s\n", cert.KeyAlgorithm)
				fmt.Printf("Sig Algorithm:   %s\n", cert.SigAlgorithm)
			}

			if cert.InLocalCache {
				fmt.Printf("Local Cache:     [OK] YES (%s)\n", cert.LocalPath)
			} else {
				fmt.Printf("Local Cache:     [FAIL] NO\n")
			}

			fmt.Println()
		}
	} else {
		// Summary view
		fmt.Printf("%-30s %-10s %-15s %-12s %s\n",
			"Domain", "Type", "Expiry", "Local Cache", "S3 Key")
		fmt.Printf("%s\n", strings.Repeat("-", 120))

		for _, cert := range certs {
			expiryStr := "-"
			if !cert.Expiry.IsZero() {
				daysUntilExpiry := int(time.Until(cert.Expiry).Hours() / 24)
				expiryStr = fmt.Sprintf("%d days", daysUntilExpiry)
				if daysUntilExpiry < 0 {
					expiryStr = "EXPIRED"
				}
			}

			cacheStatus := "NO"
			if cert.InLocalCache {
				cacheStatus = "YES"
			}

			fmt.Printf("%-30s %-10s %-15s %-12s %s\n",
				truncateString(cert.Domain, 30),
				cert.CertType,
				expiryStr,
				cacheStatus,
				truncateString(cert.S3Key, 50))
		}

		fmt.Printf("\n")
		fmt.Printf("Total certificates: %d\n", len(certs))
		cachedCount := 0
		for _, cert := range certs {
			if cert.InLocalCache {
				cachedCount++
			}
		}
		fmt.Printf("Cached locally: %d\n", cachedCount)
	}

	return nil
}

func displayCertificatesJSON(certs []CertificateInfo) error {
	// Simple JSON output
	fmt.Println("[")
	for i, cert := range certs {
		fmt.Printf("  {\n")
		fmt.Printf("    \"domain\": %q,\n", cert.Domain)
		fmt.Printf("    \"certType\": %q,\n", cert.CertType)
		fmt.Printf("    \"s3Key\": %q,\n", cert.S3Key)
		fmt.Printf("    \"inLocalCache\": %t,\n", cert.InLocalCache)
		fmt.Printf("    \"localPath\": %q,\n", cert.LocalPath)
		if !cert.Expiry.IsZero() {
			fmt.Printf("    \"expiry\": %q,\n", cert.Expiry.Format(time.RFC3339))
			fmt.Printf("    \"notBefore\": %q,\n", cert.NotBefore.Format(time.RFC3339))
			fmt.Printf("    \"subject\": %q,\n", cert.Subject)
			fmt.Printf("    \"issuer\": %q,\n", cert.Issuer)
			fmt.Printf("    \"serialNumber\": %q,\n", cert.SerialNumber)
			fmt.Printf("    \"keyAlgorithm\": %q,\n", cert.KeyAlgorithm)
			fmt.Printf("    \"sigAlgorithm\": %q\n", cert.SigAlgorithm)
		} else {
			fmt.Printf("    \"expiry\": null\n")
		}
		if i < len(certs)-1 {
			fmt.Printf("  },\n")
		} else {
			fmt.Printf("  }\n")
		}
	}
	fmt.Println("]")

	return nil
}

func deleteTLSCertificate(ctx context.Context, cfg AdminConfig, cacheDir string, domain string, s3Key string, dryRun bool) error {
	// Initialize S3 storage
	if cfg.TLS.LetsEncrypt == nil {
		return fmt.Errorf("TLS Let's Encrypt configuration not found")
	}

	s3cfg := cfg.TLS.LetsEncrypt.S3
	endpoint := s3cfg.Endpoint
	if endpoint == "" {
		endpoint = "s3.amazonaws.com"
	}

	// Use default timeout for TLS certificate operations (30 seconds)
	s3Timeout := 30 * time.Second

	s3store, err := storage.New(
		endpoint,
		s3cfg.AccessKey,
		s3cfg.SecretKey,
		s3cfg.Bucket,
		!s3cfg.DisableTLS,
		s3cfg.Debug,
		s3Timeout,
		storage.WithRegion(s3cfg.Region),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 storage: %w", err)
	}

	var keysToDelete []string // S3 objects that exist
	var localFiles []string   // local cache files that exist
	var marks []string        // certificate keys to mark deleted
	localSnapshots := make(map[string][]byte)

	if domain != "" {
		name, err := autocertName(domain)
		if err != nil {
			return err
		}

		// autocert caches a domain's ECDSA certificate as "<domain>" and its RSA one as
		// "<domain>+rsa". The S3 cache stores each under tlsmanager.S3ObjectKey, the local
		// fallback cache (an autocert.DirCache) as a file with the entry's name. Only what
		// exists is deleted and counted: storage.DeleteContext succeeds for a missing key.
		for _, entry := range []string{name, name + "+rsa"} {
			key := tlsmanager.S3ObjectKey(entry)
			// Marked even when S3 lacks it: a running node may hold a copy it has yet
			// to write to S3, and the domain's certificates are what is being deleted.
			marks = append(marks, key)
			exists, err := tlsObjectDeletable(ctx, s3store, key, nil)
			if err != nil {
				return fmt.Errorf("failed to look up %s in S3: %w", key, err)
			}
			if exists {
				keysToDelete = append(keysToDelete, key)
			}

			localPath := filepath.Join(cacheDir, entry)
			if _, err := os.Lstat(localPath); err == nil {
				if !dryRun {
					data, readErr := tlsmanager.ReadLocalCertificateFile(ctx, localPath)
					if readErr != nil {
						return readErr
					}
					localSnapshots[localPath] = data
				}
				localFiles = append(localFiles, localPath)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("failed to check local cache file %s: %w", localPath, err)
			}
		}

		if len(keysToDelete) == 0 && len(localFiles) == 0 {
			return fmt.Errorf("no certificate found for %s in S3 or in %s", name, cacheDir)
		}

		fmt.Printf("Deleting certificates for domain: %s\n", name)
		for _, key := range keysToDelete {
			fmt.Printf("  S3 object:  %s\n", key)
		}
		for _, localPath := range localFiles {
			fmt.Printf("  Local file: %s\n", localPath)
		}
	} else {
		// Delete by S3 key: a full key, a hash, or a prefix of either. A trailing "..."
		// (as tls list truncates keys) marks a prefix. Any other value is looked up as
		// a key first, so an existing key is deleted even when it is also the prefix
		// of another key, and it is taken as a prefix only when it is not a key.
		searchKey := s3Key
		if strings.HasPrefix(searchKey, "autocert/") && !strings.HasPrefix(searchKey, "autocert/cert-") {
			return fmt.Errorf("key is not a certificate cache entry")
		}
		if !strings.HasPrefix(searchKey, "autocert/") {
			searchKey = "autocert/cert-" + searchKey
		}
		prefix, isPrefix := strings.CutSuffix(searchKey, "...")

		if !isPrefix {
			if isACMEAccountKey(searchKey) {
				return fmt.Errorf("refusing to delete ACME account key %s", searchKey)
			}
			// storage.DeleteContext succeeds for a missing key, so look first: a key
			// that is not there must not be reported as deleted.
			exists, err := tlsObjectDeletable(ctx, s3store, searchKey, nil)
			if err != nil {
				return fmt.Errorf("failed to look up %s in S3: %w", searchKey, err)
			}
			if exists {
				keysToDelete = []string{searchKey}
				fmt.Printf("Deleting certificate: %s\n", searchKey)
			}
		}

		if len(keysToDelete) == 0 {
			// Search for matching certificates by prefix
			fmt.Printf("Searching for certificates matching prefix: %s\n", searchKey)

			objectKeys, knownKeys, err := listAutocertKeys(ctx, s3store)
			if err != nil {
				return fmt.Errorf("error searching S3: %w", err)
			}

			var matches []string
			for _, key := range objectKeys {
				if err := ctx.Err(); err != nil {
					return err
				}
				if !strings.HasPrefix(key, "autocert/cert-") || isACMEAccountKey(key) {
					continue
				}
				if strings.HasPrefix(key, prefix) {
					active, err := tlsObjectDeletable(ctx, s3store, key, knownKeys)
					if err != nil {
						return err
					}
					if active {
						matches = append(matches, key)
					}
				}
			}

			if len(matches) == 0 {
				return fmt.Errorf("no certificates found matching prefix: %s", searchKey)
			}

			if len(matches) > 1 {
				fmt.Printf("\nFound %d matching certificates:\n", len(matches))
				for _, match := range matches {
					fmt.Printf("  - %s\n", match)
				}
				return fmt.Errorf("prefix is ambiguous, please provide more characters to uniquely identify the certificate")
			}

			keysToDelete = matches
			fmt.Printf("Found matching certificate: %s\n", matches[0])
		}
	}

	if dryRun {
		fmt.Println("\nDRY RUN - No changes will be made")
		return nil
	}

	if domain == "" {
		marks = keysToDelete
	}
	cache, err := tlsmanager.OpenS3Cache(s3cfg)
	if err != nil {
		return fmt.Errorf("failed to open the certificate cache: %w", err)
	}
	if err := markDeleted(ctx, cache, marks); err != nil {
		return err
	}

	var failures []error
	deleted := len(keysToDelete)
	for _, key := range keysToDelete {
		logger.Info("Deleted certificate from S3 with a persistent revocation fence", "key", key)
	}

	removed := 0
	for _, localPath := range localFiles {
		didRemove, err := tlsmanager.RemoveLocalCertificateIfSame(ctx, localPath, localSnapshots[localPath])
		if err != nil {
			failures = append(failures, fmt.Errorf("local file %s: %w", localPath, err))
			continue
		}
		if didRemove {
			removed++
		}
	}

	fmt.Printf("\nDeleted %d certificate(s) from S3 and %d file(s) from the local cache\n", deleted, removed)
	if len(failures) > 0 {
		return fmt.Errorf("%d deletion(s) failed: %w", len(failures), errors.Join(failures...))
	}
	return nil
}

func cleanTLSCertificates(ctx context.Context, cfg AdminConfig, cacheDir string, dryRun bool, force bool) error {
	// Initialize S3 storage
	if cfg.TLS.LetsEncrypt == nil {
		return fmt.Errorf("TLS Let's Encrypt configuration not found")
	}

	s3cfg := cfg.TLS.LetsEncrypt.S3
	endpoint := s3cfg.Endpoint
	if endpoint == "" {
		endpoint = "s3.amazonaws.com"
	}

	// Use default timeout for TLS certificate operations (30 seconds)
	s3Timeout := 30 * time.Second

	s3store, err := storage.New(
		endpoint,
		s3cfg.AccessKey,
		s3cfg.SecretKey,
		s3cfg.Bucket,
		!s3cfg.DisableTLS,
		s3cfg.Debug,
		s3Timeout,
		storage.WithRegion(s3cfg.Region),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 storage: %w", err)
	}

	// List all objects in autocert/ first so legacy autocert/deleted-<hash> markers
	// are known before inspecting autocert/cert-<hash> entries.
	prefix := "autocert/"
	objectKeys, knownKeys, err := listAutocertKeys(ctx, s3store)
	if err != nil {
		return fmt.Errorf("error listing S3 objects: %w", err)
	}

	var expiredCerts []expiredCertificate
	now := time.Now()

	// clean fails if it could not read a certificate (it cannot tell whether that one
	// expired) or delete an expired one; it still cleans everything else.
	var failures []error
	failed := func() error {
		if len(failures) == 0 {
			return nil
		}
		return fmt.Errorf("%d operation(s) failed: %w", len(failures), errors.Join(failures...))
	}

	for _, key := range objectKeys {
		if err := ctx.Err(); err != nil {
			return err
		}

		// Skip non-certificate objects
		if !strings.HasPrefix(key, prefix+"cert-") {
			continue
		}

		certInfo := CertificateInfo{
			S3Key: key,
		}
		certInfo.Domain, certInfo.CacheName = tryDecodeDomain(key, cfg.TLS.LetsEncrypt.Domains)

		// autocert stores its ACME account key under "acme_account+key" (or legacy
		// "acme_account.key"), which S3Cache hashes under autocert/cert- as a
		// private-key-only PEM entry with no certificate.
		if isACMEAccountKey(key) {
			continue
		}

		// Download and parse certificate to check expiry
		certData, version, etag, err := readTLSObject(ctx, s3store, key)
		if err != nil {
			logger.Warn("Failed to download certificate", "key", key, "error", err)
			failures = append(failures, fmt.Errorf("read S3 object %s: %w", key, err))
			continue
		}

		markerData, markerErr := readLegacyDeletionMarker(ctx, s3store, key, certData, knownKeys)
		if markerErr != nil {
			logger.Warn("Failed to read certificate deletion marker", "key", key, "error", markerErr)
			failures = append(failures, fmt.Errorf("read S3 deletion marker for %s: %w", key, markerErr))
			continue
		}
		pending, pendingExpiry, pendingErr := tlsmanager.PendingCertificateCleanup(certData)
		if pendingErr != nil {
			failures = append(failures, fmt.Errorf("decode S3 object %s: %w", key, pendingErr))
			continue
		}
		decodedData, absent, decodeErr := tlsmanager.DecodeCertificateObjectData(certData, markerData)
		if decodeErr != nil {
			failures = append(failures, fmt.Errorf("decode S3 object %s: %w", key, decodeErr))
			continue
		}
		if absent {
			if pending {
				certInfo.Expiry = pendingExpiry
				certInfo.CertType = "pending history"
				expiredCerts = append(expiredCerts, expiredCertificate{CertificateInfo: certInfo, historyOnly: true})
			}
			continue
		}
		if err := parseCertificate(decodedData, &certInfo); err != nil {
			logger.Warn("Failed to parse certificate", "key", key, "error", err)
			failures = append(failures, fmt.Errorf("parse S3 object %s: %w", key, err))
			continue
		}

		// Check if expired
		if certInfo.Expiry.Before(now) {
			expiredCerts = append(expiredCerts, expiredCertificate{
				CertificateInfo:   certInfo,
				version:           version,
				etag:              etag,
				hasPendingHistory: pending,
			})
		} else if pending {
			certInfo.Expiry = pendingExpiry
			certInfo.CertType = "pending history"
			expiredCerts = append(expiredCerts, expiredCertificate{CertificateInfo: certInfo, historyOnly: true})
		}
	}

	if len(expiredCerts) == 0 {
		fmt.Println("No expired certificates found.")
		return failed()
	}

	// The local fallback cache keeps a certificate under its autocert cache name.
	for i := range expiredCerts {
		cert := &expiredCerts[i]
		if cert.historyOnly {
			continue
		}
		if cert.CacheName == "" {
			logger.Warn("Cannot tell the local cache name of an expired certificate, leaving the local cache alone for it", "key", cert.S3Key)
			continue
		}
		localPath, err := expiredLocalCopy(cacheDir, cert.CacheName, now)
		if err != nil {
			logger.Warn("Failed to inspect local cache file, leaving it alone", "path", filepath.Join(cacheDir, cert.CacheName), "error", err)
			failures = append(failures, err)
			continue
		}
		cert.LocalPath = localPath
		cert.InLocalCache = localPath != ""
	}

	// Display expired certificates
	fmt.Printf("Found %d expired certificate(s):\n\n", len(expiredCerts))
	for _, cert := range expiredCerts {
		expiredDays := int(now.Sub(cert.Expiry).Hours() / 24)
		fmt.Printf("  %s (%s) - expired %d days ago\n", cert.Domain, cert.CertType, expiredDays)
		if cert.InLocalCache {
			fmt.Printf("    local copy: %s\n", cert.LocalPath)
		}
	}

	if dryRun {
		fmt.Println("\nDRY RUN - No changes will be made")
		return failed()
	}

	// Confirm deletion
	if !force {
		fmt.Printf("\nDelete these %d expired certificate(s)? [y/N]: ", len(expiredCerts))
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" && response != "yes" {
			fmt.Println("Cancelled.")
			return failed()
		}
	}

	cache, err := tlsmanager.OpenS3Cache(s3cfg)
	if err != nil {
		return err
	}
	// Clean does not revoke the name: a node may hold a valid replacement that
	// S3 has not received. Each delete is tied to the object found expired.
	deleted, removed := 0, 0
	for _, cert := range expiredCerts {
		gone := false
		var err error
		if !cert.historyOnly {
			gone, err = cache.ExpireObject(ctx, cert.S3Key, cert.etag, now, cert.version)
			if err == nil && !gone && cert.version != "" {
				err = cache.QueueExpiredVersion(ctx, cert.S3Key, cert.version, cert.Expiry)
			}
		}
		if err == nil && (cert.historyOnly || cert.hasPendingHistory || cert.version != "") {
			cleaned, cleanErr := cache.CleanupExpiredVersions(ctx, cert.S3Key, now)
			err = cleanErr
			gone = gone || cleaned > 0
		}

		if err != nil {
			logger.Warn("Failed to delete certificate from S3", "key", cert.S3Key, "error", err)
			failures = append(failures, fmt.Errorf("delete S3 object %s: %w", cert.S3Key, err))
		} else if gone {
			logger.Info("Deleted expired certificate from S3", "key", cert.S3Key, "domain", cert.Domain)
			deleted++
		}

		if !cert.InLocalCache {
			continue
		}
		gone, err = removeExpiredLocalCopy(cert.LocalPath, now)
		if err != nil {
			logger.Warn("Failed to delete certificate from local cache", "path", cert.LocalPath, "error", err)
			failures = append(failures, fmt.Errorf("delete local file %s: %w", cert.LocalPath, err))
			continue
		}
		if gone {
			logger.Info("Deleted expired certificate from local cache", "path", cert.LocalPath)
			removed++
		}
	}

	fmt.Printf("\nDeleted %d expired certificate(s) from S3 and %d file(s) from the local cache\n", deleted, removed)
	return failed()
}

// expiredCertificate identifies the S3 object clean read and found expired.
type expiredCertificate struct {
	CertificateInfo
	version           string
	etag              string
	historyOnly       bool
	hasPendingHistory bool
}

// readTLSObject downloads the object at key with its opaque ETag and the version the
// bucket served, or "" when the bucket keeps no versions. A bucket whose versioning is
// suspended names the version "null", which every write replaces in place: that does
// not identify what was read, so it counts as none.
func readTLSObject(ctx context.Context, s3store *storage.S3Storage, key string) ([]byte, string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, s3store.Timeout)
	defer cancel()
	out, err := s3store.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s3store.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, "", "", err
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, "", "", err
	}
	version := aws.ToString(out.VersionId)
	if version == "null" {
		version = ""
	}
	return data, version, aws.ToString(out.ETag), nil
}

// removeExpiredLocalCopy inspects a regular local snapshot and removes it under
// the shared entry lease only if its bytes still match. A concurrent replacement
// remains canonical; no rename-aside window makes the entry temporarily missing.
func removeExpiredLocalCopy(path string, now time.Time) (removed bool, err error) {
	linfo, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !linfo.Mode().IsRegular() {
		return false, fmt.Errorf("certificate cache entry %q is not regular", filepath.Base(path))
	}
	data, err := tlsmanager.ReadLocalCertificateFile(context.Background(), path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var info CertificateInfo
	if err := parseCertificate(data, &info); err != nil {
		return false, err
	}
	if !info.Expiry.Before(now) {
		return false, nil
	}
	return tlsmanager.RemoveLocalCertificateIfSame(context.Background(), path, data)
}

// writeLocalCacheFile stores data as the local cache file path the way autocert.DirCache
// does: it writes a temporary file in the same directory and renames it over path, so a
// write that fails part-way (the disk fills) leaves no partial file under the cache name,
// which a later run would skip as already cached and the server would read. The new file
// keeps the permissions of the file it replaces, as writing in place would. It is given
// to dirOwner, the owner of the cache directory when that is another user (see
// cacheTLSCertificates), before it gets its name, so the server never sees a cache name
// it cannot open. Without one it keeps the owner and group of the file it replaces, so
// tls cache --force preserves the server's access to an existing cache.
func writeLocalCacheFile(path string, data []byte, dirOwner *fileOwner) error {
	return writeLocalCacheFileContext(context.Background(), path, data, dirOwner)
}
func writeLocalCacheFileContext(ctx context.Context, path string, data []byte, dirOwner *fileOwner) error {
	return tlsmanager.WriteLocalCertificateFile(ctx, path, data, func(f *os.File, old os.FileInfo) error {
		mode := fs.FileMode(0600)
		if old != nil {
			mode = old.Mode().Perm()
		}
		if dirOwner != nil {
			if err := chownFile(f, dirOwner.uid, dirOwner.gid); err != nil {
				return err
			}
		} else if old != nil {
			if err := takeOwner(f, old); err != nil {
				return err
			}
		}
		return f.Chmod(mode)
	})
}

// takeOwner gives f the owner and group of the file old, if it has others.
func takeOwner(f *os.File, old os.FileInfo) error {
	want, ok := old.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if have, ok := info.Sys().(*syscall.Stat_t); ok && have.Uid == want.Uid && have.Gid == want.Gid {
		return nil
	}
	return chownFile(f, int(want.Uid), int(want.Gid))
}

// geteuid is os.Geteuid and chownFile (*os.File).Chown. Only root can give a file to
// another user, so tests replace them to reach that path and record the hand-over.
var (
	geteuid   = os.Geteuid
	chownFile = (*os.File).Chown
)

// fileOwner is the user and group tls cache gives a file or directory it creates.
type fileOwner struct {
	uid, gid int
}

// foreignOwner returns the owner of the file info describes when that is not the user
// this process runs as, and nil when it is.
func foreignOwner(info os.FileInfo) *fileOwner {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) == geteuid() {
		return nil
	}
	return &fileOwner{uid: int(st.Uid), gid: int(st.Gid)}
}

// makeCacheDir creates dir, and each missing parent, with mode 0700, as the server
// creates its fallback directory (tlsmanager.NewFallbackCache). Each directory it creates
// is given the owner of the directory it is created in, when that is another user: run
// as root on a node whose server runs as its own user, it would otherwise leave a
// root-owned directory the server cannot write, where the default /var/lib/sora/certs
// is made in the server's /var/lib/sora (the StateDirectory of dist/sora.service). In a
// sticky directory such as /tmp each user's entries are their own, so what is made in
// one stays its maker's.
func makeCacheDir(dir string) error {
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return &fs.PathError{Op: "mkdir", Path: dir, Err: syscall.ENOTDIR}
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	// Resolve configured parent symlinks once, then keep that directory open through
	// creation and hand-over. Its owner may replace an ancestor after Mkdir; opening
	// dir by its full path then could give an unrelated directory away instead.
	// Split without cleaning the parent: a configured symlink followed by ".."
	// must retain its filesystem meaning. Ignore trailing separators on a new leaf.
	dir = strings.TrimRight(dir, string(filepath.Separator))
	parentPath, name := filepath.Split(dir)
	if parentPath == "" {
		parentPath = "."
	}
	parent, err := os.OpenRoot(parentPath)
	if errors.Is(err, fs.ErrNotExist) && parentPath != dir {
		if err = makeCacheDir(parentPath); err == nil {
			parent, err = os.OpenRoot(parentPath)
		}
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	if name == "." || name == ".." {
		// Creating a missing prefix can make a terminal dot component resolve.
		// It names an existing directory, so validate it without any hand-over.
		_, err := os.Stat(dir)
		return err
	}
	err = parent.Mkdir(name, 0700)
	if errors.Is(err, fs.ErrExist) {
		info, statErr := parent.Stat(name)
		if statErr == nil && !info.IsDir() {
			statErr = &fs.PathError{Op: "mkdir", Path: dir, Err: syscall.ENOTDIR}
		}
		return statErr
	}
	if err != nil {
		return err
	}

	parentInfo, err := parent.Stat(".")
	if err == nil && parentInfo.Mode()&fs.ModeSticky == 0 {
		if owner := foreignOwner(parentInfo); owner != nil {
			if err = giveDir(parent, name, owner); err != nil {
				err = fmt.Errorf("give %s to the owner of %s (%d:%d): %w", dir, filepath.Dir(dir), owner.uid, owner.gid, err)
			}
		}
	}
	if err != nil {
		parent.Remove(name)
	}
	return err
}

// giveDir gives the directory name, just created under the held parent, to owner.
// Neither an ancestor replacement nor a leaf symlink may redirect the hand-over.
func giveDir(parent *os.Root, name string, owner *fileOwner) error {
	f, err := parent.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return chownFile(f, owner.uid, owner.gid)
}

// markDeleted atomically replaces each selected entry with its authoritative,
// key-free revocation generation. The legacy timestamp is compatibility metadata;
// no physical name deletion may subsequently erase the generation barrier.
func markDeleted(ctx context.Context, cache *tlsmanager.S3Cache, keys []string) error {
	at := time.Now()
	for _, key := range keys {
		if err := cache.MarkDeleted(ctx, key, at); err != nil {
			return err
		}
	}
	return nil
}

func cacheTLSCertificates(ctx context.Context, cfg AdminConfig, cacheDir string, specificDomain string, force bool) error {
	// Initialize S3 storage
	if cfg.TLS.LetsEncrypt == nil {
		return fmt.Errorf("TLS Let's Encrypt configuration not found")
	}

	if len(cfg.TLS.LetsEncrypt.Domains) == 0 {
		return fmt.Errorf("no domains configured in tls.letsencrypt.domains")
	}

	s3cfg := cfg.TLS.LetsEncrypt.S3
	endpoint := s3cfg.Endpoint
	if endpoint == "" {
		endpoint = "s3.amazonaws.com"
	}

	// Use default timeout for TLS certificate operations (30 seconds)
	s3Timeout := 30 * time.Second

	s3store, err := storage.New(
		endpoint,
		s3cfg.AccessKey,
		s3cfg.SecretKey,
		s3cfg.Bucket,
		!s3cfg.DisableTLS,
		s3cfg.Debug,
		s3Timeout,
		storage.WithRegion(s3cfg.Region),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 storage: %w", err)
	}

	// The server reads and writes the cache directory as its own user (User=sora in
	// dist/sora.service), while tls cache is usually run as root: what it creates goes to
	// the owner of the directory it is created in, when that is another user, or the
	// server cannot read the certificates nor, in a directory created here, write its own.
	if err := makeCacheDir(cacheDir); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	dirInfo, err := os.Stat(cacheDir)
	if err != nil {
		return fmt.Errorf("failed to read the cache directory: %w", err)
	}
	dirOwner := foreignOwner(dirInfo)

	// Determine which domains to cache
	var domainsToCache []string
	if specificDomain != "" {
		name, err := autocertName(specificDomain)
		if err != nil {
			return err
		}
		domainsToCache = []string{name}
	} else {
		domainsToCache = cfg.TLS.LetsEncrypt.Domains
	}

	fmt.Printf("Caching certificates to: %s\n\n", cacheDir)

	cached := 0
	skipped := 0
	expired := 0
	notFound := 0
	now := time.Now()

	// A certificate that could not be downloaded or written fails the command, so a
	// script pre-warming a node's cache can tell; the others are still cached.
	var failures []error

	for _, configured := range domainsToCache {
		// Honor cancellation between domains (each iteration may issue slow S3 downloads)
		if err := ctx.Err(); err != nil {
			return err
		}

		domain, err := autocertName(configured)
		if err != nil {
			// autocert.HostWhitelist drops such a configured domain silently and the
			// server serves the others, so skip it rather than stop syncing them.
			logger.Warn("Skipping configured domain autocert cannot serve", "domain", configured, "error", err)
			continue
		}

		// Cache both ECDSA and RSA variants
		variants := []struct {
			name string
			key  string
		}{
			{"ECDSA", domain},
			{"RSA", domain + "+rsa"},
		}

		for _, variant := range variants {
			s3Key := tlsmanager.S3ObjectKey(variant.key)

			// Download from S3
			reader, err := s3store.Get(s3Key)
			if err != nil {
				// Only NoSuchKey, S3's answer for an object that does not exist, means the
				// variant is absent. The message is the provider's free text: matching it
				// for "not found" passed a missing bucket or a refusal off as absent and
				// exited 0 without caching anything.
				var noSuchKey *types.NoSuchKey
				if errors.As(err, &noSuchKey) {
					logger.Info("Certificate not found in S3", "domain", domain, "type", variant.name)
					notFound++
				} else {
					logger.Warn("Failed to download certificate from S3", "domain", domain, "type", variant.name, "error", err)
					failures = append(failures, fmt.Errorf("download %s certificate for %s (S3 object %s): %w", variant.name, domain, s3Key, err))
				}
				continue
			}

			certData, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				logger.Warn("Failed to read certificate from S3", "domain", domain, "type", variant.name, "error", err)
				failures = append(failures, fmt.Errorf("read %s certificate for %s (S3 object %s): %w", variant.name, domain, s3Key, err))
				continue
			}

			objectData := certData
			markerData, markerErr := readLegacyDeletionMarker(ctx, s3store, s3Key, objectData, nil)
			if markerErr != nil {
				logger.Warn("Failed to read certificate deletion marker from S3", "domain", domain, "type", variant.name, "error", markerErr)
				failures = append(failures, fmt.Errorf("read %s certificate deletion marker for %s (S3 object %s): %w", variant.name, domain, s3Key, markerErr))
				continue
			}
			certData, absent, decodeErr := tlsmanager.DecodeCertificateObjectData(objectData, markerData)
			if decodeErr != nil {
				failures = append(failures, fmt.Errorf("decode %s certificate for %s (S3 object %s): %w", variant.name, domain, s3Key, decodeErr))
				continue
			}
			if absent {
				notFound++
				continue
			}
			// Parse to check expiry
			certInfo := CertificateInfo{}
			if err := parseCertificate(certData, &certInfo); err != nil {
				logger.Warn("Failed to parse certificate from S3", "domain", domain, "type", variant.name, "key", s3Key, "error", err)
				failures = append(failures, fmt.Errorf("parse %s certificate for %s (S3 object %s): %w", variant.name, domain, s3Key, err))
				continue
			}

			// Skip if expired
			if !certInfo.Expiry.IsZero() && certInfo.Expiry.Before(now) {
				expiredDays := int(now.Sub(certInfo.Expiry).Hours() / 24)
				logger.Info("Skipping expired certificate", "domain", domain, "type", variant.name, "expired_days", expiredDays)
				expired++
				continue
			}

			// Determine local cache filename
			cacheFile := variant.key
			localPath := filepath.Join(cacheDir, cacheFile)

			// Check if file exists and skip if not forcing
			if !force {
				if _, err := os.Stat(localPath); err == nil {
					logger.Info("Certificate already cached (use --force to overwrite)", "domain", domain, "type", variant.name)
					skipped++
					continue
				}
			}

			// Write to local cache
			if err := writeLocalCacheFileContext(ctx, localPath, objectData, dirOwner); err != nil {
				logger.Warn("Failed to write certificate to local cache", "path", localPath, "error", err)
				failures = append(failures, fmt.Errorf("write %s certificate for %s to %s: %w", variant.name, domain, localPath, err))
				continue
			}

			expiryDays := int(certInfo.Expiry.Sub(now).Hours() / 24)
			logger.Info("Cached certificate", "domain", domain, "type", variant.name, "expiry_days", expiryDays)
			cached++
		}
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Cached:    %d certificate(s)\n", cached)
	if skipped > 0 {
		fmt.Printf("  Skipped:   %d (already cached, use --force to overwrite)\n", skipped)
	}
	if expired > 0 {
		fmt.Printf("  Expired:   %d (not cached)\n", expired)
	}
	if notFound > 0 {
		fmt.Printf("  Not found: %d (not in S3)\n", notFound)
	}
	if len(failures) > 0 {
		fmt.Printf("  Failed:    %d (not cached)\n", len(failures))
		return fmt.Errorf("%d certificate(s) could not be cached: %w", len(failures), errors.Join(failures...))
	}

	// A configured domain with neither certificate in S3 has not been issued yet, which
	// is normal in a run over all of them. A domain named with --domain that has none
	// fails the command, as tls delete --domain does.
	if specificDomain != "" && cached+skipped+expired == 0 {
		return fmt.Errorf("no certificate found for %s in S3", domainsToCache[0])
	}

	return nil
}

func isACMEAccountKey(s3Key string) bool {
	return s3Key == tlsmanager.S3ObjectKey("acme_account+key") || s3Key == tlsmanager.S3ObjectKey("acme_account.key")
}

func listAutocertKeys(ctx context.Context, s3store *storage.S3Storage) ([]string, map[string]struct{}, error) {
	objChan, errChan := s3store.ListObjects(ctx, "autocert/", false)
	var keys []string
	known := make(map[string]struct{})
	for objChan != nil || errChan != nil {
		select {
		case obj, ok := <-objChan:
			if !ok {
				objChan = nil
				continue
			}
			keys = append(keys, obj.Key)
			known[obj.Key] = struct{}{}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
				continue
			}
			if err != nil {
				return nil, nil, err
			}
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	return keys, known, nil
}

func readLegacyDeletionMarker(ctx context.Context, store *storage.S3Storage, certKey string, raw []byte, knownKeys map[string]struct{}) ([]byte, error) {
	markerKey, ok := tlsmanager.LegacyDeletionMarkerKey(certKey, raw)
	if !ok {
		return nil, nil
	}
	if knownKeys != nil {
		if _, exists := knownKeys[markerKey]; !exists {
			return nil, nil
		}
	}
	markerData, _, _, err := readTLSObject(ctx, store, markerKey)
	if err != nil {
		var missing *types.NoSuchKey
		if errors.As(err, &missing) {
			return nil, nil
		}
		return nil, err
	}
	return markerData, nil
}

// A logical tombstone remains as the publication fence but is not a certificate
// available to delete/list unless it carries an unproven legacy state that tls delete
// must overwrite with an explicit deletion barrier.
func tlsObjectDeletable(ctx context.Context, store *storage.S3Storage, key string, knownKeys map[string]struct{}) (bool, error) {
	raw, _, _, err := readTLSObject(ctx, store, key)
	if err != nil {
		var missing *types.NoSuchKey
		if errors.As(err, &missing) {
			return false, nil
		}
		return false, err
	}
	if tlsmanager.UnprovenCertificateTombstone(raw) {
		return true, nil
	}
	markerData, err := readLegacyDeletionMarker(ctx, store, key, raw, knownKeys)
	if err != nil {
		return false, err
	}
	_, absent, err := tlsmanager.DecodeCertificateObjectData(raw, markerData)
	if tlsmanager.IsUnprovenCertificateError(err) {
		return true, nil
	}
	return !absent, err
}
