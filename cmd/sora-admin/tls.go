package main

// tls.go - Command handlers for TLS certificate management
// Lists certificates from S3 and local cache for debugging

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/storage"
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
		fmt.Printf("Unknown tls subcommand: %s\n\n", subcommand)
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
  --cache-dir string    Local autocert cache directory (default: /var/cache/sora/autocert)
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
  sora-admin tls list --details
  sora-admin tls list --cache-dir /custom/path
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
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	if *domain == "" && *s3Key == "" {
		fmt.Println("Error: Either --domain or --key must be specified")
		fs.Usage()
		os.Exit(1)
	}

	if *domain != "" && *s3Key != "" {
		fmt.Println("Error: Cannot specify both --domain and --key")
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
  sora-admin tls list --details
  sora-admin tls delete --domain imap.example.com --config config.toml
  sora-admin tls delete --key 9f01dab509f55b97 --config config.toml
  sora-admin tls clean --config config.toml
  sora-admin tls cache --config config.toml

Use 'sora-admin tls <subcommand> --help' for detailed help.
`)
}

type CertificateInfo struct {
	S3Key        string
	Domain       string
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

	s3store, err := storage.New(
		endpoint,
		s3cfg.AccessKey,
		s3cfg.SecretKey,
		s3cfg.Bucket,
		!s3cfg.DisableTLS,
		s3cfg.Debug,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 storage: %w", err)
	}

	// List all objects in autocert/ prefix
	prefix := "autocert/"
	objChan, errChan := s3store.ListObjects(ctx, prefix, false)

	// Collect certificate information
	var certs []CertificateInfo

	// Read from channels
	for {
		// Both channels closed, we're done
		if objChan == nil && errChan == nil {
			break
		}

		select {
		case obj, ok := <-objChan:
			if !ok {
				// Channel closed, we're done
				objChan = nil
				continue
			}

			logger.Info("Received object from S3", "key", obj.Key)

			// Skip non-certificate objects
			if !strings.HasPrefix(obj.Key, prefix+"cert-") {
				continue
			}

			certInfo := CertificateInfo{
				S3Key: obj.Key,
			}

			// Try to determine domain from key
			// Format: autocert/cert-<sha256(domain)> or autocert/cert-<sha256(domain+rsa)>
			certInfo.Domain = tryDecodeDomain(obj.Key)

			// Download certificate from S3 to parse it
			reader, err := s3store.Get(obj.Key)
			if err != nil {
				logger.Warn("Failed to download certificate from S3", "key", obj.Key, "error", err)
				certInfo.CertType = "Error"
			} else {
				defer reader.Close()
				// Read certificate data
				certData, err := io.ReadAll(reader)
				if err != nil {
					logger.Warn("Failed to read certificate from S3", "key", obj.Key, "error", err)
					certInfo.CertType = "Error"
				} else {
					// Parse certificate
					parseCertificateData(certData, &certInfo)
				}
			}

			// Check if certificate exists in local cache
			certInfo.InLocalCache, certInfo.LocalPath = checkLocalCache(cacheDir, certInfo.Domain, certInfo.S3Key)

			certs = append(certs, certInfo)

		case err, ok := <-errChan:
			if !ok {
				// Error channel closed
				errChan = nil
				continue
			}
			if err != nil {
				return fmt.Errorf("error listing S3 objects: %w", err)
			}

		case <-ctx.Done():
			return ctx.Err()
		}
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

func tryDecodeDomain(s3Key string) string {
	// Extract hash from key: autocert/cert-<hash>
	parts := strings.Split(s3Key, "cert-")
	if len(parts) != 2 {
		return "unknown"
	}

	hash := parts[1]

	// Try common domains
	commonDomains := []string{
		"imap.migadu.com",
		"pop.migadu.com",
		"lmtp.migadu.com",
		"smtp.migadu.com",
		"mail.migadu.com",
	}

	for _, domain := range commonDomains {
		// Try both ECDSA (domain) and RSA (domain+rsa)
		if hashDomain(domain) == hash {
			return domain
		}
		if hashDomain(domain+"+rsa") == hash {
			return domain + " (RSA)"
		}
	}

	return hash[:16] + "..." // Show first 16 chars of hash
}

func hashDomain(domain string) string {
	h := sha256.Sum256([]byte(domain))
	return hex.EncodeToString(h[:])
}

func parseCertificateData(data []byte, info *CertificateInfo) {
	// autocert stores: private key PEM + certificate PEM
	// We need to skip the private key and parse the certificate

	// Try to find certificate PEM block
	var certPEM []byte
	remaining := data

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			certPEM = pem.EncodeToMemory(block)
			break
		}

		remaining = rest
	}

	if certPEM == nil {
		info.CertType = "Invalid"
		return
	}

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		info.CertType = "Invalid"
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		info.CertType = "Parse Error"
		return
	}

	// Extract information
	info.Expiry = cert.NotAfter
	info.NotBefore = cert.NotBefore
	info.Subject = cert.Subject.String()
	info.Issuer = cert.Issuer.String()
	info.SerialNumber = cert.SerialNumber.String()
	info.KeyAlgorithm = cert.PublicKeyAlgorithm.String()
	info.SigAlgorithm = cert.SignatureAlgorithm.String()

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
}

func checkLocalCache(cacheDir string, domain string, s3Key string) (bool, string) {
	// Check if cache directory exists
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		return false, ""
	}

	// Try to find the certificate in local cache
	// autocert uses the domain name (or domain+rsa) as the filename

	// Extract potential filename from domain
	var filenames []string
	if strings.Contains(domain, "(RSA)") {
		baseDomain := strings.TrimSuffix(strings.TrimSpace(domain), " (RSA)")
		filenames = []string{
			baseDomain + "+rsa",
			baseDomain,
		}
	} else if strings.HasSuffix(domain, "...") {
		// Unknown domain, can't check local cache
		return false, ""
	} else {
		filenames = []string{
			domain,
			domain + "+rsa",
		}
	}

	for _, filename := range filenames {
		localPath := filepath.Join(cacheDir, filename)
		if _, err := os.Stat(localPath); err == nil {
			return true, localPath
		}
	}

	return false, ""
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
				fmt.Printf("Local Cache:     ✓ YES (%s)\n", cert.LocalPath)
			} else {
				fmt.Printf("Local Cache:     ✗ NO\n")
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

	s3store, err := storage.New(
		endpoint,
		s3cfg.AccessKey,
		s3cfg.SecretKey,
		s3cfg.Bucket,
		!s3cfg.DisableTLS,
		s3cfg.Debug,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 storage: %w", err)
	}

	var keysToDelete []string

	if domain != "" {
		// Delete by domain - compute S3 keys for both ECDSA and RSA
		ecdsaKey := "autocert/" + hashDomain(domain)
		rsaKey := "autocert/" + hashDomain(domain+"+rsa")
		keysToDelete = []string{ecdsaKey, rsaKey}

		fmt.Printf("Deleting certificates for domain: %s\n", domain)
		fmt.Printf("  ECDSA key: %s\n", ecdsaKey)
		fmt.Printf("  RSA key:   %s\n", rsaKey)
	} else {
		// Delete by specific S3 key or prefix
		// Support full key, hash, or partial hash
		searchKey := s3Key
		if !strings.HasPrefix(searchKey, "autocert/") {
			searchKey = "autocert/cert-" + searchKey
		}

		// If the key looks partial (ends with ...), do a prefix search
		needsPrefixSearch := strings.HasSuffix(s3Key, "...") || len(s3Key) < 64

		if needsPrefixSearch {
			// Search for matching certificates by prefix
			fmt.Printf("Searching for certificates matching prefix: %s\n", searchKey)

			prefix := strings.TrimSuffix(searchKey, "...")
			objChan, errChan := s3store.ListObjects(ctx, "autocert/", false)

			var matches []string
			for {
				if objChan == nil && errChan == nil {
					break
				}

				select {
				case obj, ok := <-objChan:
					if !ok {
						objChan = nil
						continue
					}
					if strings.HasPrefix(obj.Key, prefix) {
						matches = append(matches, obj.Key)
					}
				case err, ok := <-errChan:
					if !ok {
						errChan = nil
						continue
					}
					if err != nil {
						return fmt.Errorf("error searching S3: %w", err)
					}
				case <-ctx.Done():
					return ctx.Err()
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
		} else {
			keysToDelete = []string{searchKey}
			fmt.Printf("Deleting certificate: %s\n", searchKey)
		}
	}

	if dryRun {
		fmt.Println("\nDRY RUN - No changes will be made")
		return nil
	}

	deleted := 0
	notFound := 0

	for _, key := range keysToDelete {
		// Delete from S3
		if err := s3store.Delete(key); err != nil {
			// Check if it's a "not found" error
			if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "not found") {
				logger.Info("Certificate not found in S3 (already deleted?)", "key", key)
				notFound++
			} else {
				logger.Warn("Failed to delete certificate from S3", "key", key, "error", err)
			}
		} else {
			logger.Info("Deleted certificate from S3", "key", key)
			deleted++
		}

		// Delete from local cache if it exists
		if domain != "" {
			// Extract cache filename from domain
			cacheFile := domain
			if strings.Contains(key, "+rsa") {
				cacheFile = domain + "+rsa"
			}
			localPath := filepath.Join(cacheDir, cacheFile)
			if err := os.Remove(localPath); err != nil {
				if !os.IsNotExist(err) {
					logger.Warn("Failed to delete certificate from local cache", "path", localPath, "error", err)
				}
			} else {
				logger.Info("Deleted certificate from local cache", "path", localPath)
			}
		}
	}

	fmt.Printf("\nDeleted %d certificate(s), %d not found\n", deleted, notFound)
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

	s3store, err := storage.New(
		endpoint,
		s3cfg.AccessKey,
		s3cfg.SecretKey,
		s3cfg.Bucket,
		!s3cfg.DisableTLS,
		s3cfg.Debug,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 storage: %w", err)
	}

	// List all certificates
	prefix := "autocert/"
	objChan, errChan := s3store.ListObjects(ctx, prefix, false)

	var expiredCerts []CertificateInfo
	now := time.Now()

	// Read from channels
	for {
		if objChan == nil && errChan == nil {
			break
		}

		select {
		case obj, ok := <-objChan:
			if !ok {
				objChan = nil
				continue
			}

			// Skip non-certificate objects
			if !strings.HasPrefix(obj.Key, prefix+"cert-") {
				continue
			}

			certInfo := CertificateInfo{
				S3Key: obj.Key,
			}
			certInfo.Domain = tryDecodeDomain(obj.Key)

			// Download and parse certificate to check expiry
			reader, err := s3store.Get(obj.Key)
			if err != nil {
				logger.Warn("Failed to download certificate", "key", obj.Key, "error", err)
				continue
			}

			certData, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				logger.Warn("Failed to read certificate", "key", obj.Key, "error", err)
				continue
			}

			parseCertificateData(certData, &certInfo)

			// Check if expired
			if !certInfo.Expiry.IsZero() && certInfo.Expiry.Before(now) {
				expiredCerts = append(expiredCerts, certInfo)
			}

		case err, ok := <-errChan:
			if !ok {
				errChan = nil
				continue
			}
			if err != nil {
				return fmt.Errorf("error listing S3 objects: %w", err)
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if len(expiredCerts) == 0 {
		fmt.Println("No expired certificates found.")
		return nil
	}

	// Display expired certificates
	fmt.Printf("Found %d expired certificate(s):\n\n", len(expiredCerts))
	for _, cert := range expiredCerts {
		expiredDays := int(now.Sub(cert.Expiry).Hours() / 24)
		fmt.Printf("  %s (%s) - expired %d days ago\n", cert.Domain, cert.CertType, expiredDays)
	}

	if dryRun {
		fmt.Println("\nDRY RUN - No changes will be made")
		return nil
	}

	// Confirm deletion
	if !force {
		fmt.Printf("\nDelete these %d expired certificate(s)? [y/N]: ", len(expiredCerts))
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" && response != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	// Delete expired certificates
	deleted := 0
	for _, cert := range expiredCerts {
		if err := s3store.Delete(cert.S3Key); err != nil {
			logger.Warn("Failed to delete certificate from S3", "key", cert.S3Key, "error", err)
		} else {
			logger.Info("Deleted expired certificate from S3", "key", cert.S3Key, "domain", cert.Domain)
			deleted++
		}

		// Also delete from local cache if possible
		if cert.Domain != "" && !strings.Contains(cert.Domain, "...") {
			cacheFile := cert.Domain
			if cert.CertType == "RSA" {
				cacheFile += "+rsa"
			}
			localPath := filepath.Join(cacheDir, cacheFile)
			if err := os.Remove(localPath); err != nil && !os.IsNotExist(err) {
				logger.Warn("Failed to delete from local cache", "path", localPath, "error", err)
			}
		}
	}

	fmt.Printf("\nDeleted %d expired certificate(s)\n", deleted)
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

	s3store, err := storage.New(
		endpoint,
		s3cfg.AccessKey,
		s3cfg.SecretKey,
		s3cfg.Bucket,
		!s3cfg.DisableTLS,
		s3cfg.Debug,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 storage: %w", err)
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Determine which domains to cache
	var domainsToCache []string
	if specificDomain != "" {
		domainsToCache = []string{specificDomain}
	} else {
		domainsToCache = cfg.TLS.LetsEncrypt.Domains
	}

	fmt.Printf("Caching certificates to: %s\n\n", cacheDir)

	cached := 0
	skipped := 0
	expired := 0
	notFound := 0
	now := time.Now()

	for _, domain := range domainsToCache {
		// Cache both ECDSA and RSA variants
		variants := []struct {
			name string
			key  string
		}{
			{"ECDSA", domain},
			{"RSA", domain + "+rsa"},
		}

		for _, variant := range variants {
			s3Key := "autocert/cert-" + hashDomain(variant.key)

			// Download from S3
			reader, err := s3store.Get(s3Key)
			if err != nil {
				if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "not found") {
					logger.Info("Certificate not found in S3", "domain", domain, "type", variant.name)
					notFound++
				} else {
					logger.Warn("Failed to download certificate from S3", "domain", domain, "type", variant.name, "error", err)
				}
				continue
			}

			certData, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				logger.Warn("Failed to read certificate from S3", "domain", domain, "type", variant.name, "error", err)
				continue
			}

			// Parse to check expiry
			certInfo := CertificateInfo{}
			parseCertificateData(certData, &certInfo)

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
			if err := os.WriteFile(localPath, certData, 0600); err != nil {
				logger.Warn("Failed to write certificate to local cache", "path", localPath, "error", err)
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

	return nil
}
