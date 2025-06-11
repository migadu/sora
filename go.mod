module github.com/migadu/sora

go 1.23.1

require (
	github.com/BurntSushi/toml v1.5.0
	github.com/emersion/go-imap/v2 v2.0.0-beta.5.0.20250605085616-231f7ff5a407
	github.com/emersion/go-message v0.18.2
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6
	github.com/emersion/go-smtp v0.21.3
	github.com/foxcpp/go-sieve v0.0.0-20240130002450-72d6b002882a
	github.com/jackc/pgx/v5 v5.7.5
	github.com/k3a/html2text v1.2.1
	github.com/mattn/go-sqlite3 v1.14.27
	github.com/minio/minio-go/v7 v7.0.89
	github.com/yugabyte/pgx/v5 v5.5.3-yb-5
	golang.org/x/crypto v0.37.0
	lukechampine.com/blake3 v1.4.1
)

// Use forked versions until upstreams are updated
replace github.com/foxcpp/go-sieve => github.com/migadu/go-sieve v0.0.0-20250609093216-f0c5e6465a25

replace github.com/emersion/go-imap/v2 => github.com/dejanstrbac/go-imap/v2 v2.0.0-20250611203636-5c83d840efe0

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/minio/crc64nvme v1.0.1 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/rs/xid v1.6.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)
