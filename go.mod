module github.com/migadu/sora

go 1.25.0

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/aws/aws-sdk-go-v2 v1.43.5
	github.com/aws/aws-sdk-go-v2/credentials v1.19.35
	github.com/aws/aws-sdk-go-v2/service/s3 v1.107.1
	github.com/aws/smithy-go v1.27.7
	github.com/emersion/go-imap/v2 v2.0.0-beta.7
	github.com/emersion/go-message v0.18.2
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6
	github.com/emersion/go-smtp v0.24.0
	github.com/exaring/ja4plus v0.0.3
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/golang-migrate/migrate/v4 v4.19.1
	github.com/google/uuid v1.6.0
	github.com/hashicorp/memberlist v0.6.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/k3a/html2text v1.4.0
	github.com/migadu/go-managesieve v0.1.1
	github.com/migadu/go-pop3 v0.1.4
	github.com/migadu/go-sieve v1.1.2
	github.com/prometheus/client_golang v1.24.1
	github.com/prometheus/client_model v0.6.2
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.55.0
	golang.org/x/net v0.57.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	lukechampine.com/blake3 v1.4.1
	modernc.org/sqlite v1.56.0
)

replace github.com/emersion/go-smtp => github.com/migadu/go-smtp v0.0.0-20260705231539-0ef684185ca4

replace github.com/emersion/go-message => github.com/migadu/go-message v0.0.0-20260705121217-8814c0e56d68

require (
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.37 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.36 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.37 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-metrics v0.6.1 // indirect
	github.com/hashicorp/go-msgpack/v2 v2.1.5 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/jackc/pgerrcode v0.0.0-20250907135507-afb5586c32a6 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/sean-/seed v0.0.0-20170313163322-e2103e2c3529 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.75.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.0 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

replace github.com/emersion/go-imap/v2 => github.com/migadu/go-imap/v2 v2.0.0-20260815125902-611e5ae5602e
