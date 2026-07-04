// Package managesieve implements sora's ManageSieve backend on top of the
// github.com/migadu/go-managesieve library.
//
// The library (managesieveserver) owns the RFC 5804 wire protocol: command
// parsing, quoted strings and {N}/{N+} literals, SASL PLAIN framing,
// STARTTLS, the state machine, response formatting, and abuse controls
// (line/literal bounds, timeouts, MaxErrors). This package is the adapter
// that supplies sora's business logic behind the library's Session
// interface:
//
//   - Authentication: PostgreSQL credentials with bcrypt verification and
//     rehashing, lookup-cache acceleration, master-username and master-SASL
//     impersonation (network-gated), and auth rate limiting with progressive
//     delays.
//   - Script storage: per-account scripts in PostgreSQL via the resilient
//     database layer, with master-DB session pinning after writes.
//   - SIEVE validation: scripts are validated with github.com/migadu/go-sieve
//     against the configured supported_extensions on PUTSCRIPT, CHECKSCRIPT,
//     and SETACTIVE.
//   - Quotas: max_script_size (enforced by the library, including
//     reject-before-read of oversized literals) and the per-account
//     script-count limit.
//   - Operations: connection limiting, PROXY protocol, implicit TLS with
//     deferred handshakes, connection tracking with kick support, Prometheus
//     metrics, graceful shutdown, and SIGHUP config reload (the library
//     server is rebuilt and swapped atomically).
//
// The wiring mirrors server/pop3: ManageSieveServer builds a
// managesieveserver.Server via buildLibServer, the accept loop hands
// connections to ServeConn, and the NewSession callback runs the limiter,
// completes any deferred TLS handshake, and constructs a ManageSieveSession.
//
// # Integration with LMTP
//
// When a message is delivered via LMTP, the active SIEVE script (if any) is
// executed by server/sieveengine. This package only manages the scripts.
package managesieve
