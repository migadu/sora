# Security Guide

Securing your mail server is critical. Sora provides several features to help you build a secure and robust email service.

## Transport Layer Security (TLS)

Always use TLS to encrypt communications between clients, proxies, and servers.

*   **Enabling TLS**: In each server's configuration section (e.g., `[servers.imap]`), set `tls = true` and provide the paths to your certificate and key files:
    ```toml
    [servers.imap]
    addr = ":993" # Standard IMAPS port
    tls = true
    tls_cert_file = "/path/to/your/fullchain.pem"
    tls_key_file = "/path/to/your/privkey.pem"
    ```
    It is highly recommended that `tls_cert_file` contains the full certificate chain.

*   **STARTTLS**: For protocols that support opportunistic encryption (LMTP, ManageSieve), you can enable `tls_use_starttls = true`.

*   **Client Certificates**: Sora can be configured to verify client certificates for mutual TLS (`tls_verify = true`), but this is typically disabled (`false`) for general-purpose mail servers.

## Authentication

*   **Password Schemes**: Sora supports modern and legacy password hashing schemes. The default and recommended scheme is `bcrypt`. Support for various Dovecot schemes (`SSHA512`, `SHA512-CRYPT`, etc.) is included for easier migration. This is configured in the `sora-admin` tool or via the API when creating/updating credentials, not in `config.toml`.

*   **Master Users**: The `master_username` and `master_password` settings in the protocol server sections allow a special user to log in as any other user. This is primarily intended for proxy-to-backend authentication and administrative access. **Protect these credentials carefully.**

## Authentication Rate Limiting

To protect against brute-force password attacks, Sora has a built-in rate limiter. You can enable it in each protocol's configuration:

```toml
[servers.imap.auth_rate_limit]
enabled = true
max_attempts_per_ip = 10
max_attempts_per_username = 5
ip_window_duration = "15m"
fast_block_threshold = 10
fast_block_duration = "5m"
```

This system tracks failed login attempts per IP and per username, introducing progressive delays and temporary blocks to thwart attackers.

## PROXY Protocol

When running Sora behind a load balancer or proxy, the server will only see the proxy's IP address. The PROXY protocol solves this by prepending a header to the connection that contains the real client IP.

*   **WARNING**: Only enable this if you are certain your proxy is sending this header. An attacker who can connect directly to the port could spoof their IP address if this is misconfigured.
*   **Configuration**:
    ```toml
    [servers.imap.proxy_protocol]
    enabled = true
    trusted_proxies = ["127.0.0.1/32", "10.0.0.0/8"] # List of trusted proxy IPs/CIDRs
    ```

## Client-Side S3 Encryption

For an additional layer of security, you can have Sora encrypt message bodies *before* they are uploaded to S3.

```toml
[s3]
encrypt = true
encryption_key = "YOUR-SECRET-32-BYTE-HEX-ENCODED-KEY-HERE"
```

**CRITICAL**: If you enable this, you **must** back up the `encryption_key`. If this key is lost, all encrypted message data will be permanently unrecoverable.
