# OAUTHBEARER + SAML Integration Design for Sora

## Executive Summary

This document outlines the design for integrating OAUTHBEARER SASL authentication with SAML identity providers in Sora. This will enable enterprise Single Sign-On (SSO) capabilities while maintaining backward compatibility with existing password-based authentication.

**Status**: Design Proposal
**Author**: Claude (2025-11-05)
**Target Version**: Future release

---

## Table of Contents

1. [Background](#background)
2. [Architecture Overview](#architecture-overview)
3. [Authentication Flow](#authentication-flow)
4. [Implementation Plan](#implementation-plan)
5. [Configuration](#configuration)
6. [Security Considerations](#security-considerations)
7. [Testing Strategy](#testing-strategy)
8. [Migration Path](#migration-path)
9. [Open Questions](#open-questions)

---

## Background

### Current State

Sora currently supports:
- **SASL PLAIN** authentication (IMAP, POP3, ManageSieve)
- **Password schemes**: bcrypt, SSHA512, SHA512, BLF-CRYPT
- **Master authentication**: For proxy and administrative access
- **JWT tokens**: For User API (HTTP)
- **API keys**: For Admin API (HTTP)

### Problem Statement

Many enterprises use **SAML 2.0** identity providers (Okta, Azure AD, Google Workspace, Keycloak) for centralized authentication. Email clients (Thunderbird, Apple Mail, Outlook) that support modern protocols need a way to authenticate using these enterprise identity systems without storing passwords locally.

### Solution: OAUTHBEARER SASL

**RFC 7628** defines OAUTHBEARER, a SASL mechanism that uses OAuth 2.0 bearer tokens for authentication. This is already supported by:
- Modern email clients (Thunderbird 78+, Apple Mail)
- The `go-sasl` library already used by Sora
- Major email providers (Gmail, Outlook.com)

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────┐                    ┌──────────────────┐
│  Email Client   │                    │   SAML IdP       │
│  (Thunderbird)  │                    │  (Okta/Azure AD) │
└────────┬────────┘                    └────────┬─────────┘
         │                                      │
         │ 1. User initiates login             │
         │    (opens browser)                  │
         │                                      │
         │ 2. SAML authentication flow ────────┤
         │    (web-based SSO)                  │
         │                                      │
         │ 3. Receives SAML assertion          │
         │                                      │
         ▼                                      │
┌─────────────────────────────────────────────┐│
│         OAuth Token Service                 ││
│  (External or Built-in to Sora)            ││
│                                             ││
│  - Validates SAML assertion                ││
│  - Issues OAuth 2.0 bearer token           ││
│  - Maps SAML attributes to user identity   ││
└────────────────┬────────────────────────────┘
                 │
                 │ 4. Client receives OAuth token
                 │    (short-lived JWT)
                 │
                 ▼
         ┌───────────────┐
         │     Sora      │
         │  Mail Server  │
         │               │
         │  - Validates  │
         │    bearer     │
         │    token      │
         │  - Extracts   │
         │    user       │
         │    identity   │
         └───────────────┘
```

### Component Responsibilities

#### 1. **Email Client**
- Initiates SAML authentication (browser-based)
- Receives OAuth bearer token
- Sends token via OAUTHBEARER SASL mechanism
- Refreshes token when expired

#### 2. **SAML Identity Provider** (External)
- Authenticates users
- Issues SAML assertions
- Enforces enterprise policies (MFA, conditional access)

#### 3. **OAuth Token Service** (To Be Implemented)
- **Option A**: External service (dedicated microservice)
- **Option B**: Built into Sora (new HTTP endpoint)
- **Option C**: External provider (Azure AD, Okta native OAuth)

Responsibilities:
- Validates SAML assertions
- Issues OAuth 2.0 bearer tokens (JWT format)
- Maps SAML attributes to email addresses
- Implements token refresh logic
- Maintains token revocation list (optional)

#### 4. **Sora Mail Server** (Modifications Required)
- Implements OAUTHBEARER SASL server
- Validates OAuth bearer tokens
- Extracts user identity from token claims
- Integrates with existing authentication flow
- Rate limits token validation attempts

---

## Authentication Flow

### Detailed Flow Diagram

```
Client                 Sora              Token Service       SAML IdP
  │                     │                     │                  │
  │ CAPABILITY          │                     │                  │
  ├────────────────────►│                     │                  │
  │                     │                     │                  │
  │ * SASL OAUTHBEARER  │                     │                  │
  │◄────────────────────┤                     │                  │
  │                     │                     │                  │
  │                     │                     │                  │
  │ [User opens browser and authenticates]    │                  │
  │ ────────────────────────────────────────► │                  │
  │                                            │  SAML Request   │
  │                                            ├─────────────────►│
  │                                            │                  │
  │                                            │  SAML Response  │
  │                                            │  (assertion)    │
  │                                            │◄─────────────────┤
  │                                            │                  │
  │  OAuth Bearer Token (JWT)                 │                  │
  │◄───────────────────────────────────────────┤                  │
  │                     │                     │                  │
  │                     │                     │                  │
  │ AUTHENTICATE OAUTHBEARER                  │                  │
  │ auth=Bearer ey...   │                     │                  │
  ├────────────────────►│                     │                  │
  │                     │                     │                  │
  │                     │ Validate Token      │                  │
  │                     ├────────────────────►│                  │
  │                     │                     │                  │
  │                     │ Token Valid         │                  │
  │                     │ Claims: user@ex.com │                  │
  │                     │◄────────────────────┤                  │
  │                     │                     │                  │
  │                     │ [Check account]     │                  │
  │                     │ [Load mailboxes]    │                  │
  │                     │                     │                  │
  │ OK Authenticated    │                     │                  │
  │◄────────────────────┤                     │                  │
  │                     │                     │                  │
```

### Step-by-Step Flow

#### Phase 1: Client Discovery
1. Client connects to Sora IMAP server
2. Server sends CAPABILITY including `SASL-IR AUTHENTICATE OAUTHBEARER`
3. Client recognizes OAuth support

#### Phase 2: Token Acquisition (Out-of-band)
4. Client opens browser for user authentication
5. User authenticates with SAML IdP (username/password + MFA)
6. IdP returns SAML assertion to Token Service
7. Token Service validates assertion:
   - Signature verification
   - Timestamp validation
   - Audience validation
8. Token Service extracts user email from SAML attributes (e.g., `urn:oid:0.9.2342.19200300.100.1.3`)
9. Token Service issues JWT bearer token:
   - **Issuer**: Token service identifier
   - **Subject**: User email address
   - **Expiration**: Short-lived (1-6 hours)
   - **Claims**: Additional user attributes
10. Token returned to client

#### Phase 3: IMAP Authentication
11. Client sends AUTHENTICATE OAUTHBEARER with token
12. Sora extracts bearer token from SASL payload
13. Sora validates token:
    - **Signature verification** (JWT signature using shared secret or public key)
    - **Expiration check** (exp claim)
    - **Issuer validation** (iss claim)
    - **Audience validation** (aud claim should match Sora's identifier)
14. Sora extracts email from token claims (sub or email claim)
15. Sora looks up account ID by email: `db.GetAccountIDByAddress(ctx, email)`
16. Sora establishes authenticated session
17. Server responds with `OK Authentication successful`

#### Phase 4: Token Refresh (Background)
18. Client monitors token expiration
19. Before expiration, client requests new token from Token Service
20. Token Service may require re-authentication or issue refresh token

---

## Implementation Plan

### Phase 1: Core OAUTHBEARER Support (Week 1-2)

#### 1.1. Add OAUTHBEARER to IMAP Server

**File**: `server/imap/sasl.go`

```go
// AuthenticateMechanisms returns a list of supported SASL mechanisms
func (s *IMAPSession) AuthenticateMechanisms() []string {
    mechanisms := []string{"PLAIN"}

    // Add OAUTHBEARER if OAuth is configured
    if s.server.oauthConfig != nil && s.server.oauthConfig.Enabled {
        mechanisms = append(mechanisms, "OAUTHBEARER")
    }

    return mechanisms
}

// Authenticate handles SASL authentication
func (s *IMAPSession) Authenticate(mechanism string) (sasl.Server, error) {
    switch mechanism {
    case "PLAIN":
        // ... existing PLAIN implementation ...

    case "OAUTHBEARER":
        return s.authenticateOAuthBearer()

    default:
        return nil, &imap.Error{
            Type: imap.StatusResponseTypeNo,
            Code: imap.ResponseCodeAuthenticationFailed,
            Text: "Unsupported authentication mechanism",
        }
    }
}

func (s *IMAPSession) authenticateOAuthBearer() (sasl.Server, error) {
    return sasl.NewOAuthBearerServer(func(options sasl.OAuthBearerOptions) *sasl.OAuthBearerError {
        // Get remote IP for rate limiting
        netConn := s.conn.NetConn()
        var proxyInfo *server.ProxyProtocolInfo
        if s.ProxyIP != "" {
            proxyInfo = &server.ProxyProtocolInfo{SrcIP: s.RemoteIP}
        }

        // Apply authentication delay
        remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
        server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "IMAP-OAUTHBEARER")

        // Check rate limiting
        if s.server.authLimiter != nil {
            // Extract email from token (best effort for rate limiting)
            email := extractEmailFromToken(options.Token)
            if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, netConn, proxyInfo, email); err != nil {
                s.DebugLog("Authentication: OAUTHBEARER rate limited: %v", err)
                return &sasl.OAuthBearerError{
                    Status:  "invalid_token",
                    Schemes: "bearer",
                }
            }
        }

        // Validate token with OAuth validator
        claims, err := s.server.oauthValidator.ValidateToken(s.ctx, options.Token)
        if err != nil {
            s.DebugLog("Authentication: OAUTHBEARER token validation failed: %v", err)
            metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()

            // Record failed attempt for rate limiting
            if s.server.authLimiter != nil {
                email := extractEmailFromToken(options.Token)
                s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, email, false)
            }

            return &sasl.OAuthBearerError{
                Status:  "invalid_token",
                Schemes: "bearer",
            }
        }

        // Extract email from claims
        email, ok := claims["email"].(string)
        if !ok || email == "" {
            // Try 'sub' claim as fallback
            email, ok = claims["sub"].(string)
            if !ok || email == "" {
                s.DebugLog("Authentication: OAUTHBEARER token missing email claim")
                metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
                return &sasl.OAuthBearerError{
                    Status:  "invalid_token",
                    Schemes: "bearer",
                }
            }
        }

        // Look up account by email
        address, err := server.NewAddress(email)
        if err != nil {
            s.DebugLog("Authentication: OAUTHBEARER invalid email format: %s", email)
            metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
            return &sasl.OAuthBearerError{
                Status:  "invalid_token",
                Schemes: "bearer",
            }
        }

        accountID, err := s.server.rdb.GetAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
        if err != nil {
            s.DebugLog("Authentication: OAUTHBEARER account not found for email: %s", email)
            metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
            return &sasl.OAuthBearerError{
                Status:  "invalid_token",
                Schemes: "bearer",
            }
        }

        // Create IMAP user session
        s.IMAPUser = NewIMAPUser(address, accountID)
        s.Session.User = &s.IMAPUser.User

        // Ensure default mailboxes
        if dbErr := s.server.rdb.CreateDefaultMailboxesWithRetry(s.ctx, accountID); dbErr != nil {
            s.DebugLog("Authentication: OAUTHBEARER failed to create default mailboxes: %v", dbErr)
            return &sasl.OAuthBearerError{
                Status:  "invalid_request",
                Schemes: "bearer",
            }
        }

        // Success!
        authCount := s.server.authenticatedConnections.Add(1)
        totalCount := s.server.totalConnections.Load()
        s.Log("Authentication: OAUTHBEARER session established for user '%s' (ID: %d) (connections: total=%d, authenticated=%d)",
            address.BaseAddress(), accountID, totalCount, authCount)

        metrics.AuthenticationAttempts.WithLabelValues("imap", "success").Inc()
        metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Inc()

        // Record successful attempt
        if s.server.authLimiter != nil {
            s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, email, true)
        }

        // Trigger cache warmup
        s.triggerCacheWarmup()

        return nil // Success
    }), nil
}

// Helper function to extract email from token for rate limiting
func extractEmailFromToken(token string) string {
    // This is a best-effort extraction for rate limiting purposes
    // Parse JWT without validation (just to get claims)
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return ""
    }

    payload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return ""
    }

    var claims map[string]interface{}
    if err := json.Unmarshal(payload, &claims); err != nil {
        return ""
    }

    // Try email claim first, then sub
    if email, ok := claims["email"].(string); ok {
        return email
    }
    if sub, ok := claims["sub"].(string); ok {
        return sub
    }

    return ""
}
```

#### 1.2. Create OAuth Token Validator

**New File**: `server/oauth/validator.go`

```go
package oauth

import (
    "context"
    "crypto/rsa"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/migadu/sora/logger"
)

type TokenValidator interface {
    ValidateToken(ctx context.Context, tokenString string) (map[string]interface{}, error)
}

// JWTValidator validates JWT bearer tokens
type JWTValidator struct {
    issuer         string
    audience       string

    // For symmetric signing (HS256)
    sharedSecret   []byte

    // For asymmetric signing (RS256)
    publicKey      *rsa.PublicKey
    jwksURL        string
    jwksCache      map[string]*rsa.PublicKey
    jwksCacheMutex sync.RWMutex
    jwksCacheExpiry time.Time

    // Token introspection endpoint (optional)
    introspectionURL string
    introspectionClientID string
    introspectionClientSecret string
}

type JWTValidatorConfig struct {
    // Required
    Issuer   string `toml:"issuer"`   // Expected token issuer (e.g., "https://idp.example.com")
    Audience string `toml:"audience"` // Expected audience (e.g., "sora-mail")

    // Option 1: Symmetric signing (simple but less secure)
    SharedSecret string `toml:"shared_secret"` // Base64-encoded shared secret for HS256

    // Option 2: Asymmetric signing (recommended)
    PublicKeyPEM string `toml:"public_key_pem"` // PEM-encoded RSA public key for RS256
    JWKSUrl      string `toml:"jwks_url"`       // URL to fetch public keys (e.g., "https://idp.example.com/.well-known/jwks.json")

    // Option 3: Token introspection (for opaque tokens)
    IntrospectionURL          string `toml:"introspection_url"`
    IntrospectionClientID     string `toml:"introspection_client_id"`
    IntrospectionClientSecret string `toml:"introspection_client_secret"`

    // Optional settings
    ClockSkew      string `toml:"clock_skew"`      // Allowed clock skew (e.g., "5m")
    JWKSCacheDuration string `toml:"jwks_cache_duration"` // How long to cache JWKS keys (e.g., "1h")
}

func NewJWTValidator(config JWTValidatorConfig) (*JWTValidator, error) {
    validator := &JWTValidator{
        issuer:       config.Issuer,
        audience:     config.Audience,
        jwksCache:    make(map[string]*rsa.PublicKey),
    }

    // Parse shared secret if provided
    if config.SharedSecret != "" {
        secret, err := base64.StdEncoding.DecodeString(config.SharedSecret)
        if err != nil {
            return nil, fmt.Errorf("invalid shared secret: %w", err)
        }
        validator.sharedSecret = secret
    }

    // Parse public key if provided
    if config.PublicKeyPEM != "" {
        publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(config.PublicKeyPEM))
        if err != nil {
            return nil, fmt.Errorf("invalid public key: %w", err)
        }
        validator.publicKey = publicKey
    }

    // Store JWKS URL if provided
    if config.JWKSUrl != "" {
        validator.jwksURL = config.JWKSUrl
    }

    // Store introspection settings if provided
    if config.IntrospectionURL != "" {
        validator.introspectionURL = config.IntrospectionURL
        validator.introspectionClientID = config.IntrospectionClientID
        validator.introspectionClientSecret = config.IntrospectionClientSecret
    }

    // Validate configuration
    if validator.sharedSecret == nil && validator.publicKey == nil &&
       validator.jwksURL == "" && validator.introspectionURL == "" {
        return nil, errors.New("no validation method configured (need shared_secret, public_key_pem, jwks_url, or introspection_url)")
    }

    return validator, nil
}

func (v *JWTValidator) ValidateToken(ctx context.Context, tokenString string) (map[string]interface{}, error) {
    // If introspection is configured, use that (for opaque tokens)
    if v.introspectionURL != "" {
        return v.introspectToken(ctx, tokenString)
    }

    // Otherwise, validate as JWT
    return v.validateJWT(ctx, tokenString)
}

func (v *JWTValidator) validateJWT(ctx context.Context, tokenString string) (map[string]interface{}, error) {
    // Parse token
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Check signing method
        switch token.Method.(type) {
        case *jwt.SigningMethodHMAC:
            // Symmetric signing (HS256)
            if v.sharedSecret == nil {
                return nil, errors.New("shared secret not configured")
            }
            return v.sharedSecret, nil

        case *jwt.SigningMethodRSA:
            // Asymmetric signing (RS256)
            // Try static public key first
            if v.publicKey != nil {
                return v.publicKey, nil
            }

            // Otherwise fetch from JWKS
            if v.jwksURL != "" {
                kid, ok := token.Header["kid"].(string)
                if !ok {
                    return nil, errors.New("token missing kid header")
                }

                key, err := v.getJWKSKey(ctx, kid)
                if err != nil {
                    return nil, fmt.Errorf("failed to fetch JWKS key: %w", err)
                }
                return key, nil
            }

            return nil, errors.New("no public key configured for RS256")

        default:
            return nil, fmt.Errorf("unsupported signing method: %v", token.Method)
        }
    })

    if err != nil {
        return nil, fmt.Errorf("token validation failed: %w", err)
    }

    if !token.Valid {
        return nil, errors.New("token is invalid")
    }

    // Extract claims
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, errors.New("invalid token claims")
    }

    // Validate issuer
    if v.issuer != "" {
        iss, ok := claims["iss"].(string)
        if !ok || iss != v.issuer {
            return nil, fmt.Errorf("invalid issuer: expected %s, got %s", v.issuer, iss)
        }
    }

    // Validate audience
    if v.audience != "" {
        aud, ok := claims["aud"].(string)
        if !ok {
            // Audience might be an array
            audArray, ok := claims["aud"].([]interface{})
            if !ok {
                return nil, errors.New("invalid audience claim")
            }

            found := false
            for _, a := range audArray {
                if audStr, ok := a.(string); ok && audStr == v.audience {
                    found = true
                    break
                }
            }
            if !found {
                return nil, fmt.Errorf("audience not matched: expected %s", v.audience)
            }
        } else if aud != v.audience {
            return nil, fmt.Errorf("invalid audience: expected %s, got %s", v.audience, aud)
        }
    }

    // Convert claims to map[string]interface{}
    result := make(map[string]interface{})
    for k, v := range claims {
        result[k] = v
    }

    return result, nil
}

func (v *JWTValidator) getJWKSKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
    // Check cache first
    v.jwksCacheMutex.RLock()
    if key, ok := v.jwksCache[kid]; ok && time.Now().Before(v.jwksCacheExpiry) {
        v.jwksCacheMutex.RUnlock()
        return key, nil
    }
    v.jwksCacheMutex.RUnlock()

    // Fetch JWKS from URL
    // TODO: Implement JWKS fetching with HTTP client
    // This is a placeholder - real implementation would:
    // 1. Make HTTP GET request to v.jwksURL
    // 2. Parse JSON response
    // 3. Find key with matching kid
    // 4. Convert to *rsa.PublicKey
    // 5. Cache with expiry

    return nil, errors.New("JWKS fetching not yet implemented")
}

func (v *JWTValidator) introspectToken(ctx context.Context, tokenString string) (map[string]interface{}, error) {
    // TODO: Implement token introspection (RFC 7662)
    // This is a placeholder - real implementation would:
    // 1. Make HTTP POST to v.introspectionURL
    // 2. Include client credentials
    // 3. Parse introspection response
    // 4. Return claims

    return nil, errors.New("token introspection not yet implemented")
}
```

#### 1.3. Update Server Configuration

**File**: `server/imap/server.go`

```go
type IMAPServer struct {
    // ... existing fields ...

    // OAuth support
    oauthConfig    *config.OAuthConfig
    oauthValidator oauth.TokenValidator
}

func NewIMAPServer(/* ... existing params ..., oauthConfig *config.OAuthConfig */) (*IMAPServer, error) {
    // ... existing initialization ...

    // Initialize OAuth validator if configured
    var oauthValidator oauth.TokenValidator
    if oauthConfig != nil && oauthConfig.Enabled {
        validator, err := oauth.NewJWTValidator(oauthConfig.JWT)
        if err != nil {
            return nil, fmt.Errorf("failed to initialize OAuth validator: %w", err)
        }
        oauthValidator = validator
        logger.Info("IMAP: OAuth authentication enabled")
    }

    server := &IMAPServer{
        // ... existing fields ...
        oauthConfig:    oauthConfig,
        oauthValidator: oauthValidator,
    }

    return server, nil
}
```

#### 1.4. Add Configuration Schema

**File**: `config/config.go`

```go
// OAuthConfig holds OAuth 2.0 authentication configuration
type OAuthConfig struct {
    Enabled bool              `toml:"enabled"`
    JWT     oauth.JWTValidatorConfig `toml:"jwt"`
}

// Update ServerConfig
type ServerConfig struct {
    // ... existing fields ...

    // OAuth configuration
    OAuth *OAuthConfig `toml:"oauth"`
}
```

### Phase 2: POP3 and ManageSieve Support (Week 2)

Replicate the OAUTHBEARER implementation for:
- **POP3**: `server/pop3/server.go` and `server/pop3/session.go`
- **ManageSieve**: `server/managesieve/server.go` and `server/managesieve/session.go`

The implementation pattern is identical to IMAP.

### Phase 3: Token Service (Week 3-4)

**Decision Point**: Choose one of three approaches:

#### Option A: External Token Service (Recommended for Enterprise)
- Standalone microservice
- Handles SAML-to-OAuth bridge
- Separate from Sora codebase
- Examples: Keycloak, Azure AD B2C, Auth0

**Pros**:
- Separation of concerns
- Can serve multiple applications
- Well-tested SAML implementations
- Scalable independently

**Cons**:
- Additional deployment complexity
- External dependency

#### Option B: Built-in Token Service (Simple Deployment)
- Add SAML handler to Sora
- New HTTP endpoint: `/oauth/token`
- SAML metadata endpoint: `/oauth/saml/metadata`

**New File**: `server/oauth/saml_handler.go`

```go
package oauth

import (
    "context"
    "crypto/rsa"
    "crypto/x509"
    "encoding/base64"
    "time"

    "github.com/crewjam/saml"
    "github.com/crewjam/saml/samlsp"
    "github.com/golang-jwt/jwt/v5"
)

type SAMLTokenService struct {
    samlSP          *samlsp.Middleware
    jwtSigningKey   *rsa.PrivateKey
    jwtIssuer       string
    jwtAudience     string
    tokenExpiration time.Duration
}

func (s *SAMLTokenService) HandleSAMLAssertion(assertion *saml.Assertion) (string, error) {
    // Extract email from SAML attributes
    email := ""
    for _, attr := range assertion.AttributeStatements[0].Attributes {
        if attr.Name == "email" || attr.Name == "urn:oid:0.9.2342.19200300.100.1.3" {
            if len(attr.Values) > 0 {
                email = attr.Values[0].Value
                break
            }
        }
    }

    if email == "" {
        return "", errors.New("email not found in SAML assertion")
    }

    // Create JWT token
    now := time.Now()
    claims := jwt.MapClaims{
        "iss":   s.jwtIssuer,
        "sub":   email,
        "email": email,
        "aud":   s.jwtAudience,
        "exp":   now.Add(s.tokenExpiration).Unix(),
        "iat":   now.Unix(),
        "nbf":   now.Unix(),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    return token.SignedString(s.jwtSigningKey)
}
```

**Pros**:
- Single deployment
- No external dependencies
- Simpler for small deployments

**Cons**:
- Increases Sora complexity
- SAML library maintenance burden
- Less flexible for multiple applications

#### Option C: Use Native OAuth from IdP
- Azure AD, Okta, Google Workspace support OAuth natively
- No SAML-to-OAuth bridge needed
- Clients authenticate directly with IdP OAuth

**Pros**:
- Simplest architecture
- No token service needed
- Leverages IdP capabilities

**Cons**:
- Requires IdP to support OAuth 2.0 Device Flow or similar
- Less control over token claims
- May not work with all IdPs

**Recommendation**: Start with **Option A** (external service) or **Option C** (native IdP OAuth) for production deployments. Implement **Option B** as a future enhancement for easier deployment.

### Phase 4: Testing (Week 4)

#### 4.1. Unit Tests

**New File**: `server/imap/oauth_test.go`

```go
func TestOAuthBearerAuthentication(t *testing.T) {
    // Test cases:
    // 1. Valid token → success
    // 2. Expired token → failure
    // 3. Invalid signature → failure
    // 4. Missing email claim → failure
    // 5. Unknown user → failure
    // 6. Rate limiting → failure
}

func TestTokenValidation(t *testing.T) {
    // Test JWT validation logic
}
```

#### 4.2. Integration Tests

**New File**: `integration_tests/imap/oauth_test.go`

```go
// Test OAuth authentication end-to-end
// Requires mock token service
```

#### 4.3. Client Compatibility Testing

Test with real email clients:
- Thunderbird 78+ (native OAUTHBEARER support)
- Apple Mail (iOS/macOS)
- Outlook Desktop
- Custom IMAP library (Go, Python)

---

## Configuration

### Example Configuration (config.toml)

```toml
# Enable OAuth authentication globally
[oauth]
enabled = true

# JWT token validation settings
[oauth.jwt]
issuer = "https://auth.example.com"
audience = "sora-mail"

# Option 1: Use shared secret (HS256)
# shared_secret = "base64-encoded-secret-key-here"

# Option 2: Use public key (RS256) - RECOMMENDED
public_key_pem = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
"""

# Option 3: Use JWKS URL (RS256) - RECOMMENDED FOR PRODUCTION
jwks_url = "https://auth.example.com/.well-known/jwks.json"
jwks_cache_duration = "1h"

# Option 4: Use token introspection (for opaque tokens)
# introspection_url = "https://auth.example.com/oauth2/introspect"
# introspection_client_id = "sora-introspection-client"
# introspection_client_secret = "secret"

# Clock skew tolerance
clock_skew = "5m"

# IMAP server configuration
[[servers]]
type = "imap"
name = "imap"
addr = ":993"
tls = true
tls_cert_file = "/etc/sora/certs/fullchain.pem"
tls_key_file = "/etc/sora/certs/privkey.pem"

# OAuth is automatically enabled if [oauth] is configured
# No per-server configuration needed

# Optional: disable OAuth for specific server
# [servers.oauth]
# enabled = false

# Rate limiting applies to OAuth attempts too
[servers.auth_rate_limit]
enabled = true
max_attempts_per_ip = 10
max_attempts_per_username = 5
ip_window_duration = "15m"
```

### SAML IdP Configuration (Example: Okta)

1. **Create SAML 2.0 application** in Okta
2. **Configure ACS URL**: `https://auth.example.com/saml/acs`
3. **Set Name ID format**: EmailAddress
4. **Add attribute statements**:
   - Name: `email`, Value: `user.email`
5. **Download SAML metadata XML**
6. **Configure token service** with metadata URL

### Client Configuration (Thunderbird Example)

```
Server Type: IMAP
Server: mail.example.com
Port: 993
Security: SSL/TLS
Authentication: OAuth2
Username: user@example.com
```

When prompted, Thunderbird will:
1. Open browser for authentication
2. Redirect to SAML IdP
3. User logs in with SAML credentials
4. Receive OAuth token
5. Use token with OAUTHBEARER SASL

---

## Security Considerations

### 1. Token Lifetime

**Recommendation**: Keep tokens short-lived (1-6 hours)

**Rationale**:
- Reduces impact of token theft
- Forces regular re-authentication
- Aligns with enterprise security policies

**Implementation**:
- Token Service should set `exp` claim appropriately
- Clients must implement token refresh logic

### 2. Token Storage

**Client-side**:
- Tokens should be stored in OS keychain/credential manager
- Never store in plaintext files
- Clear tokens on explicit logout

**Server-side**:
- Sora does NOT store tokens (stateless validation)
- Rate limiting state stored in PostgreSQL

### 3. Token Revocation

**Challenge**: JWT tokens are stateless and cannot be revoked

**Solutions**:
1. **Short expiration times** (primary defense)
2. **Token blacklist** (optional):
   - Add `revoked_tokens` table in PostgreSQL
   - Check token `jti` claim against blacklist
   - Automatically clean up expired entries
3. **Token introspection** (for critical deployments):
   - Use RFC 7662 introspection endpoint
   - Real-time validation with IdP

### 4. Rate Limiting

OAuth authentication attempts are subject to the same rate limiting as password-based authentication:
- Per-IP limits
- Per-user limits
- Progressive delays
- Fast IP blocking
- Cluster-wide synchronization (if cluster mode enabled)

### 5. Audience Validation

**Critical**: Always validate the `aud` claim

**Why**: Prevents token reuse across different services

**Example**: Token issued for webmail should not work for IMAP

### 6. Scope Validation (Future Enhancement)

**Current**: No scope checking (all authenticated users get full access)

**Future**: Add scope claims to tokens:
- `email.imap.read` - IMAP read access
- `email.imap.write` - IMAP write access
- `email.pop3.read` - POP3 access
- `email.smtp.send` - SMTP access

### 7. TLS Requirements

**OAUTHBEARER MUST be used over TLS** (per RFC 7628)

**Implementation**:
- Reject OAUTHBEARER on non-TLS connections
- Return error: "OAUTHBEARER requires TLS"

### 8. Clock Skew

JWT validation is sensitive to clock differences

**Configuration**: Allow 5 minutes of clock skew by default

**Monitoring**: Alert on excessive clock drift

---

## Testing Strategy

### Unit Tests

1. **Token Validation**:
   - Valid HS256 token
   - Valid RS256 token
   - Expired token
   - Invalid signature
   - Wrong issuer/audience
   - Missing claims

2. **SASL Flow**:
   - Successful authentication
   - Failed authentication
   - Rate limiting
   - Concurrent authentications

3. **Rate Limiting**:
   - OAuth attempts counted correctly
   - Cluster synchronization (if enabled)

### Integration Tests

1. **End-to-End OAuth Flow**:
   - Mock token service
   - Test IMAP AUTHENTICATE OAUTHBEARER
   - Verify session establishment

2. **Client Compatibility**:
   - Thunderbird
   - Apple Mail (simulator)
   - Custom Go IMAP client

3. **Proxy Mode**:
   - OAuth through IMAP proxy
   - OAuth through POP3 proxy

### Security Tests

1. **Token Tampering**:
   - Modified claims
   - Modified signature
   - Replay attacks

2. **Rate Limiting**:
   - Excessive OAuth attempts
   - Distributed attacks (cluster mode)

### Performance Tests

1. **Token Validation Latency**:
   - HS256: <1ms
   - RS256 (cached): <2ms
   - RS256 (JWKS fetch): <100ms
   - Introspection: <200ms

2. **Concurrent Authentications**:
   - 1000 simultaneous OAuth logins
   - Memory usage
   - CPU usage

---

## Migration Path

### Phase 1: Parallel Operation (Months 1-3)

- Deploy with OAuth **disabled by default**
- Run alongside existing password authentication
- Test with pilot users
- Monitor error rates and performance

### Phase 2: Gradual Rollout (Months 3-6)

- Enable OAuth for specific domains
- Encourage migration via email to users
- Maintain password fallback
- Gather user feedback

### Phase 3: OAuth-Primary (Months 6-12)

- Make OAuth the default authentication method
- Password authentication remains for compatibility
- Add warnings for password-only users
- Update documentation and guides

### Phase 4: Password Deprecation (Year 2+)

- **Optional**: Disable password authentication entirely
- Require OAuth for all new accounts
- Maintain password support for special cases (legacy clients)

### Backward Compatibility

- Existing SASL PLAIN authentication remains unchanged
- Clients without OAuth support continue to work
- No breaking changes to existing functionality
- OAuth is purely additive

---

## Open Questions

### 1. Token Service Implementation

**Question**: Should we implement a built-in SAML-to-OAuth token service or document integration with external services?

**Options**:
- **A**: External only (document Keycloak/Auth0 setup)
- **B**: Built-in optional service (adds ~5000 lines of code)
- **C**: Hybrid (external for production, built-in for testing)

**Recommendation**: Start with **Option A**, add **Option B** in future release if demand exists

### 2. Token Refresh Mechanism

**Question**: Should Sora implement OAuth refresh token support?

**Current**: Clients must re-authenticate when token expires

**Alternative**: Support RFC 6749 refresh tokens
- Add refresh token endpoint to token service
- Store refresh tokens in PostgreSQL (encrypted)
- Allow clients to get new access tokens without re-auth

**Recommendation**: Defer to Phase 2 (after initial OAUTHBEARER support stabilizes)

### 3. Multi-Tenancy

**Question**: How should OAuth work in multi-tenant deployments?

**Current Design**: Single issuer/audience for entire Sora instance

**Alternative**: Per-domain OAuth configuration
- Each domain has own IdP
- Different token validation per domain
- More complex configuration

**Recommendation**: Start with single-tenant, add multi-tenant support in future release

### 4. SASL-IR (Initial Response) Support

**Question**: Should we support SASL-IR for OAUTHBEARER?

**Background**: SASL-IR allows client to send token in initial AUTHENTICATE command, reducing round trips

**Implementation**: `go-sasl` library already supports this

**Recommendation**: Yes, implement SASL-IR support for better performance

### 5. Device Flow for Native Apps

**Question**: Should Sora's token service implement OAuth 2.0 Device Flow (RFC 8628)?

**Use Case**: Native email clients without browser (e.g., command-line mail clients)

**Flow**:
1. Client requests device code from token service
2. User visits URL and enters code
3. User authenticates with SAML
4. Client polls for token

**Recommendation**: Defer to Phase 3 (after core OAUTHBEARER support is stable)

### 6. Token Introspection Caching

**Question**: Should we cache token introspection results?

**Trade-offs**:
- **Cache**: Better performance, but revoked tokens may remain valid briefly
- **No cache**: Real-time revocation, but higher latency and IdP load

**Recommendation**: Cache with short TTL (1-5 minutes) and configurable

### 7. Client Registration

**Question**: Should Sora implement OAuth client registration?

**Current**: All clients use same audience (`sora-mail`)

**Alternative**: Dynamic client registration (RFC 7591)
- Each client app gets unique client_id
- Finer-grained access control
- Better auditability

**Recommendation**: Defer to Phase 4 (complex feature, low initial value)

---

## Next Steps

### Immediate Actions

1. **Gather Requirements**:
   - Which SAML IdPs need to be supported?
   - What is the expected token lifetime?
   - Is cluster mode required?

2. **Choose Token Service Approach**:
   - External (Keycloak/Auth0)?
   - Built-in?
   - Native IdP OAuth?

3. **Create Proof of Concept**:
   - Implement OAUTHBEARER SASL in IMAP
   - Mock token validator
   - Test with Thunderbird

4. **Design Review**:
   - Security team review
   - Architecture review
   - User experience review

### Development Timeline

**Week 1-2**: Core OAUTHBEARER in IMAP
**Week 2**: POP3 and ManageSieve support
**Week 3-4**: Token service (if built-in)
**Week 4**: Testing and documentation
**Week 5-6**: Beta testing with pilot users
**Week 7-8**: Bug fixes and performance tuning
**Week 9**: Production release

**Total Estimated Time**: 9 weeks (2+ months)

---

## References

### RFCs and Standards

- **RFC 7628**: SASL OAUTHBEARER and XOAUTH2 mechanisms
- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 7519**: JSON Web Token (JWT)
- **RFC 7662**: OAuth 2.0 Token Introspection
- **RFC 8628**: OAuth 2.0 Device Authorization Grant
- **SAML 2.0**: OASIS standard for identity federation

### Libraries

- **go-sasl** (github.com/emersion/go-sasl): Already in use, supports OAUTHBEARER
- **jwt-go** (github.com/golang-jwt/jwt/v5): JWT parsing and validation
- **go-saml** (github.com/crewjam/saml): SAML 2.0 implementation for Go

### External Services

- **Keycloak**: Open-source identity and access management
- **Okta**: Enterprise identity platform
- **Azure AD**: Microsoft enterprise identity
- **Auth0**: Authentication and authorization platform
- **Google Workspace**: OAuth for Gmail integration

### Email Clients with OAuth Support

- **Thunderbird 78+**: Native OAUTHBEARER support
- **Apple Mail**: iOS 14+ and macOS Big Sur+
- **Outlook**: Desktop and mobile versions
- **Gmail App**: Native OAuth

---

## Appendix A: JWT Token Format Example

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-id-123"
  },
  "payload": {
    "iss": "https://auth.example.com",
    "sub": "user@example.com",
    "aud": "sora-mail",
    "exp": 1699999999,
    "iat": 1699996399,
    "nbf": 1699996399,
    "email": "user@example.com",
    "name": "John Doe",
    "groups": ["employees", "engineering"]
  },
  "signature": "..."
}
```

### Key Claims

- **iss** (issuer): Token service identifier
- **sub** (subject): User's email address (primary identifier)
- **aud** (audience): Must be "sora-mail" or configured value
- **exp** (expiration): Unix timestamp (1-6 hours from iat)
- **iat** (issued at): Unix timestamp
- **nbf** (not before): Unix timestamp
- **email**: User's email (used for account lookup)
- **name**: User's display name (optional, for logging)
- **groups**: User's groups (optional, future use for ACLs)

---

## Appendix B: SAML Assertion Example

```xml
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      user@example.com
    </saml:NameID>
  </saml:Subject>
  <saml:Conditions>
    <saml:NotBefore>2025-11-05T10:00:00Z</saml:NotBefore>
    <saml:NotOnOrAfter>2025-11-05T11:00:00Z</saml:NotOnOrAfter>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>user@example.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="firstName">
      <saml:AttributeValue>John</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="lastName">
      <saml:AttributeValue>Doe</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

Token Service extracts `email` attribute and issues JWT.

---

## Appendix C: OAUTHBEARER Protocol Exchange

```
Client: AUTHENTICATE OAUTHBEARER
Server: +

Client: n,a=user@example.com,^Ahost=mail.example.com^Aport=993^Aauth=Bearer eyJhbGc...^A^A
Server: + eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIn0=

(If token invalid)
Client: ^A
Server: NO Authentication failed

(If token valid)
Server: OK Authentication successful
```

**Breakdown**:
- **n,a=user@example.com**: GS2 header (authzid)
- **^A**: ASCII 0x01 separator
- **host=mail.example.com**: Server hostname
- **port=993**: Server port
- **auth=Bearer eyJ...**: OAuth bearer token
- **^A^A**: End of message

**Error Response** (Base64-decoded):
```json
{
  "status": "invalid_token",
  "schemes": "bearer",
  "scope": "email"
}
```

---

## Conclusion

Integrating OAUTHBEARER with SAML support will position Sora as a modern, enterprise-ready mail server. The implementation is straightforward thanks to existing library support, and the architecture allows for flexible deployment models.

**Key Benefits**:
- ✅ Enterprise SSO integration
- ✅ No password storage in email clients
- ✅ Centralized authentication and MFA enforcement
- ✅ Backward compatible with existing authentication
- ✅ Scalable and secure token validation
- ✅ Standards-compliant (RFC 7628)

**Key Challenges**:
- ⚠️ Token service deployment complexity
- ⚠️ Client compatibility testing
- ⚠️ Token revocation limitations (inherent to JWT)
- ⚠️ Additional monitoring and troubleshooting requirements

**Recommendation**: Proceed with implementation, starting with core OAUTHBEARER support and external token service integration. Built-in SAML bridge can be added in a future release based on user demand.

---

**Questions or Feedback?** Open an issue or discussion on the Sora GitHub repository.
