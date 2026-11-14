package db

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/migadu/sora/config"
)

// defaultPostgresPort is used for a host entry without a port when the endpoint sets none.
const defaultPostgresPort = 5432

// EndpointURL returns the PostgreSQL URL for one host entry of endpoint and its
// database. The user and password are escaped by net/url, so they may contain any
// character. A host entry that carries a port ("db.example.com:5433",
// "[2001:db8::1]:5433") keeps it; otherwise the endpoint's port applies, 5432 when
// unset. sslmode follows the endpoint's tls setting; callers add further parameters
// to the returned URL's query.
func EndpointURL(endpoint *config.DatabaseEndpointConfig, host string) (*url.URL, error) {
	hostPort, err := endpointHostPort(endpoint, host)
	if err != nil {
		return nil, err
	}
	sslMode := "disable"
	if endpoint.TLSMode {
		sslMode = "require"
	}
	return &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(endpoint.User, endpoint.Password),
		Host:     hostPort,
		Path:     "/" + endpoint.Name,
		RawQuery: url.Values{"sslmode": {sslMode}}.Encode(),
	}, nil
}

func endpointHostPort(endpoint *config.DatabaseEndpointConfig, host string) (string, error) {
	if _, port, err := net.SplitHostPort(host); err == nil && port != "" {
		return host, nil
	}
	port := defaultPostgresPort
	if endpoint.Port != nil {
		var p int64
		switch v := endpoint.Port.(type) {
		case string:
			var err error
			if p, err = strconv.ParseInt(v, 10, 32); err != nil {
				return "", fmt.Errorf("invalid string for port: %q", v)
			}
		case int:
			p = int64(v)
		case int64:
			p = v
		default:
			return "", fmt.Errorf("invalid type for port: %T", v)
		}
		if p <= 0 || p > 65535 {
			return "", fmt.Errorf("port number %d is out of the valid range (1-65535)", p)
		}
		port = int(p)
	}
	// A bare IPv6 address may come with or without brackets; JoinHostPort adds them.
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
