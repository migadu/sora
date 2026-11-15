package db

import (
	"net/url"

	"github.com/migadu/sora/config"
)

// EndpointURL returns the PostgreSQL URL for one host entry of endpoint and its
// database. The user and password are escaped by net/url, so they may contain any
// character. A host entry that carries a port ("db.example.com:5433",
// "[2001:db8::1]:5433") keeps it; otherwise the endpoint's port applies, 5432 when
// unset (config.DatabaseEndpointConfig.HostPort, which [database] validation checks
// every host entry with). sslmode follows the endpoint's tls setting; callers add further parameters
// to the returned URL's query.
func EndpointURL(endpoint *config.DatabaseEndpointConfig, host string) (*url.URL, error) {
	hostPort, err := endpoint.HostPort(host)
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
