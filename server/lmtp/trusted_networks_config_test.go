package lmtp

import (
	"context"
	"strings"
	"testing"
)

// A trusted_networks entry that is neither an IP nor a CIDR fails the server's
// construction (#337). It used to drop the whole list at debug level, so the backend
// admitted no peer and refused all delivery, with nothing above debug to say why.
func TestNewRejectsMalformedTrustedNetworks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b, err := New(ctx, "malformed-trust", "localhost", "127.0.0.1:0", nil, nil, nil, LMTPServerOptions{
		TrustedNetworks: []string{"192.0.2.0/24", "10.0.0.0/33"},
	})
	if err == nil {
		b.Close()
		t.Fatal("New accepted trusted_networks with 10.0.0.0/33; want an error naming it")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/33") {
		t.Errorf("error %q does not name the malformed entry", err)
	}
}
