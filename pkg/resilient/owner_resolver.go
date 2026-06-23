package resilient

import (
	"context"
)

// OwnerDetails holds the cached S3 domain and localpart for an account.
type OwnerDetails struct {
	Domain    string
	Localpart string
}

// OwnerResolver handles resolving the S3 domain and localpart for destination accounts,
// caching the results to avoid repeated database lookups during batch operations (like LMTP or Sieve delivery).
type OwnerResolver struct {
	rdb   *ResilientDatabase
	cache map[int64]OwnerDetails
}

// NewOwnerResolver creates a new OwnerResolver.
func NewOwnerResolver(rdb *ResilientDatabase) *OwnerResolver {
	return &OwnerResolver{
		rdb:   rdb,
		cache: make(map[int64]OwnerDetails),
	}
}

// ResolveDestinationOwner returns the S3 domain and localpart for destAccountID.
// It bypasses lookup and returns currentDomain and currentLocalpart if destAccountID == currentAccountID.
func (r *OwnerResolver) ResolveDestinationOwner(ctx context.Context, destAccountID, currentAccountID int64, currentDomain, currentLocalpart string) (domain, localpart string, err error) {
	if destAccountID == currentAccountID {
		return currentDomain, currentLocalpart, nil
	}

	if details, ok := r.cache[destAccountID]; ok {
		return details.Domain, details.Localpart, nil
	}

	domain, localpart, err = r.rdb.ResolveAccountS3Owner(ctx, destAccountID)
	if err != nil {
		return "", "", err
	}

	r.cache[destAccountID] = OwnerDetails{
		Domain:    domain,
		Localpart: localpart,
	}
	return domain, localpart, nil
}
