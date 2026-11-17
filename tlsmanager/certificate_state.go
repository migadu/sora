package tlsmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"golang.org/x/crypto/acme/autocert"
)

var ErrCertificateRevoked = errors.New("certificate publication crosses a deletion barrier")
var errExpiredCertificate = errors.New("refusing to publish an expired certificate")
var errUnknownCertificateProvenance = errors.New("local certificate has no proven deletion generation")
var errUnprovenSharedCertificate = errors.New("legacy shared certificate has ambiguous deletion provenance; establish a new explicit deletion barrier after upgrade")

const statePEMType = "SORA CERTIFICATE STATE"

var stateSeparator = []byte("\n-----BEGIN " + statePEMType + "-----\n")

// A deletion changes the generation in the same object the conditional publisher
// replaces. Fingerprints contain no certificate/key bytes. Seen retains previously
// published leaves too: deleting B must also stop a queued older A after A -> B.
type certificateState struct {
	Version        int                         `json:"version"`
	Generation     string                      `json:"generation"`
	Deleted        bool                        `json:"deleted,omitempty"`
	Unproven       bool                        `json:"unproven,omitempty"`
	Absent         bool                        `json:"absent,omitempty"`
	DeletedAt      time.Time                   `json:"deleted_at,omitempty"`
	Seen           []string                    `json:"seen,omitempty"`
	Revoked        []string                    `json:"revoked,omitempty"`
	PendingExpired []pendingCertificateVersion `json:"pending_expired,omitempty"`
}
type publicationGeneration struct {
	Value string `json:"value"`
	Known bool   `json:"known"`
}
type publicationContextKey struct{}

func generationContext(ctx context.Context, g publicationGeneration) context.Context {
	return context.WithValue(ctx, publicationContextKey{}, g)
}
func decodeCertificateState(raw []byte) ([]byte, certificateState, error) {
	s := certificateState{Version: 1, Generation: "legacy"}
	pos := bytes.LastIndex(raw, stateSeparator)
	if pos < 0 {
		return raw, s, nil
	}
	block, rest := pem.Decode(raw[pos+1:])
	if block == nil || block.Type != statePEMType || len(bytes.TrimSpace(rest)) != 0 {
		return nil, s, errors.New("invalid certificate state footer")
	}
	if err := json.Unmarshal(block.Bytes, &s); err != nil {
		return nil, s, err
	}
	if s.Version != 1 || s.Generation == "" {
		return nil, s, errors.New("unsupported certificate state")
	}
	return raw[:pos], s, nil
}
func encodeCertificateState(data []byte, s certificateState) ([]byte, error) {
	// The cache returns original payload bytes; state is retained on the object
	// for certificate, account-key and challenge entries alike.
	if s.Generation == "legacy" && len(s.Seen) == 0 && len(s.Revoked) == 0 && len(s.PendingExpired) == 0 && !s.Deleted && !s.Absent && !s.Unproven {
		return data, nil
	}
	if s.Deleted || s.Absent {
		data = nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), data...)
	out = append(out, '\n')
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: statePEMType, Bytes: b})...)
	return out, nil
}
func certificateFingerprint(data []byte) (string, bool) {
	remaining := data
	for {
		b, rest := pem.Decode(remaining)
		if b == nil {
			break
		}
		remaining = rest
		if b.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(b.Bytes); err == nil {
				h := sha256.Sum256(cert.Raw)
				return "leaf:" + hex.EncodeToString(h[:]), true
			}
		}
	}
	h := sha256.Sum256(data)
	return "entry:" + hex.EncodeToString(h[:]), false
}
func objectConflict(err error) bool {
	var response *awshttp.ResponseError
	return errors.As(err, &response) && (response.HTTPStatusCode() == http.StatusPreconditionFailed || response.HTTPStatusCode() == http.StatusConflict || response.HTTPStatusCode() == http.StatusNotFound)
}

// readState reads the ETag together with the bytes it identifies. A missing ETag
// cannot support conditional replacement and is never silently written over.
func (c *S3Cache) readState(ctx context.Context, key string) ([]byte, certificateState, string, bool, error) {
	result, err := c.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil {
		if missingS3Object(err) {
			state, err := c.applyLegacyDeletion(ctx, key, certificateState{Version: 1, Generation: "legacy"}, nil)
			return nil, state, "", false, err
		}
		return nil, certificateState{}, "", false, err
	}
	defer result.Body.Close()
	raw, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, certificateState{}, "", false, err
	}
	data, state, err := decodeCertificateState(raw)
	if err == nil {
		state, err = c.applyLegacyDeletion(ctx, key, state, data)
	}
	return data, state, aws.ToString(result.ETag), true, err
}
func (c *S3Cache) getSnapshot(ctx context.Context, name string) ([]byte, publicationGeneration, error) {
	if isChallengeCacheKey(name) {
		raw, err := c.getObject(ctx, S3ObjectKey(name))
		if err != nil {
			return nil, publicationGeneration{}, err
		}
		data, state, err := decodeCertificateState(raw)
		if err != nil {
			return nil, publicationGeneration{}, err
		}
		if state.Deleted || state.Absent {
			return nil, publicationGeneration{}, autocert.ErrCacheMiss
		}
		return data, publicationGeneration{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()
	data, state, _, exists, err := c.readState(ctx, S3ObjectKey(name))
	if err != nil {
		return nil, publicationGeneration{}, err
	}
	g := publicationGeneration{Value: state.Generation, Known: true}
	if state.Unproven {
		return nil, g, errUnprovenSharedCertificate
	}
	if !exists || state.Deleted || state.Absent {
		return nil, g, autocert.ErrCacheMiss
	}
	return data, g, nil
}
func (c *S3Cache) putGeneration(ctx context.Context, name string, data []byte, g publicationGeneration) error {
	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()
	key := S3ObjectKey(name)
	// A local file can contain a footer downloaded by older admin cache commands.
	data, _, err := decodeCertificateState(data)
	if err != nil {
		return err
	}
	fp, _ := certificateFingerprint(data)
	info, certificateErr := parseCertificate(data)
	for attempt := 0; attempt < 4; attempt++ {
		current, state, etag, exists, err := c.readState(ctx, key)
		if err != nil {
			return err
		}
		// A conditional conflict may span expiry and CLEAN. Recheck on every
		// attempt rather than republishing an expired snapshot into its vacancy.
		// Account/challenge entries are not certificates and retain their behavior.
		if certificateErr == nil && !time.Now().Before(info.NotAfter) {
			return errExpiredCertificate
		}
		if state.Unproven {
			return errUnprovenSharedCertificate
		}
		if slices.Contains(state.Revoked, fp) {
			return ErrCertificateRevoked
		}
		if !g.Known && state.Generation != "legacy" {
			return errors.Join(ErrCertificateRevoked, errUnknownCertificateProvenance)
		}
		if g.Known && g.Value != state.Generation {
			return ErrCertificateRevoked
		}

		if exists && (strings.TrimSpace(etag) == "" || strings.TrimSpace(etag) == "*") {
			return errors.New("certificate store returned no ETag; refusing unfenced publication")
		}
		if exists && !state.Deleted && !state.Absent {
			if isCertificateCacheKey(name) && olderCertificate(data, current) {
				return nil
			}
			previous, _ := certificateFingerprint(current)
			if !slices.Contains(state.Seen, previous) {
				state.Seen = append(state.Seen, previous)
			}
		}
		if !slices.Contains(state.Seen, fp) {
			state.Seen = append(state.Seen, fp)
		}

		state.Deleted = false
		state.Absent = false
		raw, err := encodeCertificateState(data, state)
		if err != nil {
			return err
		}
		err = c.putObjectConditional(ctx, key, raw, etag, exists)
		if err == nil {
			return nil
		}
		if !objectConflict(err) {
			return err
		}
	}
	return errors.New("certificate publication conflicted repeatedly")
}

// revokeObject replaces the exact entry with a key-free tombstone. It retains
// seen/revoked identities and changes generation; no subsequent physical DELETE
// may erase this authoritative barrier.
func (c *S3Cache) revokeObject(ctx context.Context, key string, at time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()
	for attempt := 0; attempt < 4; attempt++ {
		data, state, etag, exists, err := c.readState(ctx, key)
		if err != nil {
			return err
		}
		if exists && (strings.TrimSpace(etag) == "" || strings.TrimSpace(etag) == "*") {
			return errors.New("certificate store returned no ETag; refusing unfenced deletion")
		}
		if exists && !state.Deleted {
			fp, _ := certificateFingerprint(data)
			if !slices.Contains(state.Seen, fp) {
				state.Seen = append(state.Seen, fp)
			}
		}
		for _, fp := range state.Seen {
			if !slices.Contains(state.Revoked, fp) {
				state.Revoked = append(state.Revoked, fp)
			}
		}
		state.Seen = nil
		state.Unproven = false
		state.Deleted = true
		state.Absent = true
		state.DeletedAt = at.UTC()
		state.Generation = uuid.NewString()
		raw, err := encodeCertificateState(nil, state)
		if err != nil {
			return err
		}
		err = c.putObjectConditional(ctx, key, raw, etag, exists)
		if err == nil {
			return nil
		}
		if !objectConflict(err) {
			return err
		}
	}
	return fmt.Errorf("certificate deletion conflicted repeatedly")
}

// Timestamp-only records from an older deployment are never promoted to proof
// of new issuance. Their stable generation forces unproven local entries to stop.
func (c *S3Cache) applyLegacyDeletion(ctx context.Context, key string, state certificateState, data []byte) (certificateState, error) {
	if state.Generation != "legacy" {
		return state, nil
	}
	marker, ok := deletionMarkerKey(key)
	if !ok {
		return state, nil
	}
	raw, err := c.getObject(ctx, marker)
	if errors.Is(err, autocert.ErrCacheMiss) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	at, err := time.Parse(time.RFC3339Nano, string(bytes.TrimSpace(raw)))
	if err != nil {
		return state, err
	}
	state.Generation = "legacy-deleted:" + at.UTC().Format(time.RFC3339Nano)
	state.DeletedAt = at
	if len(data) > 0 {
		state.Unproven = true
	} else {
		state.Deleted = true
		state.Absent = true
	}

	return state, nil
}

// ExpireObject clears only the exact current expired object. It leaves its
// generation/history in place, so cleaning cannot erase a revocation fence or
// replace a concurrent renewal. It does not revoke a valid unpublished renewal.
func (c *S3Cache) ExpireObject(ctx context.Context, key, expectedETag string, now time.Time, versions ...string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()
	data, state, etag, exists, err := c.readState(ctx, key)
	if err != nil {
		return false, err
	}
	if !exists || state.Deleted || state.Absent {
		return false, nil
	}
	if strings.TrimSpace(expectedETag) == "" || strings.TrimSpace(expectedETag) == "*" || strings.TrimSpace(etag) == "" || strings.TrimSpace(etag) == "*" {
		return false, errors.New("missing ETag for expired certificate")
	}
	if etag != expectedETag {
		return false, nil
	}
	info, err := parseCertificate(data)
	if err != nil {
		return false, err
	}
	if now.Before(info.NotAfter) {
		return false, nil
	}
	state.Absent = true
	state.Unproven = false
	for _, version := range versions {
		pendingVersion(&state, version, info.NotAfter)
	}
	raw, err := encodeCertificateState(nil, state)
	if err != nil {
		return false, err
	}
	err = c.putObjectConditional(ctx, key, raw, etag, true)
	if objectConflict(err) {
		return false, nil
	}
	return err == nil, err
}

func olderCertificate(incoming, current []byte) bool {
	a, aErr := parseCertificate(incoming)
	b, bErr := parseCertificate(current)
	if aErr != nil || bErr != nil {
		return false
	}
	aFP, _ := certificateFingerprint(incoming)
	bFP, _ := certificateFingerprint(current)
	return aFP != bFP && (b.NotBefore.After(a.NotBefore) || (b.NotBefore.Equal(a.NotBefore) && b.NotAfter.After(a.NotAfter)))
}

func missingS3Object(err error) bool {
	var api interface{ ErrorCode() string }
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "NoSuchBucket", "AccessDenied", "InvalidAccessKeyId":
			return false
		case "NoSuchKey", "NoSuchVersion", "NotFound":
			return true
		}
	}
	var response *awshttp.ResponseError
	return errors.As(err, &response) && response.HTTPStatusCode() == http.StatusNotFound
}
