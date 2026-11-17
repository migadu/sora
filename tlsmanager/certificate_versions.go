package tlsmanager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type pendingCertificateVersion struct {
	Version   string    `json:"version"`
	ExpiredAt time.Time `json:"expired_at"`
}

func pendingVersion(state *certificateState, id string, expiry time.Time) {
	if id == "" || id == "null" {
		return
	}
	if !slices.ContainsFunc(state.PendingExpired, func(v pendingCertificateVersion) bool { return v.Version == id }) {
		state.PendingExpired = append(state.PendingExpired, pendingCertificateVersion{id, expiry})
	}
}

// PendingCertificateCleanup exposes only public cleanup intent, never the removed
// certificate/private-key payload. A later clean can finish an interrupted purge.
func PendingCertificateCleanup(raw []byte) (bool, time.Time, error) {
	_, state, err := decodeCertificateState(raw)
	if err != nil {
		return false, time.Time{}, err
	}
	var expiry time.Time
	for _, v := range state.PendingExpired {
		if expiry.IsZero() || v.ExpiredAt.Before(expiry) {
			expiry = v.ExpiredAt
		}
	}
	return len(state.PendingExpired) > 0, expiry, nil
}
func (c *S3Cache) QueueExpiredVersion(ctx context.Context, key, id string, expiry time.Time) error {
	if id == "" || id == "null" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()
	for i := 0; i < 4; i++ {
		data, state, etag, exists, err := c.readState(ctx, key)
		if err != nil {
			return err
		}
		if exists && (strings.TrimSpace(etag) == "" || etag == "*") {
			return errors.New("missing ETag for certificate cleanup intent")
		}
		if !exists {
			state.Absent = true
		}
		if state.Deleted || state.Absent {
			state.Unproven = false
		}
		pendingVersion(&state, id, expiry)
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
	return errors.New("certificate cleanup intent conflicted repeatedly")
}

// CleanupExpiredVersions deletes only immutable historical versions proven expired.
// Current key-free state and valid renewals are kept. Null versions are not immutable
// and are never deleted by version ID. Only intents observed at entry are acknowledged.
func (c *S3Cache) CleanupExpiredVersions(ctx context.Context, key string, now time.Time) (removed int, err error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, initial, _, _, err := c.readState(ctx, key)
	if err != nil {
		return 0, err
	}
	ack := make(map[string]bool, len(initial.PendingExpired))
	for _, v := range initial.PendingExpired {
		ack[v.Version] = true
	}
	var keyMarker, versionMarker *string
	for {
		page, err := c.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(c.bucket), Prefix: aws.String(key), KeyMarker: keyMarker, VersionIdMarker: versionMarker})
		if err != nil {
			return removed, err
		}
		for _, v := range page.Versions {
			if aws.ToString(v.Key) != key {
				continue
			}
			id := aws.ToString(v.VersionId)
			if id == "" || v.IsLatest == nil {
				return removed, errors.New("version listing did not identify immutable historical state")
			}
			if id == "null" || aws.ToBool(v.IsLatest) {
				continue
			}
			result, err := c.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key), VersionId: aws.String(id)})
			if err != nil {
				if missingS3Object(err) {
					continue
				}
				return removed, err
			}
			raw, readErr := io.ReadAll(result.Body)
			closeErr := result.Body.Close()
			if readErr != nil {
				return removed, readErr
			}
			if closeErr != nil {
				return removed, closeErr
			}
			data, state, err := decodeCertificateState(raw)
			if err != nil {
				return removed, err
			}
			if state.Deleted || state.Absent {
				continue
			}
			info, err := parseCertificate(data)
			if err != nil {
				return removed, fmt.Errorf("classify historical certificate version %s: %w", id, err)
			}
			if !now.After(info.NotAfter) {
				continue
			}
			_, err = c.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key), VersionId: aws.String(id)})
			if err != nil && !missingS3Object(err) {
				return removed, err
			}
			removed++
		}
		if !aws.ToBool(page.IsTruncated) {
			break
		}
		if page.NextKeyMarker == nil || (aws.ToString(page.NextKeyMarker) == aws.ToString(keyMarker) && aws.ToString(page.NextVersionIdMarker) == aws.ToString(versionMarker)) {
			return removed, errors.New("version listing did not advance")
		}
		keyMarker, versionMarker = page.NextKeyMarker, page.NextVersionIdMarker
	}
	for i := 0; i < 4; i++ {
		data, state, etag, exists, err := c.readState(ctx, key)
		if err != nil {
			return removed, err
		}
		if !exists {
			return removed, errors.New("certificate cleanup fence disappeared")
		}
		if strings.TrimSpace(etag) == "" || etag == "*" {
			return removed, errors.New("missing ETag while acknowledging certificate cleanup")
		}
		if state.Deleted || state.Absent {
			state.Unproven = false
		}
		state.PendingExpired = slices.DeleteFunc(state.PendingExpired, func(v pendingCertificateVersion) bool { return ack[v.Version] })
		raw, err := encodeCertificateState(data, state)
		if err != nil {
			return removed, err
		}
		err = c.putObjectConditional(ctx, key, raw, etag, true)
		if err == nil {
			return removed, nil
		}
		if !objectConflict(err) {
			return removed, err
		}
	}
	return removed, errors.New("certificate cleanup acknowledgment conflicted repeatedly")
}

// LegacyDeletionMarkerKey returns the legacy deletion marker S3 key for certKey when
// raw carries legacy certificate state whose provenance depends on that marker.
func LegacyDeletionMarkerKey(certKey string, raw []byte) (string, bool) {
	_, state, err := decodeCertificateState(raw)
	if err != nil || state.Generation != "legacy" {
		return "", false
	}
	return deletionMarkerKey(certKey)
}

// DecodeCertificateObjectData decodes an S3 certificate object together with any
// accompanying legacy deletion marker bytes (nil when the marker object is absent).
func DecodeCertificateObjectData(raw, legacyMarker []byte) (data []byte, absent bool, err error) {
	data, state, err := decodeCertificateState(raw)
	if err != nil {
		return nil, false, err
	}
	if state.Generation == "legacy" && legacyMarker != nil {
		at, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(legacyMarker)))
		if parseErr != nil {
			return nil, false, fmt.Errorf("deletion marker: %w", parseErr)
		}
		if !state.Deleted && !state.Absent && len(data) > 0 {
			state.Unproven = true
		} else {
			state.Deleted = true
			state.Absent = true
		}
		state.DeletedAt = at
	}
	absent = state.Deleted || state.Absent
	if !absent && state.Unproven {
		return data, false, errUnprovenSharedCertificate
	}
	return data, absent, nil
}

// IsUnprovenCertificateError reports whether err indicates an unproven legacy shared
// certificate that requires an explicit deletion barrier.
func IsUnprovenCertificateError(err error) bool {
	return errors.Is(err, errUnprovenSharedCertificate)
}

// UnprovenCertificateTombstone reports whether raw is a persisted tombstone that still
// carries the legacy unproven flag and requires MarkDeleted to clear it.
func UnprovenCertificateTombstone(raw []byte) bool {
	_, state, err := decodeCertificateState(raw)
	return err == nil && (state.Deleted || state.Absent) && state.Unproven
}
