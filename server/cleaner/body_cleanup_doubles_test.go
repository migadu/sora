package cleaner

import (
	"context"
	"github.com/migadu/sora/db"
	"time"
)

// Adapt existing orchestration doubles to the typed callback. Real PostgreSQL
// tests cover intent persistence and same-connection/exact-row retirement.
func runBodyCleanupDouble(ctx context.Context, rdb interface {
	ExecuteWithLockedS3Orphans(context.Context, []db.UserScopedObjectForCleanup, time.Duration, func(context.Context, []db.UserScopedObjectForCleanup) error) error
	DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(context.Context, []db.UserScopedObjectForCleanup) (int64, error)
}, objects []db.UserScopedObjectForCleanup, grace time.Duration, fn func(context.Context, []db.UserScopedObjectForCleanup) (db.S3BodyCleanupResult, error)) (int64, error) {
	var retired int64
	err := rdb.ExecuteWithLockedS3Orphans(ctx, objects, grace, func(ctx context.Context, orphans []db.UserScopedObjectForCleanup) error {
		result, err := fn(ctx, orphans)
		if err != nil {
			return err
		}
		if len(result.Gone) > 0 {
			retired, err = rdb.DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx, result.Gone)
		}
		return err
	})
	return retired, err
}
func (m *mockDatabase) ExecuteWithS3BodyCleanup(ctx context.Context, objects []db.UserScopedObjectForCleanup, grace time.Duration, fn func(context.Context, []db.UserScopedObjectForCleanup) (db.S3BodyCleanupResult, error)) (int64, error) {
	return runBodyCleanupDouble(ctx, m, objects, grace, fn)
}
func (d *s3ProbeDatabase) ExecuteWithS3BodyCleanup(ctx context.Context, objects []db.UserScopedObjectForCleanup, grace time.Duration, fn func(context.Context, []db.UserScopedObjectForCleanup) (db.S3BodyCleanupResult, error)) (int64, error) {
	return runBodyCleanupDouble(ctx, d, objects, grace, fn)
}
func (f *fakePurgeObjectDB) ExecuteWithS3BodyCleanup(ctx context.Context, objects []db.UserScopedObjectForCleanup, grace time.Duration, fn func(context.Context, []db.UserScopedObjectForCleanup) (db.S3BodyCleanupResult, error)) (int64, error) {
	return runBodyCleanupDouble(ctx, f, objects, grace, fn)
}
