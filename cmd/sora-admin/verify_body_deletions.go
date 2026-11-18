package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
)

func handleVerifyBodyDeletions(ctx context.Context) {
	fs := flag.NewFlagSet("verify body-deletions", flag.ExitOnError)
	hash := fs.String("content-hash", "", "Content hash of the intent to reconcile")
	operation := fs.String("operation-id", "", "Exact operation UUID from the intent listing")
	reconcile := fs.Bool("reconcile", false, "Reconcile one intent after storage operations have been drained")
	drained := fs.Bool("storage-drained", false, "Acknowledge that old requests/writers cannot resume; this is not automatic detection")
	fs.Usage = func() {
		fmt.Print(`List unresolved S3 message-body deletion intents (read-only by default).

Usage:
  sora-admin verify body-deletions
  sora-admin verify body-deletions --reconcile --content-hash HASH --operation-id UUID --storage-drained

Reconciliation requires [s3] body_deletion_protocol = "global-hash-v1" and a
completed operational drain. Protected referenced bodies are downloaded and
verified; orphan-only keys are deleted. An uncertain request keeps the fence.
`)
	}
	if err := fs.Parse(os.Args[3:]); err != nil {
		return
	}
	if err := verifyBodyDeletions(ctx, globalConfig, *hash, *operation, *reconcile, *drained); err != nil {
		fmt.Fprintf(os.Stderr, "Body deletion verification failed: %v\n", err)
		os.Exit(1)
	}
}

func verifyBodyDeletions(ctx context.Context, cfg AdminConfig, hash, operation string, reconcile, drained bool) error {
	if reconcile {
		if hash == "" || operation == "" || !drained {
			return fmt.Errorf("--reconcile requires --content-hash, --operation-id and --storage-drained")
		}
		if err := cfg.S3.RequireBodyDeletionProtocol(); err != nil {
			return err
		}
	} else if hash != "" || operation != "" || drained {
		return fmt.Errorf("intent selection and --storage-drained require --reconcile")
	}
	rdb, err := newAdminDatabase(ctx, &cfg.Database)
	if err != nil {
		return err
	}
	defer rdb.Close()
	if !reconcile {
		intents, err := rdb.ListS3BodyDeleteIntents(ctx)
		if err != nil {
			return err
		}
		for _, i := range intents {
			fmt.Printf("%s %s %s keys=%v", i.ContentHash, i.OperationID, i.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), i.ObjectKeys)
			if i.LastError != nil {
				fmt.Printf(" error=%s", *i.LastError)
			}
			fmt.Println()
		}
		fmt.Printf("%d unresolved deletion intent(s); none modified\n", len(intents))
		return nil
	}
	store, err := newPurgeStorage(cfg)
	if err != nil {
		return err
	}
	if err := reconcileBodyDeletion(ctx, rdb, store, hash, operation, drained); err != nil {
		return err
	}
	fmt.Printf("Reconciled body deletion intent %s for %s\n", operation, hash)
	return nil
}

func reconcileBodyDeletion(ctx context.Context, rdb *resilient.ResilientDatabase, store objectStorage, hash, operation string, drained bool) error {
	return rdb.ReconcileS3BodyDeleteIntent(ctx, hash, operation, drained, func(ctx context.Context, intent db.S3BodyDeleteIntent, required map[string]bool) error {
		for _, key := range intent.ObjectKeys {
			object, err := parseRekeyCursor(key)
			if err != nil || object.ContentHash != intent.ContentHash {
				return fmt.Errorf("intent contains an invalid body key %q", key)
			}
			if required[key] {
				body, err := readStoredBodyContext(ctx, store, key)
				if err != nil {
					return fmt.Errorf("protected body %s must be restored/verified before clearing its fence: %w", key, err)
				}
				kind, _ := classifyStoredBody(body, intent.ContentHash)
				if kind == storedBodyMismatch {
					return fmt.Errorf("protected body %s does not match its content hash", key)
				}
			} else if err := deleteStoredBody(ctx, store, key); err != nil {
				return fmt.Errorf("orphan-only body %s remains quarantined: %w", key, err)
			}
		}
		return nil
	})
}
