# Rolling out per-account FTS (migration 000050)

Migration 000050 adds `messages_fts_v2`: one full-text row per (content hash, mailbox owner),
indexed by a multicolumn GIN on `(account_id, text_body_tsv)`. The new binary answers every
body search from this table alone, so on an existing installation it must be **populated
before the new binary serves traffic**.

## Who needs this runbook

| Installation | What happens |
|---|---|
| Fresh install | Nothing to do. The migration creates an empty table and its indexes. |
| `messages_fts` up to 25,000 rows (dev, test, small installs) | Nothing to do. The migration populates `messages_fts_v2` itself. |
| `messages_fts` over 25,000 rows | **Follow this runbook.** The migration refuses to run until the backfill below has completed (it checks `fts_v2_backfill_state`), because applying it earlier would leave body search missing existing mail. |

Why the data matters: `text_body` is nulled the moment its vector is computed, so the tsvector in
`messages_fts` is the **only** copy of the searchable text. It cannot be rebuilt without re-fetching
and re-parsing every body from S3. Treat both tables as data, not as a cache.

## Before you start

- Run every SQL step **directly against the primary on port 5432, never through pgbouncer**.
  The backfill procedures `COMMIT` between batches, which a transaction pooler cannot carry.
- Searches are served by the replicas, so **replica lag is user-visible**: during a lagging
  backfill a search silently returns fewer results. Watch lag the whole time (see *Watch*).
- Do not run a large import or `sora-admin messages restore` during the index build. Those are
  the only long transactions that hold back the build and vacuum.
- Run each `CALL` below **as its own statement**: one `psql -c` per `CALL`, or one per line in an
  interactive session. Several `CALL`s in one `psql -c "...; ..."` run as a single implicit
  transaction, and the procedures' `COMMIT`s fail with `invalid transaction termination`.

## Steps

1. **Create the table and the cheap indexes out-of-band.** The table is empty, so this is instant.
   Do **not** create the composite GIN or the `account_id` index yet: bulk-loading into an existing
   GIN index (with `fastupdate = off`) costs one index insertion per row.

   ```sql
   CREATE EXTENSION IF NOT EXISTS btree_gin;
   CREATE TABLE IF NOT EXISTS messages_fts_v2 (
       content_hash  VARCHAR(64)  NOT NULL,
       account_id    BIGINT       NOT NULL,
       text_body     TEXT,
       text_body_tsv tsvector,
       sent_date     TIMESTAMPTZ,
       created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
       PRIMARY KEY (content_hash, account_id)
   );
   CREATE INDEX IF NOT EXISTS idx_messages_fts_v2_queue ON messages_fts_v2 (created_at)
       WHERE text_body_tsv IS NULL;
   CREATE INDEX IF NOT EXISTS idx_messages_fts_v2_sent_date ON messages_fts_v2 (sent_date)
       WHERE sent_date IS NOT NULL;
   ```

2. **Load the backfill procedures**: `psql -h <primary> -p 5432 -d <db> -f scripts/fts_v2_backfill.sql`.

3. **Backfill, newest mail first.** Each procedure is resumable and idempotent, and prints its
   progress. Start with `(5000, 200)` (batch size, sleep in ms) and raise the sleep the moment
   replica lag grows. Each records its completion in `fts_v2_backfill_state`; `rest` starts
   below the date range `recent` already covered.

   ```sql
   CALL fts_v2_backfill_recent(interval '24 months', 5000, 200);
   ```
   ```sql
   CALL fts_v2_backfill_rest(5000, 200);
   ```

4. **Catch up** on pairs delivered while the backfill ran. The first pass starts from 0: besides
   covering mail delivered during the backfill, it is what keys older shared-mailbox mail on
   the mailbox owner (the backfill itself keys on `messages.account_id`, which keeps it an
   index-only scan). Each pass ends by printing the id to start the next one from; use it,
   instead of rescanning from 0.

   ```sql
   CALL fts_v2_catchup(0);
   ```

5. **Build the remaining indexes** with a plain `CREATE INDEX`, not `CONCURRENTLY`: nothing reads
   or writes the table yet, so the `ShareLock` costs users nothing, and it is one table scan
   instead of two. GIN has no parallel build, so this is single-threaded.

   ```sql
   SET maintenance_work_mem = '2GB';
   CREATE INDEX idx_messages_fts_v2_account_tsv ON messages_fts_v2
       USING gin (account_id, text_body_tsv) WHERE text_body_tsv IS NOT NULL;
   ALTER INDEX idx_messages_fts_v2_account_tsv SET (fastupdate = off);
   CREATE INDEX idx_messages_fts_v2_account_id ON messages_fts_v2 (account_id);
   ```

6. **`ANALYZE messages_fts_v2;`** This is not optional: without statistics the planner has no
   selectivity estimate for `@@` and can pick the whole-corpus plan this change exists to avoid.

7. **Catch up again** from the id the last pass printed, then **verify**:

   ```sql
   SELECT * FROM fts_v2_verification();   -- recent_missing_pairs ~0, rest_done = true
   ```

   It only checks the newest million messages (pass a different count as its argument), and
   table sizes are planner estimates: a full count would be one long query holding a snapshot
   on the primary right before the deploy. Full coverage is shown by the catch-up reporting 0
   rows twice in a row.

   Confirm all replicas have caught up and carry the table and index. A replica without the table
   fails every search with `relation "messages_fts_v2" does not exist`.

8. **Deploy the new binary** (rolling). Migration 000050 finds the backfill recorded and the
   indexes present, checks their shape, and takes no lock that could queue behind the catch-up.

   Deliberately backfilling only recent mail (older mail stays unsearchable by body) is allowed,
   but must be recorded before the deploy, or the migration refuses:
   `INSERT INTO fts_v2_backfill_state (step) VALUES ('accept_partial');`

9. **Keep running the catch-up during the rollout** until it reports 0 rows twice in a row. Old
   nodes write only `messages_fts`, so they keep producing work until the last one has rolled.

## Rollback

During the soak the new binary keeps writing `messages_fts` as well, so rolling back is a binary
rollback only: the old binary starts fine against schema version 50 and never reads the new table.

**After any rollback, before rolling forward again, run the catch-up once more.** While the old
binary runs nothing writes `messages_fts_v2`, and nothing re-syncs it when the new binary returns.

Do not run migration 000051 (which retires `messages_fts`) until the soak is over: after it, a
rollback means a restore.

## Watch

```sql
-- replica lag, from the primary
SELECT application_name, state, replay_lag FROM pg_stat_replication;
-- index build progress
SELECT phase, blocks_done, blocks_total, tuples_done, tuples_total FROM pg_stat_progress_create_index;
-- anything blocked
SELECT pid, state, wait_event_type, wait_event, left(query, 80), now() - xact_start AS age
FROM pg_stat_activity WHERE state <> 'idle' ORDER BY age DESC LIMIT 20;
-- FTS worker backlog after the deploy: should trend to 0
SELECT count(*) FROM messages_fts_v2 WHERE text_body_tsv IS NULL AND created_at < now() - interval '10 min';
```

From Sora: `sora_fts_queue_depth`, LMTP delivery latency, and on the replicas any
`conflict with recovery` cancellations.
