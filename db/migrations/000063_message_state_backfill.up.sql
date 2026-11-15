-- Give every live message a message_state row (#1151).
--
-- Readers LEFT JOIN message_state and show a message without a row as having no flags
-- (COALESCE(ms.flags, 0)), but the rest of Sora only sees messages that have one:
-- SEARCH's flag tests are NULL for it, so SEARCH UNSEEN and NOT SEEN leave it out
-- (RFC 9051 §6.4.4: UNSEEN is "Messages that do not have the \Seen flag set");
-- mailbox_stats.unseen_count, which STATUS UNSEEN reports (§6.3.11), and the
-- first-unseen lookup count only rows; every flag writer UPDATEs the row, so IMAP STORE
-- answered OK and changed nothing and the User API answered 404; and COPY and MOVE gave
-- the copy no row either. Older builds left such messages behind: migration 000022 run
-- without its copy (#613), and `sora-admin messages restore` of a message whose mailbox
-- an older build had purged. Every insert path writes a row, and COPY and MOVE now write
-- one for a source that has none, so repairing the existing rows once is enough.
--
-- The new row holds no flags and no keywords, which is what every reader already showed,
-- so no client sees a change: updated_modseq stays NULL (nothing for CONDSTORE to report).
-- Expunged messages are left alone: restore writes the row of the message it brings back.
--
-- UNSEEN. Whether such a message is already counted in its mailbox's unseen_count depends
-- on how it lost its row, so the message_state INSERT trigger's +1 would count some twice:
-- the messages trigger reads a missing row as no flags, so a restore by an older build
-- counted the message as an unseen arrival, and 000022 without its copy left unseen_count
-- counting the flags it dropped. The unseen_count of each mailbox that gets a row is
-- counted again instead, as RecomputeMailboxUnseen does. Like it, this first locks the
-- mailboxes rows FOR UPDATE (lockMailboxStats, db/mailbox_stats.go), in ascending id order
-- as lockMailboxStatsPair does: the count cannot race a flag change or an expunge, and the
-- locks are taken in the order every other path takes them.
--
-- COST. Finding the messages without a row reads the id of every message, so this
-- migration checks at most 1,000,000 ids by itself: it runs under the migration leader
-- lock, and every other instance gives up after 3 x migration_timeout. On a larger
-- database, run scripts/message_state_backfill.sql first, on the primary over a direct
-- connection (not through a transaction pooler). It checks the ids in batches, each in a
-- transaction of its own, and records how far it got in message_state_backfill; this
-- migration then checks only the ids above that, and drops the table. It can run while
-- the old release serves mail. Without it, a database that large is refused. Counting a
-- mailbox's unseen messages again reads its unseen rows, once per mailbox that gets a row.

DO $$
DECLARE
    checked bigint := 0;
    top bigint;
    ids bigint[];
    boxes bigint[];
BEGIN
    IF to_regclass('message_state_backfill') IS NOT NULL THEN
        SELECT COALESCE(max(checked_through), 0) INTO checked FROM message_state_backfill;
    END IF;
    SELECT COALESCE(max(id), 0) INTO top FROM messages;
    IF top - checked > 1000000 THEN
        RAISE EXCEPTION 'message ids % to % have not been checked for a missing message_state row, more than this migration checks by itself. Run scripts/message_state_backfill.sql (CALL sora_backfill_message_state()), then sora-admin migrate force <previous version> and migrate again; see docs/DATABASE.md, Migration 000063.',
            checked + 1, top;
    END IF;

    -- The statements of sora_backfill_message_state_batch in the script. The ids come from
    -- the primary keys (and message_state); of messages, only the rows of the ids without
    -- a state row are read.
    ids := ARRAY(
        SELECT x.id FROM messages x
        WHERE x.id > checked
          AND NOT EXISTS (SELECT 1 FROM message_state ms
                          WHERE ms.message_id = x.id AND ms.message_id > checked));
    boxes := ARRAY(
        SELECT DISTINCT m.mailbox_id FROM messages m
        WHERE m.id = ANY (ids) AND m.expunged_at IS NULL AND m.mailbox_id IS NOT NULL
        ORDER BY 1);
    IF cardinality(boxes) > 0 THEN
        PERFORM 1 FROM mailboxes WHERE id = ANY (boxes) ORDER BY id FOR UPDATE;
        INSERT INTO message_state (message_id, mailbox_id)
        SELECT m.id, m.mailbox_id
        FROM messages m
        WHERE m.id = ANY (ids)
          AND m.expunged_at IS NULL
          AND m.mailbox_id = ANY (boxes)
        ON CONFLICT (message_id) DO NOTHING;
        WITH unseen AS (
            SELECT ms.mailbox_id, count(*) AS unseen
            FROM message_state ms
            JOIN messages m ON m.id = ms.message_id AND m.mailbox_id = ms.mailbox_id
            WHERE ms.mailbox_id = ANY (boxes) AND (ms.flags & 1) = 0 AND m.expunged_at IS NULL
            GROUP BY ms.mailbox_id
        )
        UPDATE mailbox_stats s
        SET unseen_count = COALESCE(u.unseen, 0), updated_at = now()
        FROM unnest(boxes) AS b(id) LEFT JOIN unseen u ON u.mailbox_id = b.id
        WHERE s.mailbox_id = b.id;
    END IF;

    DROP TABLE IF EXISTS message_state_backfill;
END $$;
