-- Revert to the original maintain_mailbox_stats_messages function from migration 000022

CREATE OR REPLACE FUNCTION maintain_mailbox_stats_messages() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        WITH deltas AS (
            SELECT mailbox_id,
                   COUNT(*) AS count_delta,
                   SUM(size) AS size_delta,
                   MAX(created_modseq) AS modseq_val
            FROM new_table
            WHERE expunged_at IS NULL AND mailbox_id IS NOT NULL
            GROUP BY mailbox_id
        )
        INSERT INTO mailbox_stats (mailbox_id, message_count, total_size, highest_modseq, updated_at)
        SELECT mailbox_id, count_delta, size_delta, modseq_val, now() FROM deltas
        ON CONFLICT (mailbox_id) DO UPDATE SET
            message_count = mailbox_stats.message_count + EXCLUDED.message_count,
            total_size = mailbox_stats.total_size + EXCLUDED.total_size,
            highest_modseq = GREATEST(mailbox_stats.highest_modseq, EXCLUDED.highest_modseq),
            updated_at = now();

    ELSIF TG_OP = 'DELETE' THEN
        WITH deltas AS (
            SELECT mailbox_id,
                   COUNT(*) AS count_delta,
                   SUM(size) AS size_delta
            FROM old_table
            WHERE expunged_at IS NULL AND mailbox_id IS NOT NULL
            GROUP BY mailbox_id
        )
        UPDATE mailbox_stats ms
        SET message_count = ms.message_count - d.count_delta,
            total_size = ms.total_size - d.size_delta,
            updated_at = now()
        FROM deltas d
        WHERE ms.mailbox_id = d.mailbox_id;

    ELSIF TG_OP = 'UPDATE' THEN
        WITH deltas AS (
            SELECT
                mb.mailbox_id,
                SUM(mb.count_delta) AS count_delta,
                SUM(mb.unseen_delta) AS unseen_delta,
                SUM(mb.size_delta) AS size_delta,
                MAX(mb.modseq_val) AS max_modseq
            FROM old_table o
            JOIN new_table n ON o.id = n.id
            LEFT JOIN message_state ms ON ms.message_id = n.id
            CROSS JOIN LATERAL (
                SELECT o.mailbox_id AS mailbox_id,
                       -1 AS count_delta,
                       -(1 - COALESCE(ms.flags & 1, 0)) AS unseen_delta,
                       -o.size AS size_delta,
                       0::BIGINT AS modseq_val
                WHERE o.expunged_at IS NULL
                  AND (o.expunged_at IS DISTINCT FROM n.expunged_at OR o.mailbox_id IS DISTINCT FROM n.mailbox_id)
                UNION ALL
                SELECT n.mailbox_id AS mailbox_id,
                       1 AS count_delta,
                       1 - COALESCE(ms.flags & 1, 0) AS unseen_delta,
                       n.size AS size_delta,
                       CASE WHEN o.mailbox_id IS DISTINCT FROM n.mailbox_id THEN COALESCE(n.created_modseq, 0) ELSE 0 END AS modseq_val
                WHERE n.expunged_at IS NULL
                  AND (o.expunged_at IS DISTINCT FROM n.expunged_at OR o.mailbox_id IS DISTINCT FROM n.mailbox_id)
                UNION ALL
                SELECT n.mailbox_id AS mailbox_id,
                       0 AS count_delta,
                       0 AS unseen_delta,
                       0::BIGINT AS size_delta,
                       COALESCE(n.expunged_modseq, 0) AS modseq_val
                WHERE o.expunged_at IS NULL AND n.expunged_at IS NOT NULL
            ) mb
            WHERE mb.mailbox_id IS NOT NULL
            GROUP BY mb.mailbox_id
        )
        UPDATE mailbox_stats ms
        SET message_count = ms.message_count + d.count_delta,
            unseen_count = ms.unseen_count + d.unseen_delta,
            total_size = ms.total_size + d.size_delta,
            highest_modseq = GREATEST(ms.highest_modseq, d.max_modseq),
            updated_at = now()
        FROM deltas d
        WHERE ms.mailbox_id = d.mailbox_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
