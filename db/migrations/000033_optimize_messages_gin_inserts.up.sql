-- Disable fastupdate on remaining GIN indexes to prevent unpredictable latency spikes.
-- PostgreSQL's GIN index uses a pending list for fast updates. When the list exceeds
-- gin_pending_list_limit, the inserting transaction must synchronously flush the list 
-- to the main index. This can take 20+ seconds, causing massive IMAP APPEND spikes.
--
-- Setting fastupdate = off forces every insert to directly update the GIN tree.
-- While this slightly increases the baseline cost of an insert, it guarantees
-- predictable latency and prevents the random massive timeout spikes during bulk delivery.

ALTER INDEX IF EXISTS idx_messages_recipients_json SET (fastupdate = off);
ALTER INDEX IF EXISTS idx_messages_subject_trgm SET (fastupdate = off);
ALTER INDEX IF EXISTS idx_message_state_custom_flags SET (fastupdate = off);
ALTER INDEX IF EXISTS idx_messages_from_email_sort_trgm SET (fastupdate = off);
ALTER INDEX IF EXISTS idx_messages_from_name_sort_trgm SET (fastupdate = off);
ALTER INDEX IF EXISTS idx_messages_to_email_sort_trgm SET (fastupdate = off);
ALTER INDEX IF EXISTS idx_messages_to_name_sort_trgm SET (fastupdate = off);
ALTER INDEX IF EXISTS idx_messages_cc_email_sort_trgm SET (fastupdate = off);

ALTER INDEX IF EXISTS idx_messages_fts_text_body_tsv SET (fastupdate = off);
