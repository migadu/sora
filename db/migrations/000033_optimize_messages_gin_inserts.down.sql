ALTER INDEX IF EXISTS idx_messages_recipients_json SET (fastupdate = on);
ALTER INDEX IF EXISTS idx_messages_subject_trgm SET (fastupdate = on);
ALTER INDEX IF EXISTS idx_message_state_custom_flags SET (fastupdate = on);
ALTER INDEX IF EXISTS idx_messages_from_email_sort_trgm SET (fastupdate = on);
ALTER INDEX IF EXISTS idx_messages_from_name_sort_trgm SET (fastupdate = on);
ALTER INDEX IF EXISTS idx_messages_to_email_sort_trgm SET (fastupdate = on);
ALTER INDEX IF EXISTS idx_messages_to_name_sort_trgm SET (fastupdate = on);
ALTER INDEX IF EXISTS idx_messages_cc_email_sort_trgm SET (fastupdate = on);

ALTER INDEX IF EXISTS idx_messages_fts_text_body_tsv SET (fastupdate = on);
