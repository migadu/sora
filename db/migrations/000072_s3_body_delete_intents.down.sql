-- Do not erase a live/uncertain storage fence during a downgrade. The exclusive
-- lock joins the emptiness check and DROP against concurrent intent creation.
DO $$ BEGIN
    LOCK TABLE s3_body_delete_intents IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM s3_body_delete_intents) THEN
        RAISE EXCEPTION 'S3 body deletion intents remain; drain and reconcile them before downgrading';
    END IF;
    DROP TABLE s3_body_delete_intents;
END $$;
