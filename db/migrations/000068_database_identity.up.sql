-- A logical destination identity for resumable imports. PostgreSQL 14+ provides
-- gen_random_uuid() without an extension. This row is data, not a process, host,
-- DSN or pool identity: restarts, replicated failover and backups preserve it.
-- A clone operated as an independent destination must explicitly regenerate it
-- before importing; existing imports must be stopped before that rotation.
CREATE TABLE IF NOT EXISTS public.database_identity (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    identity UUID NOT NULL DEFAULT gen_random_uuid()
);

-- Reapplying Up retains an existing identity. Normal startup serializes
-- migrations through the existing migration-driver advisory lock.
INSERT INTO public.database_identity (singleton) VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;
