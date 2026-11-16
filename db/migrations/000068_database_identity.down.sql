-- Remove the logical destination identity. A subsequent Up generates a NEW UUID;
-- completion records for the previous identity must not suppress that new import.
-- Stop binaries/importers using the identity before dropping or rotating it.
DROP TABLE IF EXISTS public.database_identity;
