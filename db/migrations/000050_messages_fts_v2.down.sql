-- Dropping messages_fts_v2 reverts body search to the hash-keyed messages_fts table, which
-- the binary that introduced v2 keeps dual-written for exactly this reason. The extension is
-- left in place: it is trusted, costs nothing unused, and dropping it would fail while any
-- other index depends on it.
DROP TABLE IF EXISTS messages_fts_v2;
