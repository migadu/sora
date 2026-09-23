-- Remove IMAP keywords that are not encodable as a flag, and the wedged mailboxes
-- they leave behind.
--
-- RFC 9051 §9: flag-keyword is an atom, and atom is 1*ATOM-CHAR over CHAR
-- (%x01-7F), excluding atom-specials -- so a keyword is printable ASCII with
-- none of ( ) { SP % * " \ ]. Until the application-side check that now lives in
-- helpers.IsValidFlagName, one path bypassed every IMAP parser: Sieve's
-- imap4flags `addflag`/`setflag` (RFC 5232). A script such as
--
--     require ["imap4flags"];
--     addflag "НЕОБРАБОТЕНО";
--
-- stored that keyword on message_state.custom_flags, and the mailbox_stats
-- trigger unioned it into the mailbox's custom_flags_cache -- the per-mailbox
-- keyword registry SELECT advertises in * FLAGS (...).
--
-- The registry is union-only (see migration 000037): no trigger branch and no
-- code path has ever removed a keyword from it. So the damage outlived both the
-- Sieve rule and the messages: on SELECT, the encoder rejected the keyword
-- mid-list, and because encoder errors are sticky the untagged response was
-- never terminated and never flushed. The client got silence and eventually gave
-- up -- the mailbox was unopenable by every IMAP client, permanently, while
-- STATUS and POP3 (which do not advertise flags) kept working.
--
-- The application now filters these on read, so an affected mailbox opens again
-- as soon as the new code is deployed. This migration removes the stored values
-- so the database stops carrying data no IMAP response can express, and so the
-- registry cannot re-poison a mailbox via the trigger's UPDATE branch when an
-- affected message is later restored, moved or copied.

-- Matches a valid keyword: printable ASCII only (which excludes CTL, SP and
-- every non-ASCII byte), and none of the atom-specials. Note "}" is allowed and
-- "{" is not -- only the opening brace is an atom-special. This mirrors
-- helpers.isAtomChar exactly; the two are checked against the same table of
-- cases in TestIsValidFlagName.
CREATE OR REPLACE FUNCTION sora_is_valid_imap_keyword(kw text) RETURNS boolean AS $$
    SELECT kw <> ''
       AND kw ~ '^[\x21-\x7e]+$'
       AND kw !~ '[()\{%*"\\\]]';
$$ LANGUAGE sql IMMUTABLE;

-- 1. The messages. Poisoned rows are found through the registry rather than by
--    scanning message_state: the registry is union-only, so every keyword ever
--    set on a message in a mailbox is in that mailbox's registry (MOVE and COPY
--    union into the destination's as well). That makes it an exact index of the
--    mailboxes worth visiting, and the per-mailbox b-tree from migration 000039
--    serves the rest, so this touches a handful of mailboxes instead of the whole
--    table. ARRAY(subquery) is evaluated once, ahead of the scan, which keeps the
--    planner on the index whatever it guesses about the jsonb predicate.
--
--    This step must run before the registry is cleaned, since the registry is
--    what locates the rows. Soft-deleted (expunged) rows are covered on purpose:
--    `messages restore` or a MOVE would otherwise carry the keyword back into a
--    cleaned registry through the stats trigger.
--
--    A row whose mailbox registry never recorded the keyword (a NULL cache that
--    predates migration 000024's backfill) is not visited. That is harmless: the
--    application filters these keywords on every read path, so this migration is
--    hygiene, not what makes an affected mailbox usable again.
UPDATE message_state ms
SET custom_flags = (
        SELECT COALESCE(jsonb_agg(flag ORDER BY flag), '[]'::jsonb)
        FROM jsonb_array_elements_text(ms.custom_flags) AS elem(flag)
        WHERE sora_is_valid_imap_keyword(flag)
    )
WHERE ms.mailbox_id = ANY (ARRAY(
        SELECT mstats.mailbox_id
        FROM mailbox_stats mstats
        WHERE mstats.custom_flags_cache IS NOT NULL
          AND EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(mstats.custom_flags_cache) AS elem(flag)
                WHERE left(flag, 1) <> '\' AND NOT sora_is_valid_imap_keyword(flag)
            )
    ))
  AND ms.custom_flags IS NOT NULL
  AND ms.custom_flags <> '[]'::jsonb
  AND EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(ms.custom_flags) AS elem(flag)
        WHERE NOT sora_is_valid_imap_keyword(flag)
    );

-- 2. The per-mailbox keyword registry -- the one SELECT advertises. One row per
--    mailbox, so a plain pass is cheap. System flags (leading backslash) are
--    kept as they are.
UPDATE mailbox_stats
SET custom_flags_cache = (
        SELECT COALESCE(jsonb_agg(flag ORDER BY flag), '[]'::jsonb)
        FROM jsonb_array_elements_text(custom_flags_cache) AS elem(flag)
        WHERE left(flag, 1) = '\' OR sora_is_valid_imap_keyword(flag)
    ),
    updated_at = now()
WHERE custom_flags_cache IS NOT NULL
  AND EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(custom_flags_cache) AS elem(flag)
        WHERE left(flag, 1) <> '\' AND NOT sora_is_valid_imap_keyword(flag)
    );

DROP FUNCTION sora_is_valid_imap_keyword(text);
