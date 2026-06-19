# RFC 4314 (IMAP ACL) Compliance — Gap Fix Plan

Source: 53-agent compliance audit (2026-06-19), adversarially verified against current code
in `sora` + `../go-imap-migadu/go-imap`. 47 requirements: 29 compliant, 6 partial, 8 fail.
Full detail in memory: `rfc4314-acl-compliance-gaps`.

Legend: **[lib]** = fix in go-imap (`../go-imap-migadu/go-imap`); **[sora]** = fix in this repo.
Scope note: nearly all enforcement gaps below only affect **shared-mailbox grantees with restricted
rights** — a mailbox owner holds all rights, so personal mailboxes are unaffected.

---

## Phase 0 — Dev setup & shipping

- [x] Add `RIGHTS=kxte` capability (§2.1/§2.2) — **[lib]** capability.go + `RightSetExtended` in acl.go
- [x] Virtual c/d rights expand/emit (§2.1.1, "latter group") — **[lib]** cmd_acl.go `expandVirtualRights` / `formatRightsWithCompat`
- [x] Point Sora at local go-imap working tree — go.mod `replace ... => ../go-imap-migadu/go-imap` (TEMP, dev only)
- [ ] **Before merge:** publish go-imap, then revert go.mod to a published pseudo-version pin (`go get github.com/migadu/go-imap/v2@<commit>` + `go mod tidy`). The local `replace` must NOT be merged.

---

## Phase 1 — Security / data-integrity (high priority, contained) — ✅ DONE

- [x] **GETACL-01** (§3.3, MUST) — require `a` (admin), not `l`-OR-`a`. Fixed at `server/imap/cmd_acl.go` GetACL (admin-only gate). Owner still passes (implicit `a`). **[sora]**
- [x] **SETACL-02** (§3.1, MUST) — reject unrecognized rights with `BAD` before normalization; prevents the `ZZ`→empty→silent-revoke regression. Up-front validation loop in `server/imap/cmd_acl.go` SetACL (matches RFC examples: "Uppercase rights are not allowed" / "The q right is not supported"). **[sora]**
- [x] **SELSEC-06** (§5.1.1, MUST NOT) — `FETCH BODY[]` (non-PEEK) no longer sets `\Seen` without the `s` right. `server/imap/fetch.go` gates implicit-seen on the `s` right with an owner fast-path (no DB cost for own mailboxes). **[sora]**

Tests: regression tests `TestACL_SetACL_RejectsUnrecognizedRights` + `TestACL_FetchDoesNotImplicitlySetSeenWithoutSeenRight` added; `TestACL_PermissionDenied` updated to assert GETACL denial for lookup-only. All ACL + Seen/Fetch integration tests pass. Adversarially reviewed — no correctness bugs.

---

## Phase 2 — Protocol correctness — ✅ DONE

- [x] **LISTRIGHTS-03** (§3.7, MUST) — Sora `ListRights` returns each right as its own untied single-char group (was one all-or-none bundle of 11). go-imap `writeListRights` emits groups verbatim + standalone `c`/`d` (no per-group compat, no duplicate rights, identifier preserved). **[sora]+[lib]**
- [x] **SELSEC-03** (§5.2, MUST) — added `imap.SelectData.ReadOnly`; go-imap server emits `[READ-ONLY]` on SELECT when `data.ReadOnly`, and the client now parses the READ-ONLY/READ-WRITE code into `SelectData.ReadOnly`. Sora sets `ReadOnly = !any(userRights ∈ {i,e,s,t,w})` (owner fast-path). **[sora]+[lib]**
- [x] **SELSEC-09** (§4, MUST) — go-imap `handleUnselect` swallows a `NO [NOPERM]` from `Expunge` on CLOSE (expunge==true only), so a user lacking `e` gets a clean close + tagged OK and the `\Deleted` messages are left intact. **[lib]**
- [x] **SELSEC-05** (§5.1.1, MUST) — `getPermanentFlags(rights)` filters PERMANENTFLAGS: `\Seen`←`s`, `\Deleted`←`t`, `\Answered`/`\Flagged`/`\Draft`/`\*`←`w`. Owner gets the full set. **[sora]**

Tests: `TestACL_RightsResponseOnSelect` (un-skipped: READ-ONLY/READ-WRITE + PERMANENTFLAGS across lr/lri/lrs/lrw/owner), `TestACL_CloseWithoutExpungeRight`, `TestACL_ListRightsIndividualGroups` — all pass. Updated pre-existing go-imap client test `TestACL/custom_child_folder` (expectation predated the `d`→`x,t,e` expansion). Full go-imap suite + broad Sora sweep (497s) green. Adversarially reviewed — no correctness bugs.

---

## Phase 3 — Partials / robustness — ✅ DONE

- [x] **SETACL-04** (§3.1, MUST) — `prepareACLIdentifier` rejects empty/whitespace/control-char identifiers with `BAD` in SETACL & LISTRIGHTS (DELETEACL via SETACL). Full SASLprep deferred (SHOULD; identifiers are emails/"anyone"). **[sora]**
- [x] **SELSEC-07** (§4) — STORE +FLAGS/-FLAGS applies the permitted flag subset (fails only when the user can modify none). STORE FLAGS (replace) now preserves the current value of flags the user may not modify and applies requested values only for modifiable ones (per-message target, grouped into batches; owner = one batch, unchanged). `server/imap/store.go` + `acl_flags.go`. **[sora]**
- [x] **SELSEC-08** (§4, MUST) — APPEND filters flags by target rights; COPY strips (per flag, batched) any source flag the user can't set on the destination, without failing. New `acl_flags.go` helpers (`userRightsForMailbox`/`flagRightHeld`/`filterFlagsByRights`). **[sora]**
- [x] **SELSEC-10** (§4, MUST) — RENAME requires `k` on the nearest existing ancestor of the new parent (covers both an existing destination parent and one auto-created); same-parent renames skip it. Caught + fixed an auto-create bypass during review. `server/imap/rename.go`. **[sora]**
- [x] **RM-01** (§2.2, MUST NOT) — already satisfied by the Phase 1 SETACL-02 fix (uppercase → `BAD` at the semantics layer). **[done in Phase 1]**

Tests: `TestACL_SetACL_RejectsEmptyIdentifier`, `TestACL_RenameRequiresCreateOnNewParent` (existing parent + auto-create bypass), `TestACL_StoreAppliesPermittedFlagSubset`, `TestACL_CopyFiltersFlagsByRights` — all pass. Full IMAP integration suite + focused hierarchy/flags sweep green. Adversarially reviewed; the one real bug found (RENAME auto-create bypass) was fixed and is now covered by a test.

**Resolved follow-up:** the pre-existing STORE FLAGS (replace) hole — clearing *unlisted* flags the user lacks rights for — is now fixed (see SELSEC-07 above). Verified by `TestACL_StoreReplacePreservesUnmodifiableFlags` and adversarially reviewed (no correctness bugs; minor note: a restricted-user replace with heterogeneous flags now issues one DB transaction per distinct target group instead of one — acceptable, IMAP STORE has no cross-message atomicity guarantee).

---

## Phase 4 — Critic findings — ✅ DONE

- [x] **GETACL owner entry** (§3.3) — `GetACL` synthesizes the owner (full rights) when absent (personal mailboxes), matching the RFC §3.3 example; no-op when the owner row already exists; degrades gracefully (omits the entry) if the owner address can't be resolved rather than failing the command. **[sora]**
- [x] **MYRIGHTS union** (§2) — confirmed real: enforcement (`has_mailbox_right`) unions user-specific + same-domain `anyone` per-right, but `GetUserMailboxRights` reported only the most-specific, so MYRIGHTS *underreported*. Now unions (via `unionRights`), consistent with enforcement — also fixes Phase 2/3 rights checks for `anyone`-granted rights. **[sora]**
- [x] **LISTRIGHTS `anyone`** (§3.4) — skips the account-existence check for special identifiers (`IsSpecialIdentifier`), so `LISTRIGHTS … anyone` succeeds. **[sora]**
- [x] **Negative `-` identifier** (§2) — `prepareACLIdentifier` rejects `-`-prefixed identifiers (negative rights unsupported) with `BAD`, covering SETACL/DELETEACL/LISTRIGHTS. **[sora]**

Tests: `TestACL_GetACLIncludesOwnerOnPersonalMailbox`, `TestACL_MyRightsUnionsAnyone`, `TestACL_ListRightsAcceptsAnyone`, `TestACL_RejectsNegativeIdentifier` — all pass. ACL/shared/flags regression sweep green (172s). Adversarially reviewed; the one finding (GETACL hard-failing on owner-email lookup error) was fixed to degrade gracefully.

**Note:** the full integration suite now runs ~21 min — use `go test -tags=integration -timeout 25m` (the default 10m timeout is exceeded; this is volume, not a hang — confirmed by a clean 1272s run).

---

## Verification (per fix + final)

- [x] go-imap tests: `cd ../go-imap-migadu/go-imap && go test ./...` — green (4 pkgs: imap, imapserver, imapclient, internal). Includes the updated `TestACL/custom_child_folder` and the new `TestACLCapabilityAdvertisesRights`.
- [x] Sora build: `go build ./...` — clean.
- [x] ACL integration tests — `TestACL_RightsResponseOnSelect` un-skipped (Phase 2). NOTE: `run_integration_tests.sh` does not exist in this repo; the real command is `go test -tags=integration -count=1 -timeout 25m ./integration_tests/imap/`. ACL/shared/flags sweep green (172s); final full-suite run in progress.
- [x] Add regression tests for each fixed gap (per-command) — added across Phases 1–4 (see below); go-imap unit tests for `RIGHTS=`/c-d in `imapserver/acl_capability_test.go`.
- [x] Final full-suite run on complete Phase 1–4 code (`-timeout 25m`) — **green: `ok … 1281.427s`, exit 0, no panics/failures.**

### Regression tests added (this session)
- Phase 1: `TestACL_SetACL_RejectsUnrecognizedRights`, `TestACL_FetchDoesNotImplicitlySetSeenWithoutSeenRight`; updated `TestACL_PermissionDenied` (GETACL denial).
- Phase 2: `TestACL_RightsResponseOnSelect` (un-skipped), `TestACL_CloseWithoutExpungeRight`, `TestACL_ListRightsIndividualGroups`; updated go-imap `TestACL/custom_child_folder`.
- Phase 3: `TestACL_SetACL_RejectsEmptyIdentifier`, `TestACL_RenameRequiresCreateOnNewParent` (incl. auto-create bypass), `TestACL_StoreAppliesPermittedFlagSubset`, `TestACL_CopyFiltersFlagsByRights`, `TestACL_StoreReplacePreservesUnmodifiableFlags`.
- Phase 4: `TestACL_GetACLIncludesOwnerOnPersonalMailbox`, `TestACL_MyRightsUnionsAnyone`, `TestACL_ListRightsAcceptsAnyone`, `TestACL_RejectsNegativeIdentifier`.
- go-imap: `TestACLCapabilityAdvertisesRights`, `TestNonACLSessionOmitsRights`, `TestExpandVirtualRights`, `TestFormatRightsWithCompat`.

## Review
_(fill in as fixes land)_
