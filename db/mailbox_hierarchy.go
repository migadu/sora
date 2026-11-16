package db

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
)

// The ways a live mailbox's place in the hierarchy (its path) can disagree with its name.
// A mailbox's path is its ancestors' IDs plus its own, each as 16 hex digits; its path
// parent is the row whose path is its path minus the last 16 characters. Its name must be
// that parent's name, '/', and its own last level (compared case-insensitively, as CREATE
// resolves ancestors).
const (
	// HierarchyDetached: linked below a parent whose name is not its name's parent part
	// (a CREATE that raced a RENAME of the parent, issue #1298; a later RENAME of that
	// parent may have rewritten the child's name since). Only the top of a detached
	// subtree is reported.
	HierarchyDetached = "detached"
	// HierarchyRootWithDelimiter: a name with a delimiter but no parent at all (an older
	// CreateMailboxForUser created "Parent/Child" at the top level).
	HierarchyRootWithDelimiter = "root_with_delimiter"
	// HierarchyParentDeleted: the path parent is soft-deleted while this mailbox is live.
	HierarchyParentDeleted = "parent_deleted"
	// HierarchyParentMissing: the path parent row does not exist.
	HierarchyParentMissing = "parent_missing"
	// HierarchyBadPath: path empty, not a multiple of 16, or not ending in the mailbox's ID.
	HierarchyBadPath = "bad_path"
)

// What RepairMailboxHierarchy does about a problem.
const (
	HierarchyActionRepair = "repair" // linked under the mailbox its name names
	HierarchyActionManual = "manual" // left for an administrator: see Reason
	HierarchyActionReport = "report" // reported only (bad_path)
)

// MailboxHierarchyProblem is a live mailbox whose path disagrees with its name.
type MailboxHierarchyProblem struct {
	Problem   string // one of the Hierarchy* problems
	AccountID int64
	Account   string // the account's primary address
	MailboxID int64
	Name      string
	Path      string
	// NameImpliedByPath is the path parent's name (deleted or not), '/', and this
	// mailbox's last level: what the path says its name is. Empty without a path parent.
	NameImpliedByPath string
	// impliedNameMatches: NameImpliedByPath equals Name, as PostgreSQL's LOWER folds them.
	impliedNameMatches bool
}

// MailboxHierarchyRepair is what RepairMailboxHierarchy did (or, in a dry run, would do)
// about a problem.
type MailboxHierarchyRepair struct {
	MailboxHierarchyProblem
	Action string // one of the HierarchyAction* actions
	// Parent is the name of the mailbox it is linked under ("" is the top level) and
	// Created the ancestors created for it, top-down. Set for HierarchyActionRepair.
	Parent  string
	Created []string
	Reason  string // why it is left alone, for HierarchyActionManual and HierarchyActionReport
}

// MaxHierarchyScanAccounts bounds the accounts one FindMailboxHierarchyProblems page reads.
const MaxHierarchyScanAccounts = 10000

// mailboxHierarchyProblemsQuery classifies the live mailboxes of the live accounts in $1
// (bigint[]). Every mailbox it reports is a problem; a mailbox it does not report is
// linked under the mailbox its name names.
const mailboxHierarchyProblemsQuery = `
WITH m AS (
	SELECT c.id,
	       c.account_id,
	       c.name,
	       c.path,
	       strpos(c.name, '/') > 0 AS has_delim,
	       -- the name up to its last '/', and its last level
	       CASE WHEN strpos(c.name, '/') > 0
	            THEN left(c.name, length(c.name) - strpos(reverse(c.name), '/')) END AS name_parent,
	       CASE WHEN strpos(c.name, '/') > 0
	            THEN right(c.name, strpos(reverse(c.name), '/') - 1) ELSE c.name END AS leaf,
	       CASE WHEN length(c.path) > 16 THEN left(c.path, length(c.path) - 16) END AS parent_path
	FROM mailboxes c
	JOIN accounts a ON a.id = c.account_id AND a.deleted_at IS NULL
	WHERE c.account_id = ANY($1::bigint[]) AND c.deleted_at IS NULL
),
chk AS (
	SELECT m.*,
	       p.name AS path_parent_name,
	       CASE
	           WHEN length(m.path) = 0
	             OR length(m.path) % 16 <> 0
	             OR right(m.path, 16) <> lpad(to_hex(m.id), 16, '0')         THEN 'bad_path'
	           WHEN m.parent_path IS NULL AND m.has_delim                     THEN 'root_with_delimiter'
	           WHEN m.parent_path IS NOT NULL AND p.id IS NULL                THEN 'parent_missing'
	           WHEN m.parent_path IS NOT NULL AND p.deleted_at IS NOT NULL    THEN 'parent_deleted'
	           WHEN m.parent_path IS NOT NULL
	            AND (NOT m.has_delim OR lower(p.name) <> lower(m.name_parent)) THEN 'detached'
	       END AS problem
	FROM m
	-- path is unique (it ends in the row's own ID), so this matches at most one row
	LEFT JOIN mailboxes p ON p.account_id = m.account_id AND p.path = m.parent_path
)
SELECT chk.problem,
       chk.account_id,
       COALESCE((SELECT cr.address FROM credentials cr
                  WHERE cr.account_id = chk.account_id AND cr.primary_identity
                  LIMIT 1), ''),
       chk.id,
       chk.name,
       chk.path,
       COALESCE(chk.path_parent_name || '/' || chk.leaf, ''),
       COALESCE(lower(chk.path_parent_name || '/' || chk.leaf) = lower(chk.name), FALSE)
FROM chk
WHERE chk.problem IS NOT NULL
ORDER BY chk.account_id, chk.problem, lower(chk.name), chk.id`

// detectMailboxHierarchyProblems runs mailboxHierarchyProblemsQuery for accountIDs on q.
func detectMailboxHierarchyProblems(ctx context.Context, q rowsQuerier, accountIDs []int64) ([]MailboxHierarchyProblem, error) {
	rows, err := q.Query(ctx, mailboxHierarchyProblemsQuery, accountIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to find mailbox hierarchy problems: %w", err)
	}
	defer rows.Close()
	var problems []MailboxHierarchyProblem
	for rows.Next() {
		var p MailboxHierarchyProblem
		if err := rows.Scan(&p.Problem, &p.AccountID, &p.Account, &p.MailboxID, &p.Name, &p.Path,
			&p.NameImpliedByPath, &p.impliedNameMatches); err != nil {
			return nil, fmt.Errorf("failed to scan mailbox hierarchy problem: %w", err)
		}
		problems = append(problems, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to find mailbox hierarchy problems: %w", err)
	}
	return problems, nil
}

// FindMailboxHierarchyProblems reads up to limit live accounts whose id is above
// afterAccountID, in id order, and returns the problems of their mailboxes and the last
// account id it read (afterAccountID when there are no more accounts). It writes nothing.
// Walk every account by passing the returned id back as afterAccountID.
func (db *Database) FindMailboxHierarchyProblems(ctx context.Context, afterAccountID int64, limit int) ([]MailboxHierarchyProblem, int64, error) {
	if limit < 1 || limit > MaxHierarchyScanAccounts {
		return nil, afterAccountID, fmt.Errorf("limit must be between 1 and %d", MaxHierarchyScanAccounts)
	}
	var accountIDs []int64
	err := db.GetWritePool().QueryRow(ctx, `
		SELECT COALESCE(array_agg(id ORDER BY id), '{}') FROM (
			SELECT id FROM accounts WHERE deleted_at IS NULL AND id > $1 ORDER BY id LIMIT $2
		) a`, afterAccountID, limit).Scan(&accountIDs)
	if err != nil {
		return nil, afterAccountID, fmt.Errorf("failed to list accounts: %w", err)
	}
	if len(accountIDs) == 0 {
		return nil, afterAccountID, nil
	}
	problems, err := detectMailboxHierarchyProblems(ctx, db.GetWritePool(), accountIDs)
	return problems, accountIDs[len(accountIDs)-1], err
}

// RepairMailboxHierarchy repairs the hierarchy of one account's mailboxes, in one
// transaction, and returns what it did about each problem. Without apply it is a dry run:
// it reads, in a read-only transaction, and returns what it would do.
//
// The name is what clients see: LIST, SELECT, APPEND and Sieve fileinto all go by name,
// while \HasChildren, RENAME's cascade to the children and DELETE's refusal of a mailbox
// with children go by path. So a mailbox is moved, with its subtree, under the mailbox
// its name's parent part names (at the top level when its name has no '/'), and its id,
// UIDVALIDITY, messages and subscription stay as they are. Missing ancestors below the
// deepest one that exists are created as CREATE creates them (RFC 9051 section 6.3.4),
// unless the mailbox has a path parent that gives it another name. The CREATE-vs-RENAME
// race or a later RENAME of a parent it was already detached from left it so (before
// issue #1650, renaming "Gam" to "X" turned "Alpha/Beta" below it into "X/a/Beta"), and
// neither name is known to be the one the user meant, so it is left for an administrator
// (HierarchyActionManual). A malformed path is only reported. Problems are handled shallowest name first, so an ancestor's
// repair is in place before its descendants'.
//
// The account's live mailboxes are locked FOR UPDATE first: RENAME and DELETE lock the
// rows they change, and CREATE locks its parent FOR KEY SHARE, so none of them runs
// while the paths change below it. The repair then checks that every mailbox it repaired
// has left the detection and that no other has entered it, or rolls everything back.
func (db *Database) RepairMailboxHierarchy(ctx context.Context, accountID int64, apply bool) ([]MailboxHierarchyRepair, error) {
	txOptions := pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
	if apply {
		txOptions = pgx.TxOptions{}
	}
	tx, err := db.GetWritePool().BeginTx(ctx, txOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	if apply {
		if _, err := tx.Exec(ctx, `
			SELECT 1 FROM mailboxes WHERE account_id = $1 AND deleted_at IS NULL ORDER BY id FOR UPDATE
		`, accountID); err != nil {
			return nil, fmt.Errorf("failed to lock mailboxes: %w", err)
		}
	}

	r := &hierarchyRepairer{db: db, tx: tx, accountID: accountID, apply: apply,
		byID: map[int64]*hierarchyMailbox{}, byLower: map[string]*hierarchyMailbox{}}
	rows, err := tx.Query(ctx, `
		SELECT id, name, LOWER(name), path FROM mailboxes
		WHERE account_id = $1 AND deleted_at IS NULL
	`, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to load mailboxes: %w", err)
	}
	for rows.Next() {
		m := &hierarchyMailbox{}
		if err := rows.Scan(&m.id, &m.name, &m.lower, &m.path); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan mailbox: %w", err)
		}
		r.add(m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to load mailboxes: %w", err)
	}

	problems, err := detectMailboxHierarchyProblems(ctx, tx, []int64{accountID})
	if err != nil {
		return nil, err
	}
	delim := string(consts.MailboxDelimiter)
	sort.SliceStable(problems, func(i, j int) bool {
		di, dj := strings.Count(problems[i].Name, delim), strings.Count(problems[j].Name, delim)
		if di != dj {
			return di < dj
		}
		return problems[i].Name < problems[j].Name
	})

	repairs := make([]MailboxHierarchyRepair, 0, len(problems))
	found, repaired := map[int64]bool{}, map[int64]bool{}
	for _, p := range problems {
		found[p.MailboxID] = true
	}
	for _, p := range problems {
		repair, err := r.repair(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("mailbox %q (id %d): %w", p.Name, p.MailboxID, err)
		}
		if repair.Action == HierarchyActionRepair {
			repaired[p.MailboxID] = true
		}
		repairs = append(repairs, repair)
	}

	if !apply || len(repaired) == 0 {
		return repairs, nil
	}
	left, err := detectMailboxHierarchyProblems(ctx, tx, []int64{accountID})
	if err != nil {
		return nil, err
	}
	for _, p := range left {
		if repaired[p.MailboxID] || !found[p.MailboxID] {
			return nil, fmt.Errorf("mailbox %q (id %d) is %s after the repair; nothing was changed", p.Name, p.MailboxID, p.Problem)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit: %w", err)
	}
	return repairs, nil
}

// hierarchyMailbox is a live mailbox as the repair sees it: lower is its name as
// PostgreSQL's LOWER folds it, the key ancestors are looked up by, as CREATE does.
type hierarchyMailbox struct {
	id    int64
	name  string
	lower string
	path  string
}

// hierarchyRepairer keeps the account's live mailboxes in step with the repairs: a dry
// run makes the same decisions as the repair because it applies them here, in memory,
// with a negative id and a path of non-hex digits for each ancestor it would create.
type hierarchyRepairer struct {
	db        *Database
	tx        pgx.Tx
	accountID int64
	apply     bool
	boxes     []*hierarchyMailbox
	byID      map[int64]*hierarchyMailbox
	byLower   map[string]*hierarchyMailbox
	virtual   int64
}

func (r *hierarchyRepairer) add(m *hierarchyMailbox) {
	r.boxes = append(r.boxes, m)
	r.byID[m.id] = m
	r.byLower[m.lower] = m
}

func (r *hierarchyRepairer) repair(ctx context.Context, p MailboxHierarchyProblem) (MailboxHierarchyRepair, error) {
	res := MailboxHierarchyRepair{MailboxHierarchyProblem: p}
	manual := func(format string, args ...any) (MailboxHierarchyRepair, error) {
		res.Action = HierarchyActionManual
		res.Reason = fmt.Sprintf(format, args...)
		return res, nil
	}

	if p.Problem == HierarchyBadPath {
		res.Action = HierarchyActionReport
		res.Reason = fmt.Sprintf("path %q is malformed", p.Path)
		return res, nil
	}
	m := r.byID[p.MailboxID]
	if m == nil {
		return manual("mailbox changed while the repair ran")
	}

	delim := string(consts.MailboxDelimiter)
	levels := strings.Split(m.name, delim)
	lowerLevels := strings.Split(m.lower, delim)
	if !helpers.MailboxNameValid(m.name) || len(levels) != len(lowerLevels) {
		return manual("%q is not a valid mailbox name", m.name)
	}

	// The deepest ancestor that exists, and the ones below it to create.
	var parent *hierarchyMailbox
	var missing []int
	for i := len(levels) - 1; i >= 1; i-- {
		if a := r.byLower[strings.Join(lowerLevels[:i], delim)]; a != nil {
			parent = a
			break
		}
		missing = append([]int{i}, missing...)
	}
	if len(missing) > 0 && p.NameImpliedByPath != "" && !p.impliedNameMatches {
		return manual("no mailbox %q; its path places it at %q",
			strings.Join(levels[:len(levels)-1], delim), p.NameImpliedByPath)
	}
	if parent != nil {
		if strings.HasPrefix(parent.path, m.path) {
			return manual("its parent %q is inside its own subtree", parent.name)
		}
		if parent.id > 0 && !validMailboxPath(parent.path, parent.id) {
			return manual("its parent %q has a malformed path", parent.name)
		}
	}

	for _, i := range missing {
		created, err := r.create(ctx, strings.Join(levels[:i], delim), strings.Join(lowerLevels[:i], delim), parent)
		if err != nil {
			return res, err
		}
		res.Created = append(res.Created, created.name)
		parent = created
	}
	if err := r.reparent(ctx, m, parent); err != nil {
		return res, err
	}
	res.Action = HierarchyActionRepair
	if parent != nil {
		res.Parent = parent.name
	}
	return res, nil
}

// create creates the ancestor name below parent (nil: at the top level), as CREATE does.
func (r *hierarchyRepairer) create(ctx context.Context, name, lower string, parent *hierarchyMailbox) (*hierarchyMailbox, error) {
	var parentID *int64
	parentPath := ""
	if parent != nil {
		parentID, parentPath = &parent.id, parent.path
	}
	m := &hierarchyMailbox{name: name, lower: lower}
	if !r.apply {
		r.virtual--
		m.id = r.virtual
		m.path = parentPath + fmt.Sprintf("~%d~", -m.id)
		r.add(m)
		return m, nil
	}
	// A mailbox of that name created at the top level since the mailboxes were loaded
	// (the only create that does not wait for the locks) is used as it is.
	if err := r.db.CreateMailbox(ctx, r.tx, r.accountID, name, parentID); err != nil && !errors.Is(err, consts.ErrDBUniqueViolation) {
		return nil, fmt.Errorf("failed to create %q: %w", name, err)
	}
	err := r.tx.QueryRow(ctx, `
		SELECT id, name, path FROM mailboxes
		WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL
	`, r.accountID, name).Scan(&m.id, &m.name, &m.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read back %q: %w", name, err)
	}
	r.add(m)
	return m, nil
}

// reparent links m, with its subtree, below parent (nil: at the top level). Only paths
// change. Soft-deleted rows of the subtree move too, as they do on RENAME.
func (r *hierarchyRepairer) reparent(ctx context.Context, m, parent *hierarchyMailbox) error {
	parentPath := ""
	if parent != nil {
		parentPath = parent.path
	}
	oldPath, newPath := m.path, helpers.GetMailboxPath(parentPath, m.id)
	if r.apply {
		if _, err := r.tx.Exec(ctx, `
			UPDATE mailboxes
			SET path = $3 || SUBSTRING(path FROM LENGTH($2) + 1), updated_at = now()
			WHERE account_id = $1 AND path LIKE $2 || '%'
		`, r.accountID, oldPath, newPath); err != nil {
			return fmt.Errorf("failed to move the subtree: %w", err)
		}
	}
	for _, b := range r.boxes {
		if strings.HasPrefix(b.path, oldPath) {
			b.path = newPath + b.path[len(oldPath):]
		}
	}
	return nil
}

// validMailboxPath reports whether path is well formed for the mailbox id: whole
// 16-digit segments, the last one id's.
func validMailboxPath(path string, id int64) bool {
	return path != "" && len(path)%helpers.HexIDLength == 0 && strings.HasSuffix(path, helpers.FormatMailboxID(id))
}
