package db

import "context"

func (d *Database) FindExistingContentHashes(ctx context.Context, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	rows, err := d.GetReadPool().Query(ctx, `SELECT content_hash FROM messages WHERE content_hash = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var chash string
		if err := rows.Scan(&chash); err != nil {
			continue // log or ignore individual scan errors
		}
		result = append(result, chash)
	}

	return result, nil
}
