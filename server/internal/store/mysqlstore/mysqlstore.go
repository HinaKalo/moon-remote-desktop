// Package mysqlstore implements store.Store on MySQL 8.
package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"moon-remote/server/internal/db"
	"moon-remote/server/internal/store"
)

// Store is the MySQL-backed store.
type Store struct {
	db *db.DB
}

// New wraps an open, migrated database.
func New(d *db.DB) *Store { return &Store{db: d} }

var _ store.Store = (*Store)(nil)

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return store.ErrNotFound
	case db.IsDuplicate(err):
		return store.ErrConflict
	case isForeignKeyMissing(err):
		return store.ErrNotFound
	}
	return err
}

func (s *Store) UpsertUser(ctx context.Context, u store.User) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (sub, display_name, created_at, updated_at)
		VALUES (?, ?, ?, ?) AS new
		ON DUPLICATE KEY UPDATE display_name = new.display_name, updated_at = new.updated_at`,
		u.Sub, u.DisplayName, u.CreatedAt.UTC(), u.UpdatedAt.UTC())
	return mapErr(err)
}

func (s *Store) GetUser(ctx context.Context, sub string) (store.User, error) {
	var u store.User
	err := s.db.QueryRowContext(ctx,
		`SELECT sub, display_name, created_at, updated_at FROM users WHERE sub = ?`, sub).
		Scan(&u.Sub, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt)
	return u, mapErr(err)
}

func (s *Store) CreateDevice(ctx context.Context, d store.Device) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO devices
		(id, user_sub, name, kind, public_key, token_hash, et_host, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.UserSub, d.Name, string(d.Kind), d.PublicKey, d.TokenHash, nullHost(d.ETHost),
		d.CreatedAt.UTC(), d.LastSeenAt.UTC())
	return mapErr(err)
}

const deviceColumns = `id, user_sub, name, kind, public_key, token_hash, et_host, created_at, last_seen_at`

func scanDevice(row interface{ Scan(...any) error }) (store.Device, error) {
	var d store.Device
	var kind string
	var host sql.NullInt64
	err := row.Scan(&d.ID, &d.UserSub, &d.Name, &kind, &d.PublicKey, &d.TokenHash, &host, &d.CreatedAt, &d.LastSeenAt)
	d.Kind = store.DeviceKind(kind)
	if host.Valid {
		d.ETHost = int(host.Int64)
	}
	return d, err
}

func (s *Store) GetDevice(ctx context.Context, userSub, id string) (store.Device, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE id = ? AND user_sub = ?`, id, userSub))
	return d, mapErr(err)
}

func (s *Store) DeviceByTokenHash(ctx context.Context, tokenHash []byte) (store.Device, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE token_hash = ?`, tokenHash))
	return d, mapErr(err)
}

func (s *Store) ListDevices(ctx context.Context, userSub string) ([]store.Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE user_sub = ? ORDER BY created_at, id`, userSub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func affectedOne(res sql.Result, err error) error {
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) RenameDevice(ctx context.Context, userSub, id, name string) error {
	// Renaming to the same name reports 0 affected rows in MySQL, so check existence
	// separately instead of trusting RowsAffected.
	if _, err := s.GetDevice(ctx, userSub, id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET name = ? WHERE id = ? AND user_sub = ?`, name, id, userSub)
	return mapErr(err)
}

func (s *Store) DeleteDevice(ctx context.Context, userSub, id string) error {
	return affectedOne(s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ? AND user_sub = ?`, id, userSub))
}

func (s *Store) TouchDevice(ctx context.Context, id string, at time.Time) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen_at = ? WHERE id = ?`, at.UTC(), id); err != nil {
		return mapErr(err)
	}
	var one int
	return mapErr(s.db.QueryRowContext(ctx, `SELECT 1 FROM devices WHERE id = ?`, id).Scan(&one))
}

func (s *Store) AssignETHost(ctx context.Context, userSub, id string) (int, error) {
	var host int
	err := s.db.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		// Lock the user's device rows so two devices cannot pick the same number.
		rows, err := tx.QueryContext(ctx,
			`SELECT id, et_host FROM devices WHERE user_sub = ? FOR UPDATE`, userSub)
		if err != nil {
			return err
		}
		used := map[int]bool{}
		found := false
		for rows.Next() {
			var rid string
			var h sql.NullInt64
			if err := rows.Scan(&rid, &h); err != nil {
				rows.Close()
				return err
			}
			if rid == id {
				found = true
				if h.Valid {
					host = int(h.Int64)
				}
			}
			if h.Valid {
				used[int(h.Int64)] = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if !found {
			return store.ErrNotFound
		}
		if host != 0 {
			return nil
		}
		for h := store.FirstETHost; h <= store.LastETHost; h++ {
			if !used[h] {
				host = h
				_, err := tx.ExecContext(ctx, `UPDATE devices SET et_host = ? WHERE id = ?`, h, id)
				return err
			}
		}
		return store.ErrFull
	})
	if err != nil {
		return 0, mapErr(err)
	}
	return host, nil
}

const networkColumns = `user_sub, network_name, secret_sealed, cidr, listen_port, created_at`

func scanNetwork(row interface{ Scan(...any) error }) (store.Network, error) {
	var n store.Network
	var port sql.NullInt64
	err := row.Scan(&n.UserSub, &n.NetworkName, &n.SecretSealed, &n.CIDR, &port, &n.CreatedAt)
	if port.Valid {
		n.ListenPort = int(port.Int64)
	}
	return n, err
}

func (s *Store) GetNetwork(ctx context.Context, userSub string) (store.Network, error) {
	n, err := scanNetwork(s.db.QueryRowContext(ctx,
		`SELECT `+networkColumns+` FROM et_networks WHERE user_sub = ?`, userSub))
	return n, mapErr(err)
}

func (s *Store) CreateNetwork(ctx context.Context, n store.Network) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO et_networks (`+networkColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
		n.UserSub, n.NetworkName, n.SecretSealed, n.CIDR, nullHost(n.ListenPort), n.CreatedAt.UTC())
	return mapErr(err)
}

func (s *Store) ListNetworks(ctx context.Context) ([]store.Network, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+networkColumns+` FROM et_networks ORDER BY network_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.Network{}
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func nullHost(h int) sql.NullInt64 {
	if h == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(h), Valid: true}
}
