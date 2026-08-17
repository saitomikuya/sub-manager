package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Settings struct {
	PasswordHash     []byte
	MustChange       bool
	SessionVersion   int
	LogRetentionDays int
	TrustedProxies   string
}

type Session struct {
	CSRFToken string
	Version   int
	ExpiresAt time.Time
}

type Subscription struct {
	ID            int64
	Name          string
	Path          string
	Content       string
	Enabled       bool
	FetchCount    int64
	LastFetchedAt *time.Time
	LastFetchedIP string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type AccessLog struct {
	ID             int64
	SubscriptionID int64
	RequestedAt    time.Time
	ClientIP       string
	ClientName     string
	UserAgent      string
	Method         string
	StatusCode     int
}

type LogPage struct {
	Logs       []AccessLog
	Total      int
	Page       int
	PageSize   int
	TotalPages int
}

func OpenStore(path string, defaultPasswordHash []byte, defaultRetention int) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// Serializing writes keeps counters and logs consistent while remaining ample
	// for the intended small self-hosted deployment.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}

	s := &Store{db: db}
	if err := s.migrate(defaultPasswordHash, defaultRetention); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) migrate(defaultPasswordHash []byte, defaultRetention int) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			password_hash BLOB NOT NULL,
			must_change_password INTEGER NOT NULL DEFAULT 1,
			session_version INTEGER NOT NULL DEFAULT 1,
			log_retention_days INTEGER NOT NULL DEFAULT 90,
			trusted_proxies TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS subscriptions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL UNIQUE,
			content TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			fetch_count INTEGER NOT NULL DEFAULT 0,
			last_fetched_at TEXT,
			last_fetched_ip TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS access_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
			requested_at TEXT NOT NULL,
			client_ip TEXT NOT NULL,
			client_name TEXT NOT NULL,
			user_agent TEXT NOT NULL,
			method TEXT NOT NULL,
			status_code INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_access_logs_subscription_time ON access_logs(subscription_id, requested_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip ON access_logs(client_ip)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token_hash BLOB PRIMARY KEY,
			csrf_token TEXT NOT NULL,
			version INTEGER NOT NULL,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("database migration: %w", err)
		}
	}
	now := dbTime(time.Now())
	_, err := s.db.Exec(`INSERT OR IGNORE INTO settings
		(id, password_hash, must_change_password, session_version, log_retention_days, trusted_proxies, created_at, updated_at)
		VALUES (1, ?, 1, 1, ?, '', ?, ?)`, defaultPasswordHash, defaultRetention, now, now)
	return err
}

func (s *Store) Settings(ctx context.Context) (Settings, error) {
	var out Settings
	var mustChange int
	err := s.db.QueryRowContext(ctx, `SELECT password_hash, must_change_password, session_version,
		log_retention_days, trusted_proxies FROM settings WHERE id = 1`).Scan(
		&out.PasswordHash, &mustChange, &out.SessionVersion, &out.LogRetentionDays, &out.TrustedProxies)
	out.MustChange = mustChange != 0
	return out, err
}

func (s *Store) ChangePassword(ctx context.Context, hash []byte) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE settings SET password_hash = ?, must_change_password = 0,
		session_version = session_version + 1, updated_at = ? WHERE id = 1`, hash, dbTime(time.Now())); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return 0, err
	}
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT session_version FROM settings WHERE id = 1`).Scan(&version); err != nil {
		return 0, err
	}
	return version, tx.Commit()
}

func (s *Store) UpdateSettings(ctx context.Context, retention int, trustedProxies string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE settings SET log_retention_days = ?, trusted_proxies = ?, updated_at = ? WHERE id = 1`,
		retention, trustedProxies, dbTime(time.Now()))
	return err
}

func (s *Store) CreateSession(ctx context.Context, rawToken, csrf string, version int, expires time.Time) error {
	hash := sha256.Sum256([]byte(rawToken))
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash, csrf_token, version, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)`, hash[:], csrf, version, dbTime(expires), dbTime(time.Now()))
	return err
}

func (s *Store) Session(ctx context.Context, rawToken string) (Session, error) {
	hash := sha256.Sum256([]byte(rawToken))
	var out Session
	var expires string
	err := s.db.QueryRowContext(ctx, `SELECT s.csrf_token, s.version, s.expires_at
		FROM sessions s JOIN settings cfg ON cfg.id = 1
		WHERE s.token_hash = ? AND s.version = cfg.session_version AND s.expires_at > ?`, hash[:], dbTime(time.Now())).Scan(
		&out.CSRFToken, &out.Version, &expires)
	if err != nil {
		return Session{}, err
	}
	out.ExpiresAt, err = parseDBTime(expires)
	return out, err
}

func (s *Store) DeleteSession(ctx context.Context, rawToken string) error {
	hash := sha256.Sum256([]byte(rawToken))
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hash[:])
	return err
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, dbTime(time.Now()))
	return err
}

func (s *Store) ListSubscriptions(ctx context.Context) ([]Subscription, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, path, content, enabled, fetch_count,
		last_fetched_at, last_fetched_ip, created_at, updated_at FROM subscriptions ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Subscription
	for rows.Next() {
		sub, err := scanSubscription(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scanSubscription(row scanner) (Subscription, error) {
	var sub Subscription
	var enabled int
	var lastFetched sql.NullString
	var created, updated string
	err := row.Scan(&sub.ID, &sub.Name, &sub.Path, &sub.Content, &enabled, &sub.FetchCount,
		&lastFetched, &sub.LastFetchedIP, &created, &updated)
	if err != nil {
		return sub, err
	}
	sub.Enabled = enabled != 0
	sub.CreatedAt, err = parseDBTime(created)
	if err != nil {
		return sub, err
	}
	sub.UpdatedAt, err = parseDBTime(updated)
	if err != nil {
		return sub, err
	}
	if lastFetched.Valid {
		t, parseErr := parseDBTime(lastFetched.String)
		if parseErr != nil {
			return sub, parseErr
		}
		sub.LastFetchedAt = &t
	}
	return sub, nil
}

func (s *Store) SubscriptionByID(ctx context.Context, id int64) (Subscription, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, path, content, enabled, fetch_count,
		last_fetched_at, last_fetched_ip, created_at, updated_at FROM subscriptions WHERE id = ?`, id)
	return scanSubscription(row)
}

func (s *Store) SubscriptionByPath(ctx context.Context, path string) (Subscription, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, path, content, enabled, fetch_count,
		last_fetched_at, last_fetched_ip, created_at, updated_at FROM subscriptions WHERE path = ? AND enabled = 1`, path)
	return scanSubscription(row)
}

func (s *Store) CreateSubscription(ctx context.Context, name, path, content string, enabled bool) (int64, error) {
	now := dbTime(time.Now())
	result, err := s.db.ExecContext(ctx, `INSERT INTO subscriptions(name, path, content, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`, name, path, content, boolInt(enabled), now, now)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) UpdateSubscription(ctx context.Context, id int64, name, path, content string, enabled bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE subscriptions SET name = ?, path = ?, content = ?, enabled = ?, updated_at = ? WHERE id = ?`,
		name, path, content, boolInt(enabled), dbTime(time.Now()), id)
	if err != nil {
		return err
	}
	return expectOne(result)
}

func (s *Store) DeleteSubscription(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM subscriptions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return expectOne(result)
}

func (s *Store) SetSubscriptionEnabled(ctx context.Context, id int64, enabled bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE subscriptions SET enabled = ?, updated_at = ? WHERE id = ?`,
		boolInt(enabled), dbTime(time.Now()), id)
	if err != nil {
		return err
	}
	return expectOne(result)
}

func (s *Store) BatchUpdateContent(ctx context.Context, ids []int64, content string) (int64, error) {
	if len(ids) == 0 {
		return 0, errors.New("no subscriptions selected")
	}
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+2)
	args = append(args, content, dbTime(time.Now()))
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	countArgs := make([]any, len(ids))
	for i, id := range ids {
		countArgs[i] = id
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscriptions WHERE id IN (`+strings.Join(placeholders, ",")+`)`, countArgs...).Scan(&existing); err != nil {
		return 0, err
	}
	if existing != len(ids) {
		return 0, sql.ErrNoRows
	}
	query := `UPDATE subscriptions SET content = ?, updated_at = ? WHERE id IN (` + strings.Join(placeholders, ",") + `)`
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if updated != int64(len(ids)) {
		return 0, fmt.Errorf("batch update affected %d of %d subscriptions", updated, len(ids))
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return updated, nil
}

func (s *Store) RecordAccess(ctx context.Context, subscriptionID int64, ip, client, userAgent, method string, status int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := dbTime(time.Now())
	result, err := tx.ExecContext(ctx, `UPDATE subscriptions SET fetch_count = fetch_count + 1,
		last_fetched_at = ?, last_fetched_ip = ? WHERE id = ?`, now, ip, subscriptionID)
	if err != nil {
		return err
	}
	if err := expectOne(result); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_logs
		(subscription_id, requested_at, client_ip, client_name, user_agent, method, status_code)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, subscriptionID, now, ip, client, userAgent, method, status); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AccessLogs(ctx context.Context, subscriptionID int64, page, pageSize int, ip, client string) (LogPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	where := []string{"subscription_id = ?"}
	args := []any{subscriptionID}
	if ip != "" {
		where = append(where, "client_ip LIKE ?")
		args = append(args, "%"+ip+"%")
	}
	if client != "" {
		where = append(where, "client_name = ?")
		args = append(args, client)
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_logs WHERE `+clause, args...).Scan(&total); err != nil {
		return LogPage{}, err
	}
	queryArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, `SELECT id, subscription_id, requested_at, client_ip,
		client_name, user_agent, method, status_code FROM access_logs WHERE `+clause+`
		ORDER BY requested_at DESC, id DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return LogPage{}, err
	}
	defer rows.Close()
	out := LogPage{Total: total, Page: page, PageSize: pageSize}
	if total > 0 {
		out.TotalPages = (total + pageSize - 1) / pageSize
	}
	for rows.Next() {
		var log AccessLog
		var requested string
		if err := rows.Scan(&log.ID, &log.SubscriptionID, &requested, &log.ClientIP, &log.ClientName,
			&log.UserAgent, &log.Method, &log.StatusCode); err != nil {
			return LogPage{}, err
		}
		log.RequestedAt, err = parseDBTime(requested)
		if err != nil {
			return LogPage{}, err
		}
		out.Logs = append(out.Logs, log)
	}
	return out, rows.Err()
}

func (s *Store) ClearAccessLogs(ctx context.Context, subscriptionID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM access_logs WHERE subscription_id = ?`, subscriptionID)
	return err
}

func (s *Store) CleanupLogs(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := dbTime(time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour))
	result, err := s.db.ExecContext(ctx, `DELETE FROM access_logs WHERE requested_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func expectOne(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func dbTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseDBTime(value string) (time.Time, error) { return time.Parse(time.RFC3339Nano, value) }
