package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Repository struct {
	db *sql.DB
}

type CleanupResult struct {
	DeletedRefreshTokens int64 `json:"deleted_refresh_tokens"`
	DeletedLoginAttempts int64 `json:"deleted_login_attempts"`
	DeletedIPLimits      int64 `json:"deleted_ip_limits"`
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) GetByUsername(ctx context.Context, username string) (User, error) {
	var user User
	err := r.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, created_at, updated_at
		FROM users
		WHERE username = $1
	`, username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, err
		}
		return User{}, fmt.Errorf("query user by username: %w", err)
	}

	return user, nil
}

func (r *Repository) UpsertSingleUser(ctx context.Context, username, plainPassword string) error {
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate uuid v7: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var existingID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM users ORDER BY created_at ASC LIMIT 1`).Scan(&existingID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			existingID = id.String()
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO users (id, username, password_hash, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $4)
			`, existingID, username, string(hash), now); err != nil {
				return fmt.Errorf("insert admin user: %w", err)
			}
		} else {
			return fmt.Errorf("select existing user: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			UPDATE users
			SET username = $2, password_hash = $3, updated_at = $4
			WHERE id = $1
		`, existingID, username, string(hash), now); err != nil {
			return fmt.Errorf("update admin user: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id <> $1`, existingID); err != nil {
		return fmt.Errorf("cleanup extra users: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func (r *Repository) GetLoginAttempt(ctx context.Context, username string) (LoginAttempt, error) {
	var attempt LoginAttempt
	attempt.Username = username

	var lockedUntil sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT failed_attempts, locked_until
		FROM auth_login_attempts
		WHERE username = $1
	`, username).Scan(&attempt.FailedAttempts, &lockedUntil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return attempt, nil
		}
		return LoginAttempt{}, fmt.Errorf("query login attempt: %w", err)
	}
	if lockedUntil.Valid {
		value := lockedUntil.Time.UTC()
		attempt.LockedUntil = &value
	}

	return attempt, nil
}

func (r *Repository) RegisterFailedAttempt(ctx context.Context, username string, maxAttempts int, lockDuration time.Duration, now time.Time) (*time.Time, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin login attempt tx: %w", err)
	}
	defer tx.Rollback()

	var failed int
	var lockedUntil sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT failed_attempts, locked_until
		FROM auth_login_attempts
		WHERE username = $1
		FOR UPDATE
	`, username).Scan(&failed, &lockedUntil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			failed = 0
			lockedUntil = sql.NullTime{}
		} else {
			return nil, fmt.Errorf("lock login attempt row: %w", err)
		}
	}

	if lockedUntil.Valid && now.Before(lockedUntil.Time) {
		until := lockedUntil.Time.UTC()
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit existing lock tx: %w", err)
		}
		return &until, nil
	}

	failed++
	var nextLock *time.Time
	var nextLockValue any = nil
	if failed >= maxAttempts {
		until := now.UTC().Add(lockDuration)
		nextLock = &until
		nextLockValue = until
		failed = 0
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO auth_login_attempts (username, failed_attempts, locked_until, updated_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (username)
		DO UPDATE SET
			failed_attempts = EXCLUDED.failed_attempts,
			locked_until = EXCLUDED.locked_until,
			updated_at = EXCLUDED.updated_at
	`, username, failed, nextLockValue, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("upsert failed login attempt: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit login attempt tx: %w", err)
	}

	return nextLock, nil
}

func (r *Repository) ResetLoginAttempt(ctx context.Context, username string) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM auth_login_attempts
		WHERE username = $1
	`, username)
	if err != nil {
		return fmt.Errorf("reset login attempts: %w", err)
	}

	return nil
}

func (r *Repository) CreateRefreshToken(ctx context.Context, userID, rawToken string, expiresAt time.Time) error {
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate refresh token id: %w", err)
	}

	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO auth_refresh_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, id.String(), userID, tokenHash, expiresAt.UTC())
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}

	return nil
}

func (r *Repository) RotateRefreshToken(ctx context.Context, rawOldToken, rawNewToken string, newExpiresAt time.Time) (string, error) {
	hashOld := sha256.Sum256([]byte(rawOldToken))
	oldHash := hex.EncodeToString(hashOld[:])

	hashNew := sha256.Sum256([]byte(rawNewToken))
	newHash := hex.EncodeToString(hashNew[:])

	newID, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate new refresh token id: %w", err)
	}

	now := time.Now().UTC()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin refresh rotation tx: %w", err)
	}
	defer tx.Rollback()

	var oldID string
	var userID string
	var expiresAt time.Time
	var revokedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT id, user_id, expires_at, revoked_at
		FROM auth_refresh_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, oldHash).Scan(&oldID, &userID, &expiresAt, &revokedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrInvalidRefreshToken
		}
		return "", fmt.Errorf("read refresh token: %w", err)
	}

	if revokedAt.Valid || now.After(expiresAt.UTC()) {
		return "", ErrInvalidRefreshToken
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO auth_refresh_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, newID.String(), userID, newHash, newExpiresAt.UTC())
	if err != nil {
		return "", fmt.Errorf("insert rotated refresh token: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE auth_refresh_tokens
		SET revoked_at = $2, replaced_by = $3
		WHERE id = $1
	`, oldID, now, newID.String())
	if err != nil {
		return "", fmt.Errorf("revoke old refresh token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit refresh rotation tx: %w", err)
	}

	return userID, nil
}

func (r *Repository) RevokeRefreshToken(ctx context.Context, rawToken string) error {
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	_, err := r.db.ExecContext(ctx, `
		UPDATE auth_refresh_tokens
		SET revoked_at = COALESCE(revoked_at, $2)
		WHERE token_hash = $1
	`, tokenHash, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	return nil
}

func (r *Repository) AllowLoginIP(ctx context.Context, ip string, maxHits int, window time.Duration, now time.Time) (bool, time.Duration, error) {
	threshold := now.UTC().Add(-window)

	var hits int
	var windowStartedAt time.Time
	err := r.db.QueryRowContext(ctx, `
		WITH upsert AS (
			INSERT INTO auth_login_ip_limits (ip, window_started_at, hits, updated_at)
			VALUES ($1, $2, 1, $2)
			ON CONFLICT (ip) DO UPDATE
			SET
				hits = CASE
					WHEN auth_login_ip_limits.window_started_at <= $3 THEN 1
					ELSE auth_login_ip_limits.hits + 1
				END,
				window_started_at = CASE
					WHEN auth_login_ip_limits.window_started_at <= $3 THEN $2
					ELSE auth_login_ip_limits.window_started_at
				END,
				updated_at = $2
			RETURNING hits, window_started_at
		)
		SELECT hits, window_started_at FROM upsert
	`, ip, now.UTC(), threshold).Scan(&hits, &windowStartedAt)
	if err != nil {
		return false, 0, fmt.Errorf("upsert login ip rate limit: %w", err)
	}

	if hits <= maxHits {
		return true, 0, nil
	}

	retryAfter := windowStartedAt.Add(window).Sub(now.UTC())
	if retryAfter < time.Second {
		retryAfter = time.Second
	}

	return false, retryAfter, nil
}

func (r *Repository) CleanupStaleAuthData(ctx context.Context, refreshRetention time.Duration, loginAttemptRetention time.Duration, batchSize int) (CleanupResult, error) {
	if batchSize <= 0 {
		batchSize = 500
	}
	if refreshRetention <= 0 {
		refreshRetention = 14 * 24 * time.Hour
	}
	if loginAttemptRetention <= 0 {
		loginAttemptRetention = 30 * 24 * time.Hour
	}

	refreshCutoff := time.Now().UTC().Add(-refreshRetention)
	loginCutoff := time.Now().UTC().Add(-loginAttemptRetention)

	deletedRefreshTokens, err := r.deleteStaleRefreshTokens(ctx, refreshCutoff, batchSize)
	if err != nil {
		return CleanupResult{}, err
	}

	deletedLoginAttempts, err := r.deleteStaleLoginAttempts(ctx, loginCutoff, batchSize)
	if err != nil {
		return CleanupResult{}, err
	}

	deletedIPLimits, err := r.deleteStaleIPLimits(ctx, loginCutoff, batchSize)
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		DeletedRefreshTokens: deletedRefreshTokens,
		DeletedLoginAttempts: deletedLoginAttempts,
		DeletedIPLimits:      deletedIPLimits,
	}, nil
}

func (r *Repository) deleteStaleRefreshTokens(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		WITH stale AS (
			SELECT id
			FROM auth_refresh_tokens
			WHERE expires_at < NOW() OR (revoked_at IS NOT NULL AND revoked_at < $1)
			ORDER BY created_at ASC
			LIMIT $2
		)
		DELETE FROM auth_refresh_tokens t
		USING stale
		WHERE t.id = stale.id
	`, cutoff, batchSize)
	if err != nil {
		return 0, fmt.Errorf("delete stale refresh tokens: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("stale refresh tokens rows affected: %w", err)
	}

	return affected, nil
}

func (r *Repository) deleteStaleLoginAttempts(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		WITH stale AS (
			SELECT username
			FROM auth_login_attempts
			WHERE updated_at < $1
			  AND (locked_until IS NULL OR locked_until < NOW())
			ORDER BY updated_at ASC
			LIMIT $2
		)
		DELETE FROM auth_login_attempts t
		USING stale
		WHERE t.username = stale.username
	`, cutoff, batchSize)
	if err != nil {
		return 0, fmt.Errorf("delete stale login attempts: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("stale login attempts rows affected: %w", err)
	}

	return affected, nil
}

func (r *Repository) deleteStaleIPLimits(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		WITH stale AS (
			SELECT ip
			FROM auth_login_ip_limits
			WHERE updated_at < $1
			ORDER BY updated_at ASC
			LIMIT $2
		)
		DELETE FROM auth_login_ip_limits t
		USING stale
		WHERE t.ip = stale.ip
	`, cutoff, batchSize)
	if err != nil {
		return 0, fmt.Errorf("delete stale login ip limits: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("stale login ip limits rows affected: %w", err)
	}

	return affected, nil
}

var ErrInvalidRefreshToken = errors.New("invalid refresh token")
