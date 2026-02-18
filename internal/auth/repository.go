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

var ErrInvalidRefreshToken = errors.New("invalid refresh token")
