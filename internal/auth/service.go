package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultAccessTTL   = 15 * time.Minute
	defaultRefreshTTL  = 7 * 24 * time.Hour
	defaultMaxAttempts = 5
	defaultLockWindow  = 15 * time.Minute
)

type Service struct {
	repo         *Repository
	jwtSecret    []byte
	accessTTL    time.Duration
	refreshTTL   time.Duration
	maxAttempts  int
	lockDuration time.Duration
}

func NewService(repo *Repository, jwtSecret string) *Service {
	return &Service{
		repo:         repo,
		jwtSecret:    []byte(jwtSecret),
		accessTTL:    defaultAccessTTL,
		refreshTTL:   defaultRefreshTTL,
		maxAttempts:  defaultMaxAttempts,
		lockDuration: defaultLockWindow,
	}
}

func (s *Service) WithSecurityConfig(maxAttempts int, lockDuration time.Duration, accessTTL time.Duration, refreshTTL time.Duration) {
	if maxAttempts > 0 {
		s.maxAttempts = maxAttempts
	}
	if lockDuration > 0 {
		s.lockDuration = lockDuration
	}
	if accessTTL > 0 {
		s.accessTTL = accessTTL
	}
	if refreshTTL > 0 {
		s.refreshTTL = refreshTTL
	}
}

func (s *Service) Login(ctx context.Context, username, password string) (Tokens, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	password = strings.TrimSpace(password)

	if username == "" || password == "" {
		return Tokens{}, ErrInvalidCredentials
	}

	now := time.Now().UTC()
	attempt, err := s.repo.GetLoginAttempt(ctx, username)
	if err != nil {
		return Tokens{}, err
	}
	if attempt.LockedUntil != nil && now.Before(*attempt.LockedUntil) {
		return Tokens{}, ErrLoginLocked{Until: *attempt.LockedUntil}
	}

	user, err := s.repo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			lockedUntil, regErr := s.repo.RegisterFailedAttempt(ctx, username, s.maxAttempts, s.lockDuration, now)
			if regErr != nil {
				return Tokens{}, regErr
			}
			if lockedUntil != nil {
				return Tokens{}, ErrLoginLocked{Until: *lockedUntil}
			}
			return Tokens{}, ErrInvalidCredentials
		}
		return Tokens{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		lockedUntil, regErr := s.repo.RegisterFailedAttempt(ctx, username, s.maxAttempts, s.lockDuration, now)
		if regErr != nil {
			return Tokens{}, regErr
		}
		if lockedUntil != nil {
			return Tokens{}, ErrLoginLocked{Until: *lockedUntil}
		}
		return Tokens{}, ErrInvalidCredentials
	}

	if err := s.repo.ResetLoginAttempt(ctx, username); err != nil {
		return Tokens{}, err
	}

	return s.issueTokens(ctx, user.ID)
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return Tokens{}, ErrInvalidRefreshToken
	}

	newRefresh, err := randomToken(48)
	if err != nil {
		return Tokens{}, fmt.Errorf("generate new refresh token: %w", err)
	}

	newExp := time.Now().UTC().Add(s.refreshTTL)
	userID, err := s.repo.RotateRefreshToken(ctx, refreshToken, newRefresh, newExp)
	if err != nil {
		return Tokens{}, err
	}

	access, expiresIn, err := s.issueAccessToken(userID)
	if err != nil {
		return Tokens{}, err
	}

	return Tokens{
		AccessToken:  access,
		RefreshToken: newRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
	}, nil
}

func (s *Service) issueTokens(ctx context.Context, userID string) (Tokens, error) {
	access, expiresIn, err := s.issueAccessToken(userID)
	if err != nil {
		return Tokens{}, err
	}

	refreshToken, err := randomToken(48)
	if err != nil {
		return Tokens{}, fmt.Errorf("generate refresh token: %w", err)
	}
	if err := s.repo.CreateRefreshToken(ctx, userID, refreshToken, time.Now().UTC().Add(s.refreshTTL)); err != nil {
		return Tokens{}, err
	}

	return Tokens{
		AccessToken:  access,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
	}, nil
}

func (s *Service) issueAccessToken(userID string) (string, int64, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": now.Unix(),
		"exp": now.Add(s.accessTTL).Unix(),
		"typ": "access",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	encoded, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", 0, fmt.Errorf("sign jwt: %w", err)
	}

	return encoded, int64(s.accessTTL.Seconds()), nil
}

func (s *Service) BootstrapFromEnv(ctx context.Context, adminUsername, adminPassword string) error {
	adminUsername = strings.TrimSpace(strings.ToLower(adminUsername))
	adminPassword = strings.TrimSpace(adminPassword)

	if adminUsername == "" && adminPassword == "" {
		return nil
	}
	if adminUsername == "" || adminPassword == "" {
		return fmt.Errorf("ADMIN_USERNAME and ADMIN_PASSWORD are required together")
	}

	return s.repo.UpsertSingleUser(ctx, adminUsername, adminPassword)
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var ErrInvalidCredentials = errors.New("invalid credentials")

type ErrLoginLocked struct {
	Until time.Time
}

func (e ErrLoginLocked) Error() string {
	return "login temporarily locked"
}
