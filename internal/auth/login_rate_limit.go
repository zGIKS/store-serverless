package auth

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type LoginRateLimiter struct {
	repo    *Repository
	maxHits int
	window  time.Duration
}

func NewLoginRateLimiter(repo *Repository, maxHits int, window time.Duration) *LoginRateLimiter {
	if maxHits <= 0 {
		maxHits = 10
	}
	if window <= 0 {
		window = time.Minute
	}

	return &LoginRateLimiter{
		repo:    repo,
		maxHits: maxHits,
		window:  window,
	}
}

func (l *LoginRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		now := time.Now().UTC()

		allowed, retryAfter, err := l.allow(r, ip, now)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to enforce login rate limit")
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
			writeError(w, http.StatusTooManyRequests, "too many login attempts")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (l *LoginRateLimiter) allow(r *http.Request, ip string, now time.Time) (bool, time.Duration, error) {
	if l.repo == nil {
		return true, 0, nil
	}

	allowed, retryAfter, err := l.repo.AllowLoginIP(r.Context(), ip, l.maxHits, l.window, now)
	if err != nil {
		return false, 0, err
	}

	return allowed, retryAfter, nil
}

func clientIP(r *http.Request) string {
	xForwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xForwardedFor != "" {
		parts := strings.Split(xForwardedFor, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}

	if r.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil && strings.TrimSpace(host) != "" {
			return strings.TrimSpace(host)
		}
		return r.RemoteAddr
	}

	return "unknown"
}
