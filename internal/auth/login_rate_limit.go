package auth

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type LoginRateLimiter struct {
	mu        sync.Mutex
	maxHits   int
	window    time.Duration
	hitByIP   map[string][]time.Time
	maxMemory int
}

func NewLoginRateLimiter(maxHits int, window time.Duration) *LoginRateLimiter {
	if maxHits <= 0 {
		maxHits = 10
	}
	if window <= 0 {
		window = time.Minute
	}

	return &LoginRateLimiter{
		maxHits:   maxHits,
		window:    window,
		hitByIP:   make(map[string][]time.Time),
		maxMemory: 5000,
	}
}

func (l *LoginRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		now := time.Now().UTC()

		allowed, retryAfter := l.allow(ip, now)
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
			writeError(w, http.StatusTooManyRequests, "too many login attempts")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (l *LoginRateLimiter) allow(ip string, now time.Time) (bool, time.Duration) {
	threshold := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	hits := l.hitByIP[ip]
	filtered := make([]time.Time, 0, len(hits)+1)
	for _, hit := range hits {
		if hit.After(threshold) {
			filtered = append(filtered, hit)
		}
	}

	if len(filtered) >= l.maxHits {
		retryAfter := filtered[0].Add(l.window).Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		l.hitByIP[ip] = filtered
		return false, retryAfter
	}

	filtered = append(filtered, now)
	l.hitByIP[ip] = filtered

	if len(l.hitByIP) > l.maxMemory {
		for key, value := range l.hitByIP {
			if len(value) == 0 || value[len(value)-1].Before(threshold) {
				delete(l.hitByIP, key)
			}
		}
	}

	return true, 0
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
		return r.RemoteAddr
	}

	return "unknown"
}
