package observability

import (
	"encoding/json"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
)

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.statusCode = status
	r.ResponseWriter.WriteHeader(status)
}

func RequestLoggingMiddleware(logger *Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now().UTC()
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)

		logger.Info("http_request", map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      recorder.statusCode,
			"duration_ms": time.Since(start).Milliseconds(),
			"ip":          clientIP(r),
		})
	})
}

func RecoverMiddleware(logger *Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				sentry.WithScope(func(scope *sentry.Scope) {
					scope.SetExtra("panic", rec)
					scope.SetExtra("stack", string(debug.Stack()))
					sentry.CaptureMessage("panic in request")
				})

				logger.Error("panic_recovered", map[string]any{
					"path":   r.URL.Path,
					"method": r.Method,
					"panic":  rec,
				})

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
			}
		}()

		next.ServeHTTP(w, r)
	})
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
