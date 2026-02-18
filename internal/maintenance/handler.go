package maintenance

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"store-serverless/internal/auth"
	"store-serverless/internal/observability"
)

type CleanupHandler struct {
	repo                  *auth.Repository
	logger                *observability.Logger
	cronSecret            string
	refreshRetention      time.Duration
	loginAttemptRetention time.Duration
	batchSize             int
}

func NewCleanupHandler(
	repo *auth.Repository,
	logger *observability.Logger,
	cronSecret string,
	refreshRetention time.Duration,
	loginAttemptRetention time.Duration,
	batchSize int,
) *CleanupHandler {
	return &CleanupHandler{
		repo:                  repo,
		logger:                logger,
		cronSecret:            strings.TrimSpace(cronSecret),
		refreshRetention:      refreshRetention,
		loginAttemptRetention: loginAttemptRetention,
		batchSize:             batchSize,
	}
}

func (h *CleanupHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if h.cronSecret == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) != h.cronSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	result, err := h.repo.CleanupStaleAuthData(r.Context(), h.refreshRetention, h.loginAttemptRetention, h.batchSize)
	if err != nil {
		h.logger.Error("auth_cleanup_failed", map[string]any{"error": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cleanup failed"})
		return
	}

	h.logger.Info("auth_cleanup_completed", map[string]any{
		"deleted_refresh_tokens": result.DeletedRefreshTokens,
		"deleted_login_attempts": result.DeletedLoginAttempts,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"result": result,
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
