package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"

	"store-serverless/internal/auth"
	"store-serverless/internal/db"
	"store-serverless/internal/observability"
	"store-serverless/internal/product"
)

func main() {
	_ = godotenv.Load()

	logger := observability.NewLogger()

	databaseURL := mustEnv("DATABASE_URL")
	jwtSecret := mustEnv("JWT_SECRET")
	port := envOrDefault("PORT", "8080")

	if err := observability.InitSentry(os.Getenv("SENTRY_DSN"), envOrDefault("APP_ENV", "development")); err != nil {
		logger.Error("init_sentry_failed", map[string]any{"error": err.Error()})
	}
	defer observability.FlushSentry()

	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		logger.Error("open_database_failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	defer database.Close()

	if err := database.Ping(); err != nil {
		logger.Error("ping_database_failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	if err := db.RunMigrations(database); err != nil {
		logger.Error("migrations_failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	authRepo := auth.NewRepository(database)
	authService := auth.NewService(authRepo, jwtSecret)
	authService.WithSecurityConfig(
		envIntOrDefault("LOGIN_MAX_ATTEMPTS", 5),
		envMinutesOrDefault("LOGIN_LOCK_MINUTES", 15),
		envMinutesOrDefault("ACCESS_TOKEN_TTL_MINUTES", 15),
		envHoursOrDefault("REFRESH_TOKEN_TTL_HOURS", 168),
	)
	authHandler := auth.NewHandler(authService)

	if err := authService.BootstrapFromEnv(context.Background(), os.Getenv("ADMIN_USERNAME"), os.Getenv("ADMIN_PASSWORD")); err != nil {
		logger.Error("bootstrap_admin_failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	productRepo := product.NewRepository(database)
	productHandler := product.NewHandler(productRepo)

	loginLimiter := auth.NewLoginRateLimiter(
		envIntOrDefault("LOGIN_RATE_LIMIT_MAX", 10),
		envSecondsOrDefault("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 60),
	)

	mux := http.NewServeMux()
	mux.Handle("POST /auth/login", loginLimiter.Middleware(http.HandlerFunc(authHandler.Login)))
	mux.HandleFunc("POST /auth/refresh", authHandler.Refresh)
	mux.HandleFunc("GET /health", healthHandler(database))
	mux.HandleFunc("GET /products", productHandler.ListProducts)
	mux.Handle("POST /products", auth.Middleware(jwtSecret, http.HandlerFunc(productHandler.CreateProduct)))
	mux.Handle("PUT /products/{id}", auth.Middleware(jwtSecret, http.HandlerFunc(productHandler.UpdateProduct)))
	mux.Handle("DELETE /products/{id}", auth.Middleware(jwtSecret, http.HandlerFunc(productHandler.DeleteProduct)))

	handler := observability.RecoverMiddleware(logger, observability.RequestLoggingMiddleware(logger, mux))

	addr := fmt.Sprintf(":%s", port)
	logger.Info("server_start", map[string]any{"addr": addr})
	if err := http.ListenAndServe(addr, handler); err != nil {
		logger.Error("server_failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
}

func healthHandler(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		status := http.StatusOK
		body := map[string]any{"status": "ok", "time": time.Now().UTC().Format(time.RFC3339)}
		if err := database.PingContext(ctx); err != nil {
			status = http.StatusServiceUnavailable
			body = map[string]any{"status": "degraded", "time": time.Now().UTC().Format(time.RFC3339)}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

func mustEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		fmt.Printf("missing required env: %s\n", name)
		os.Exit(1)
	}
	return value
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func envIntOrDefault(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envMinutesOrDefault(name string, fallback int) time.Duration {
	return time.Duration(envIntOrDefault(name, fallback)) * time.Minute
}

func envHoursOrDefault(name string, fallback int) time.Duration {
	return time.Duration(envIntOrDefault(name, fallback)) * time.Hour
}

func envSecondsOrDefault(name string, fallback int) time.Duration {
	return time.Duration(envIntOrDefault(name, fallback)) * time.Second
}
