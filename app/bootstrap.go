package app

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

	"github.com/joho/godotenv"

	"store-serverless/internal/auth"
	"store-serverless/internal/db"
	"store-serverless/internal/maintenance"
	"store-serverless/internal/media"
	"store-serverless/internal/observability"
	"store-serverless/internal/product"
)

type Options struct {
	LoadDotEnv    bool
	RunMigrations bool
}

type Runtime struct {
	Handler http.Handler
	Close   func() error
}

func Build(options Options) (*Runtime, error) {
	if options.LoadDotEnv {
		_ = godotenv.Load()
	}

	logger := observability.NewLogger()

	databaseURL, err := mustEnv("DATABASE_URL")
	if err != nil {
		return nil, err
	}
	jwtSecret, err := mustEnv("JWT_SECRET")
	if err != nil {
		return nil, err
	}
	cloudinaryURL, err := mustEnv("CLOUDINARY_URL")
	if err != nil {
		return nil, err
	}

	if err := observability.InitSentry(os.Getenv("SENTRY_DSN"), envOrDefault("APP_ENV", "development")); err != nil {
		logger.Error("init_sentry_failed", map[string]any{"error": err.Error()})
	}

	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	database.SetMaxOpenConns(envIntOrDefault("DB_MAX_OPEN_CONNS", 10))
	database.SetMaxIdleConns(envIntOrDefault("DB_MAX_IDLE_CONNS", 5))
	database.SetConnMaxLifetime(envMinutesOrDefault("DB_CONN_MAX_LIFETIME_MINUTES", 30))
	database.SetConnMaxIdleTime(envMinutesOrDefault("DB_CONN_MAX_IDLE_TIME_MINUTES", 10))

	if err := database.Ping(); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	if options.RunMigrations {
		if err := db.RunMigrations(database); err != nil {
			_ = database.Close()
			return nil, fmt.Errorf("run migrations: %w", err)
		}
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
	cleanupHandler := maintenance.NewCleanupHandler(
		authRepo,
		logger,
		os.Getenv("CRON_SECRET"),
		envDaysOrDefault("AUTH_REFRESH_TOKEN_RETENTION_DAYS", 14),
		envDaysOrDefault("AUTH_LOGIN_ATTEMPT_RETENTION_DAYS", 30),
		envIntOrDefault("AUTH_CLEANUP_BATCH_SIZE", 500),
	)

	if err := authService.BootstrapFromEnv(context.Background(), os.Getenv("ADMIN_USERNAME"), os.Getenv("ADMIN_PASSWORD")); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("bootstrap admin: %w", err)
	}

	productRepo := product.NewRepository(database)
	cloudinaryClient, err := media.NewCloudinary(cloudinaryURL)
	if err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("init cloudinary: %w", err)
	}
	productHandler := product.NewHandler(productRepo, cloudinaryClient)
	mediaUploadHandler := media.NewUploadHandler(cloudinaryClient)

	loginLimiter := auth.NewLoginRateLimiter(
		authRepo,
		envIntOrDefault("LOGIN_RATE_LIMIT_MAX", 10),
		envSecondsOrDefault("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 60),
	)

	mux := http.NewServeMux()
	mux.Handle("POST /auth/login", loginLimiter.Middleware(http.HandlerFunc(authHandler.Login)))
	mux.HandleFunc("POST /auth/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /auth/logout", authHandler.Logout)
	mux.HandleFunc("GET /internal/maintenance/cleanup", cleanupHandler.Handle)
	mux.HandleFunc("POST /internal/maintenance/cleanup", cleanupHandler.Handle)
	mux.HandleFunc("GET /health", healthHandler(database))
	mux.HandleFunc("GET /products", productHandler.ListProducts)
	mux.Handle("POST /products", auth.Middleware(jwtSecret, http.HandlerFunc(productHandler.CreateProduct)))
	mux.Handle("PUT /products/{id}", auth.Middleware(jwtSecret, http.HandlerFunc(productHandler.UpdateProduct)))
	mux.Handle("DELETE /products/{id}", auth.Middleware(jwtSecret, http.HandlerFunc(productHandler.DeleteProduct)))
	mux.Handle("POST /media/upload", auth.Middleware(jwtSecret, http.HandlerFunc(mediaUploadHandler.Upload)))

	handler := observability.RecoverMiddleware(logger, observability.RequestLoggingMiddleware(logger, mux))

	return &Runtime{
		Handler: handler,
		Close: func() error {
			observability.FlushSentry()
			return database.Close()
		},
	}, nil
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

func mustEnv(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("missing required env: %s", name)
	}
	return value, nil
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

func envDaysOrDefault(name string, fallback int) time.Duration {
	return time.Duration(envIntOrDefault(name, fallback)) * 24 * time.Hour
}

func envSecondsOrDefault(name string, fallback int) time.Duration {
	return time.Duration(envIntOrDefault(name, fallback)) * time.Second
}

func EnvBoolOrDefault(name string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if value == "" {
		return fallback
	}

	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
