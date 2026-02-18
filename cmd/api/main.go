package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"store-serverless/internal/app"
	"store-serverless/internal/observability"
)

func main() {
	logger := observability.NewLogger()
	port := envOrDefault("PORT", "8080")
	runtime, err := app.Build(app.Options{
		LoadDotEnv:    true,
		RunMigrations: app.EnvBoolOrDefault("RUN_MIGRATIONS_ON_STARTUP", true),
	})
	if err != nil {
		logger.Error("app_bootstrap_failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	defer runtime.Close()

	addr := fmt.Sprintf(":%s", port)
	server := &http.Server{
		Addr:              addr,
		Handler:           runtime.Handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	logger.Info("server_start", map[string]any{"addr": addr})
	if err := server.ListenAndServe(); err != nil {
		logger.Error("server_failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}
