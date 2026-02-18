package api

import (
	"encoding/json"
	"net/http"
	"sync"

	_ "github.com/jackc/pgx/v5/stdlib"

	"store-serverless/internal/app"
)

var (
	initOnce   sync.Once
	apiRuntime *app.Runtime
	initErr    error
)

func Handler(w http.ResponseWriter, r *http.Request) {
	initOnce.Do(func() {
		apiRuntime, initErr = app.Build(app.Options{
			LoadDotEnv:    false,
			RunMigrations: app.EnvBoolOrDefault("RUN_MIGRATIONS_ON_STARTUP", false),
		})
	})

	if initErr != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "application bootstrap failed"})
		return
	}

	apiRuntime.Handler.ServeHTTP(w, r)
}
