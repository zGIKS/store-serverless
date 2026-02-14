package observability

import (
	"time"

	"github.com/getsentry/sentry-go"
)

func InitSentry(dsn, environment string) error {
	if dsn == "" {
		return nil
	}

	return sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Environment:      environment,
		AttachStacktrace: true,
	})
}

func FlushSentry() {
	sentry.Flush(2 * time.Second)
}
