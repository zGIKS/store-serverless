package observability

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type Logger struct {
	base *log.Logger
}

func NewLogger() *Logger {
	return &Logger{base: log.New(os.Stdout, "", 0)}
}

func (l *Logger) Info(message string, fields map[string]any) {
	l.write("info", message, fields)
}

func (l *Logger) Error(message string, fields map[string]any) {
	l.write("error", message, fields)
}

func (l *Logger) write(level, message string, fields map[string]any) {
	payload := map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"message":   message,
	}
	for k, v := range fields {
		payload[k] = v
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		l.base.Println(`{"level":"error","message":"failed to encode log"}`)
		return
	}

	l.base.Println(string(encoded))
}
