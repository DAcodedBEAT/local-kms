package src

import (
	"context"
	"log/slog"
	"os"

	"github.com/nsmithuk/local-kms/src/config"
)

var logger *slog.Logger

func init() {
	ctx := context.Background()
	level := slog.LevelInfo
	if v := config.GetEnv(ctx, "LOG_LEVEL", ""); v != "" {
		_ = level.UnmarshalText([]byte(v))
	}

	logger = slog.New(&contextHandler{slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})})
	slog.SetDefault(logger)
}
