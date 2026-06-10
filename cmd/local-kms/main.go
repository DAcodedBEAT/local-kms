package main

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/nsmithuk/local-kms/src"
	"github.com/nsmithuk/local-kms/src/config"
)

var (
	Version   string
	GitCommit string
)

func main() {
	ctx := context.Background()

	Version = config.ResolveVersion(Version)
	GitCommit = config.ResolveGitCommit(GitCommit)

	slog.InfoContext(ctx, "Local KMS", "version", Version, "commit", GitCommit)

	//---

	config.AWSAccountId = config.GetEnv(ctx, "ACCOUNT_ID", "111122223333")
	config.AWSRegion = config.GetEnv(ctx, "REGION", "eu-west-2")

	dataPath := config.GetEnv(ctx, "DATA_PATH", "/tmp/local-kms")
	config.DatabasePath, _ = filepath.Abs(dataPath)

	//-------------------------------
	// Seed

	seedPath := config.GetEnv(ctx, "SEED_PATH", "/init/seed.yaml")

	//-------------------------------
	// Run

	port := config.GetEnv(ctx, "PORT", "8080")

	src.Run(ctx, port, seedPath)
}
