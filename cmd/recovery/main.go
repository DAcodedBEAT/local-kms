package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
)

var (
	Version   string
	GitCommit string
)

func main() {
	ctx := context.Background()

	Version = config.ResolveVersion(Version)
	GitCommit = config.ResolveGitCommit(GitCommit)

	slog.InfoContext(ctx, "Local KMS Recovery Utility", "version", Version, "commit", GitCommit)

	dbPath := flag.String("db", "/data", "Path to the KMS data directory")
	removeCorrupted := flag.Bool("remove-corrupted", false, "Remove corrupted entries (WARNING: destructive)")
	flag.Parse()

	if _, err := os.Stat(*dbPath); os.IsNotExist(err) {
		slog.ErrorContext(ctx, "Database path does not exist", "path", *dbPath)
		os.Exit(1)
	}

	slog.InfoContext(ctx, "Opening database", "path", *dbPath)
	db := data.NewDatabase(ctx, *dbPath)
	defer func() {
		if err := db.Close(); err != nil {
			slog.ErrorContext(ctx, "Error closing database", "error", err)
		}
	}()

	slog.InfoContext(ctx, "Running Health Check")

	report := db.HealthCheck()

	if report.DiskSpaceIssue != "" {
		slog.WarnContext(ctx, "Disk space issue detected", "issue", report.DiskSpaceIssue)
	}

	if len(report.Entries) == 0 {
		slog.InfoContext(ctx, "No corruption detected")
		return
	}

	slog.WarnContext(ctx, "Found corruption", 
		"corrupted_keys", report.CorruptedKeys,
		"corrupted_aliases", report.CorruptedAliases,
		"corrupted_tags", report.CorruptedTags,
	)

	for i, entry := range report.Entries {
		slog.InfoContext(ctx, "Corruption details", "index", i+1, "description", entry.Description)
	}

	if !*removeCorrupted {
		slog.WarnContext(ctx, "Corruption found. To remove corrupted entries, run with -remove-corrupted flag.", "db", *dbPath)
		os.Exit(1)
	}

	fmt.Print("\n\n=== Removing Corrupted Entries ===\n\n")
	fmt.Println("⚠ WARNING: This will permanently delete corrupted data.")
	fmt.Print("Type 'yes' to confirm: ")

	var confirmation string
	if _, err := fmt.Scanln(&confirmation); err != nil || confirmation != "yes" {
		slog.InfoContext(ctx, "Operation cancelled by user")
		os.Exit(0)
	}

	slog.InfoContext(ctx, "User confirmed corruption removal")
	removedCount := 0
	for _, entry := range report.Entries {
		if err := db.RemoveCorruptedEntry(entry.DBKey); err != nil {
			slog.ErrorContext(ctx, "Failed to remove corrupted entry", "db_key", entry.DBKey, "error", err)
		} else {
			slog.InfoContext(ctx, "Successfully removed corrupted entry", "db_key", entry.DBKey)
			removedCount++
		}
	}

	slog.InfoContext(ctx, "Cleanup complete", "removed_count", removedCount)
	slog.InfoContext(ctx, "Run health check again to verify results", "db", *dbPath)
}
