package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/nsmithuk/local-kms/src/data"
)

func main() {
	dbPath := flag.String("db", "/data", "Path to the KMS data directory")
	removeCorrupted := flag.Bool("remove-corrupted", false, "Remove corrupted entries (WARNING: destructive)")
	flag.Parse()

	if _, err := os.Stat(*dbPath); os.IsNotExist(err) {
		log.Fatalf("Database path does not exist: %s", *dbPath)
	}

	fmt.Printf("Opening database at: %s\n", *dbPath)
	db := data.NewDatabase(*dbPath)
	defer func() {
		if err := db.Close(); err != nil {
			fmt.Printf("Error closing database: %v\n", err)
		}
	}()

	fmt.Print("\n=== Running Health Check ===\n\n")

	report := db.HealthCheck()

	if report.DiskSpaceIssue != "" {
		fmt.Printf("⚠ Disk space warning: %s\n\n", report.DiskSpaceIssue)
	}

	if len(report.Entries) == 0 {
		fmt.Println("✓ No corruption detected")
		return
	}

	fmt.Printf("⚠ Found corruption:\n\n")
	fmt.Printf("Corrupted Keys:    %d\n", report.CorruptedKeys)
	fmt.Printf("Corrupted Aliases: %d\n", report.CorruptedAliases)
	fmt.Printf("Corrupted Tags:    %d\n", report.CorruptedTags)
	fmt.Println("\nDetails:")
	for i, entry := range report.Entries {
		fmt.Printf("  %d. %s\n", i+1, entry.Description)
	}

	if !*removeCorrupted {
		fmt.Printf("\n\nTo remove corrupted entries:\n  recovery -db %s -remove-corrupted\n\n", *dbPath)
		fmt.Println("⚠ WARNING: Destructive — ensure you have a backup first.")
		os.Exit(1)
	}

	fmt.Print("\n\n=== Removing Corrupted Entries ===\n\n")
	fmt.Println("⚠ WARNING: This will permanently delete corrupted data.")
	fmt.Print("Type 'yes' to confirm: ")

	var confirmation string
	if _, err := fmt.Scanln(&confirmation); err != nil || confirmation != "yes" {
		fmt.Println("Operation cancelled.")
		os.Exit(0)
	}

	removedCount := 0
	for _, entry := range report.Entries {
		fmt.Printf("Removing %s...", entry.DBKey)
		if err := db.RemoveCorruptedEntry(entry.DBKey); err != nil {
			fmt.Printf(" ERROR: %v\n", err)
		} else {
			fmt.Println(" ✓")
			removedCount++
		}
	}

	fmt.Printf("\n✓ Removed %d corrupted entries\n\n", removedCount)
	fmt.Printf("Run health check to verify:\n  recovery -db %s\n\n", *dbPath)
}
