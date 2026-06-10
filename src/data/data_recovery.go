package data

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CorruptedEntry describes a single corrupted database entry.
type CorruptedEntry struct {
	DBKey       string // raw LevelDB key
	Description string // human-readable error
}

// CorruptionReport holds the result of a database scan.
type CorruptionReport struct {
	CorruptedKeys    int
	CorruptedAliases int
	CorruptedTags    int
	Entries          []CorruptedEntry
	DiskSpaceIssue   string
}

// ScanForCorruption scans all database entries for corruption.
// Entry type is determined by the DB key pattern:
//   - contains "/tag/"   → Tag
//   - contains ":alias/" → Alias
//   - otherwise          → Key
func (d *Database) ScanForCorruption() *CorruptionReport {
	var report CorruptionReport

	iter := d.database.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		value := iter.Value()

		switch {
		case strings.Contains(key, "/tag/"):
			var tag Tag
			if err := json.Unmarshal(value, &tag); err != nil {
				report.CorruptedTags++
				report.Entries = append(report.Entries, CorruptedEntry{
					DBKey:       key,
					Description: fmt.Sprintf("corrupted tag at '%s': %v", key, err),
				})
			}

		case strings.Contains(key, ":alias/"):
			var alias Alias
			if err := json.Unmarshal(value, &alias); err != nil {
				report.CorruptedAliases++
				report.Entries = append(report.Entries, CorruptedEntry{
					DBKey:       key,
					Description: fmt.Sprintf("corrupted alias at '%s': %v", key, err),
				})
			}

		default:
			if _, err := unmarshalKey(value); err != nil {
				report.CorruptedKeys++
				report.Entries = append(report.Entries, CorruptedEntry{
					DBKey:       key,
					Description: fmt.Sprintf("corrupted key at '%s': %v", key, err),
				})
			}
		}
	}

	return &report
}

// RemoveCorruptedEntry removes a single corrupted entry from the database.
func (d *Database) RemoveCorruptedEntry(key string) error {
	if err := d.database.Delete([]byte(key), syncWrite); err != nil {
		return fmt.Errorf("failed to delete corrupted entry: %w", err)
	}
	return nil
}

// HealthCheck scans for corruption and checks available disk space.
func (d *Database) HealthCheck() *CorruptionReport {
	report := d.ScanForCorruption()

	if err := CheckDiskSpace(d.dbPath); err != nil {
		report.DiskSpaceIssue = err.Error()
	}

	return report
}
