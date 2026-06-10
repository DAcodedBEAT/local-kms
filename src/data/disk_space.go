package data

import "fmt"

// DiskSpaceError is returned when available disk space is below the minimum threshold.
type DiskSpaceError struct {
	Available uint64
	Required  uint64
}

func (e *DiskSpaceError) Error() string {
	return fmt.Sprintf("insufficient disk space: %d bytes available, %d bytes required", e.Available, e.Required)
}

// MinDiskSpaceBytes is the minimum free disk space required before any write.
// LevelDB compaction can produce files several times the size of the input; 50 MB
// provides a conservative buffer while remaining practical for local dev usage.
const MinDiskSpaceBytes = 50 * 1024 * 1024
