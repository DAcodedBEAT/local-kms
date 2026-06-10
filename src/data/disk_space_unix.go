//go:build !windows

package data

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// CheckDiskSpace verifies that dbPath has at least MinDiskSpaceBytes available.
func CheckDiskSpace(dbPath string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(dbPath, &stat); err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}

	available := stat.Bavail * uint64(stat.Bsize)
	if available < MinDiskSpaceBytes {
		return &DiskSpaceError{Available: available, Required: MinDiskSpaceBytes}
	}

	return nil
}
