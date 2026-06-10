//go:build windows

package data

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// CheckDiskSpace verifies that dbPath has at least MinDiskSpaceBytes available.
func CheckDiskSpace(dbPath string) error {
	path, err := windows.UTF16PtrFromString(dbPath)
	if err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}

	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(path, &freeBytesAvailable, &totalBytes, &totalFreeBytes); err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}

	if freeBytesAvailable < MinDiskSpaceBytes {
		return &DiskSpaceError{Available: freeBytesAvailable, Required: MinDiskSpaceBytes}
	}

	return nil
}
