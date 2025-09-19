//go:build windows
// +build windows

package utils

import (
	"log"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

func GetDiskSpace(dir string) uint64 {
	var freeBytesAvailable uint64
	var totalNumberOfBytes uint64
	var totalNumberOfFreeBytes uint64

	err := windows.GetDiskFreeSpaceEx(windows.StringToUTF16Ptr(dir),
		&freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)
	if err != nil {
		log.Panic("failed GetDiskFreeSpaceEx", zap.Error(err))
	}

	return totalNumberOfBytes
}
