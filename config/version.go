package config

import (
	"fmt"
	"time"
)

func GetMinimumVersionCutoff() time.Time {
	return time.Date(2025, time.April, 15, 0, 0, 0, 0, time.UTC)
}

// Gets the minimum patch version – This should only be set in a release series
// if there is something in the patch update that is needed to cut off
// unupgraded peers. Be sure to update this to 0x00 for any new minor release.
func GetMinimumPatchVersion() byte {
	return 0x00
}

func GetMinimumVersion() []byte {
	return []byte{0x02, 0x01, 0x00}
}

func GetVersion() []byte {
	return []byte{0x02, 0x01, 0x00}
}

func GetVersionString() string {
	return FormatVersion(GetVersion())
}

func FormatVersion(version []byte) string {
	if len(version) == 3 {
		return fmt.Sprintf(
			"%d.%d.%d",
			version[0], version[1], version[2],
		)
	} else {
		return fmt.Sprintf(
			"%d.%d.%d-p%d",
			version[0], version[1], version[2], version[3],
		)
	}
}

func GetPatchNumber() byte {
	return 0x00
}

func GetRCNumber() byte {
	return 0x06
}
