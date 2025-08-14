package tlsgen

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ChromeVersion represents a Chrome browser version
type ChromeVersion struct {
	Major    int       `json:"major"`
	Minor    int       `json:"minor"`
	Build    int       `json:"build"`
	Patch    int       `json:"patch"`
	Channel  string    `json:"channel"`
	Platform string    `json:"platform"`
	Date     time.Time `json:"date,omitempty"`
}

// String returns the version as a string in format "major.minor.build.patch"
func (v ChromeVersion) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", v.Major, v.Minor, v.Build, v.Patch)
}

// ParseVersion parses a version string into a ChromeVersion
func ParseVersion(versionStr string) (*ChromeVersion, error) {
	parts := strings.Split(versionStr, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid version format: %s, expected major.minor.build.patch", versionStr)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	build, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid build version: %s", parts[2])
	}

	patch, err := strconv.Atoi(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid patch version: %s", parts[3])
	}

	return &ChromeVersion{
		Major: major,
		Minor: minor,
		Build: build,
		Patch: patch,
	}, nil
}

// Compare compares two Chrome versions
// Returns: -1 if v < other, 0 if v == other, 1 if v > other
func (v ChromeVersion) Compare(other ChromeVersion) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}

	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}

	if v.Build != other.Build {
		if v.Build < other.Build {
			return -1
		}
		return 1
	}

	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}

	return 0
}

// IsNewer returns true if this version is newer than the other
func (v ChromeVersion) IsNewer(other ChromeVersion) bool {
	return v.Compare(other) > 0
}

// IsOlder returns true if this version is older than the other
func (v ChromeVersion) IsOlder(other ChromeVersion) bool {
	return v.Compare(other) < 0
}

// Equal returns true if versions are equal
func (v ChromeVersion) Equal(other ChromeVersion) bool {
	return v.Compare(other) == 0
}