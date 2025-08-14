package utils

import "fmt"

var (
	// Version information - set via ldflags during build
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// GetVersionString returns a formatted version string
func GetVersionString() string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, Date)
}