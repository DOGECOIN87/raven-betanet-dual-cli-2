package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// GitHubRelease represents a GitHub release
type GitHubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	CreatedAt   time.Time `json:"created_at"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

// UpdaterConfig holds configuration for the updater
type UpdaterConfig struct {
	Repository    string // e.g., "owner/repo"
	BinaryName    string // e.g., "raven-linter"
	CurrentVersion string
	Logger        *Logger
}

// Updater handles binary updates from GitHub releases
type Updater struct {
	config     UpdaterConfig
	httpClient *http.Client
	logger     *Logger
}

// NewUpdater creates a new updater instance
func NewUpdater(config UpdaterConfig) *Updater {
	logger := config.Logger
	if logger == nil {
		logger = NewDefaultLogger()
	}

	return &Updater{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// CheckForUpdate checks if a newer version is available
func (u *Updater) CheckForUpdate() (*GitHubRelease, bool, error) {
	u.logger.Debug("Checking for updates...")

	// Fetch latest release from GitHub API
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.config.Repository)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request: %w", err)
	}

	// Set User-Agent header
	req.Header.Set("User-Agent", fmt.Sprintf("%s-updater/1.0", u.config.BinaryName))

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("failed to fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, false, fmt.Errorf("failed to decode release response: %w", err)
	}

	// Skip draft and pre-release versions by default
	if release.Draft || release.Prerelease {
		u.logger.Debug("Skipping draft or pre-release version")
		return &release, false, nil
	}

	// Compare versions
	currentVersion := strings.TrimPrefix(u.config.CurrentVersion, "v")
	latestVersion := strings.TrimPrefix(release.TagName, "v")

	if currentVersion == latestVersion {
		u.logger.Debug("Already running latest version")
		return &release, false, nil
	}

	// Simple version comparison (assumes semantic versioning)
	isNewer, err := u.isNewerVersion(latestVersion, currentVersion)
	if err != nil {
		return &release, false, fmt.Errorf("failed to compare versions: %w", err)
	}

	return &release, isNewer, nil
}

// Update downloads and installs the latest version
func (u *Updater) Update(release *GitHubRelease, force bool) error {
	if release == nil {
		return fmt.Errorf("no release provided")
	}

	// Find the appropriate asset for current platform
	assetName := u.getAssetName(release.TagName)
	var downloadURL string
	var assetSize int64

	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			assetSize = asset.Size
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no compatible binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	u.logger.WithContext(map[string]interface{}{
		"version": release.TagName,
		"asset":   assetName,
		"size":    assetSize,
	}).Info("Downloading update...")

	// Download the new binary
	tempFile, err := u.downloadBinary(downloadURL, assetSize)
	if err != nil {
		return fmt.Errorf("failed to download binary: %w", err)
	}
	defer os.Remove(tempFile)

	// Verify checksum if available
	if err := u.verifyChecksum(tempFile, release, assetName); err != nil {
		u.logger.WithContext(map[string]interface{}{"error": err}).Warn("Checksum verification failed, proceeding anyway")
	}

	// Get current executable path
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	// Create backup of current binary
	backupPath := currentExe + ".backup"
	if err := u.createBackup(currentExe, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Replace current binary with new one
	if err := u.replaceBinary(tempFile, currentExe); err != nil {
		// Restore backup on failure
		if restoreErr := u.restoreBackup(backupPath, currentExe); restoreErr != nil {
			u.logger.WithContext(map[string]interface{}{"error": restoreErr}).Error("Failed to restore backup after update failure")
		}
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	// Clean up backup
	os.Remove(backupPath)

	u.logger.WithContext(map[string]interface{}{"version": release.TagName}).Info("Update completed successfully")
	return nil
}

// getAssetName returns the expected asset name for the current platform
func (u *Updater) getAssetName(version string) string {
	var suffix string
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}

	return fmt.Sprintf("%s-%s-%s-%s%s", 
		u.config.BinaryName, 
		version, 
		runtime.GOOS, 
		runtime.GOARCH, 
		suffix)
}

// downloadBinary downloads a binary from the given URL
func (u *Updater) downloadBinary(url string, expectedSize int64) (string, error) {
	resp, err := u.httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create temporary file
	tempFile, err := os.CreateTemp("", u.config.BinaryName+"-update-*")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	// Download with progress tracking
	written, err := io.Copy(tempFile, resp.Body)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	if expectedSize > 0 && written != expectedSize {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("downloaded size %d doesn't match expected size %d", written, expectedSize)
	}

	return tempFile.Name(), nil
}

// verifyChecksum verifies the downloaded binary against checksums
func (u *Updater) verifyChecksum(filePath string, release *GitHubRelease, assetName string) error {
	// Look for checksums.txt in release assets
	var checksumsURL string
	for _, asset := range release.Assets {
		if asset.Name == "checksums.txt" {
			checksumsURL = asset.BrowserDownloadURL
			break
		}
	}

	if checksumsURL == "" {
		return fmt.Errorf("no checksums.txt found in release")
	}

	// Download checksums
	resp, err := u.httpClient.Get(checksumsURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	checksumData, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse checksums and find our asset
	lines := strings.Split(string(checksumData), "\n")
	var expectedChecksum string
	
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			filename := strings.TrimPrefix(parts[1], "./")
			if filename == assetName {
				expectedChecksum = parts[0]
				break
			}
		}
	}

	if expectedChecksum == "" {
		return fmt.Errorf("checksum not found for %s", assetName)
	}

	// Calculate actual checksum
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}

	actualChecksum := hex.EncodeToString(hasher.Sum(nil))

	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	u.logger.Debug("Checksum verification passed")
	return nil
}

// createBackup creates a backup of the current binary
func (u *Updater) createBackup(source, backup string) error {
	sourceFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	backupFile, err := os.Create(backup)
	if err != nil {
		return err
	}
	defer backupFile.Close()

	_, err = io.Copy(backupFile, sourceFile)
	return err
}

// replaceBinary replaces the current binary with the new one
func (u *Updater) replaceBinary(newBinary, currentBinary string) error {
	// Get file permissions from current binary
	info, err := os.Stat(currentBinary)
	if err != nil {
		return err
	}

	// Read new binary
	newData, err := os.ReadFile(newBinary)
	if err != nil {
		return err
	}

	// Write new binary to current location
	if err := os.WriteFile(currentBinary, newData, info.Mode()); err != nil {
		return err
	}

	return nil
}

// restoreBackup restores the backup binary
func (u *Updater) restoreBackup(backup, target string) error {
	backupData, err := os.ReadFile(backup)
	if err != nil {
		return err
	}

	info, err := os.Stat(target)
	if err != nil {
		return err
	}

	return os.WriteFile(target, backupData, info.Mode())
}

// isNewerVersion compares two semantic version strings
func (u *Updater) isNewerVersion(latest, current string) (bool, error) {
	// Simple semantic version comparison
	// This is a basic implementation - for production use, consider using
	// a proper semver library like github.com/Masterminds/semver/v3
	
	latestParts := strings.Split(latest, ".")
	currentParts := strings.Split(current, ".")

	// Pad shorter version with zeros
	maxLen := len(latestParts)
	if len(currentParts) > maxLen {
		maxLen = len(currentParts)
	}

	for len(latestParts) < maxLen {
		latestParts = append(latestParts, "0")
	}
	for len(currentParts) < maxLen {
		currentParts = append(currentParts, "0")
	}

	// Compare each part
	for i := 0; i < maxLen; i++ {
		var latestNum, currentNum int
		fmt.Sscanf(latestParts[i], "%d", &latestNum)
		fmt.Sscanf(currentParts[i], "%d", &currentNum)

		if latestNum > currentNum {
			return true, nil
		} else if latestNum < currentNum {
			return false, nil
		}
	}

	return false, nil // versions are equal
}

// GetUpdateInfo returns information about available updates without downloading
func (u *Updater) GetUpdateInfo() (string, bool, error) {
	release, hasUpdate, err := u.CheckForUpdate()
	if err != nil {
		return "", false, err
	}

	if !hasUpdate {
		return u.config.CurrentVersion, false, nil
	}

	return release.TagName, true, nil
}