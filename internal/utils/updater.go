package utils

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// UpdaterConfig holds configuration for the updater
type UpdaterConfig struct {
	Repository     string `json:"repository"`
	BinaryName     string `json:"binary_name"`
	CurrentVersion string `json:"current_version"`
	Logger         *Logger `json:"-"`
}

// GitHubRelease represents a GitHub release
type GitHubRelease struct {
	TagName     string          `json:"tag_name"`
	Name        string          `json:"name"`
	Body        string          `json:"body"`
	Draft       bool            `json:"draft"`
	Prerelease  bool            `json:"prerelease"`
	CreatedAt   time.Time       `json:"created_at"`
	PublishedAt time.Time       `json:"published_at"`
	Assets      []GitHubAsset   `json:"assets"`
}

// GitHubAsset represents a GitHub release asset
type GitHubAsset struct {
	Name               string    `json:"name"`
	Label              string    `json:"label"`
	ContentType        string    `json:"content_type"`
	Size               int64     `json:"size"`
	DownloadCount      int       `json:"download_count"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	BrowserDownloadURL string    `json:"browser_download_url"`
}

// Updater handles binary updates from GitHub releases
type Updater struct {
	config     UpdaterConfig
	httpClient *HTTPClient
	logger     *Logger
}

// NewUpdater creates a new updater
func NewUpdater(config UpdaterConfig) *Updater {
	logger := config.Logger
	if logger == nil {
		logger = NewDefaultLogger()
	}

	return &Updater{
		config:     config,
		httpClient: NewDefaultHTTPClient(),
		logger:     logger,
	}
}

// CheckForUpdate checks if a newer version is available
func (u *Updater) CheckForUpdate() (*GitHubRelease, bool, error) {
	u.logger.WithComponent("updater").Debugf("Checking for updates for %s", u.config.BinaryName)

	// Get latest release from GitHub API
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.config.Repository)
	
	var release GitHubRelease
	err := u.httpClient.GetJSON(apiURL, &release)
	if err != nil {
		return nil, false, fmt.Errorf("failed to fetch latest release: %w", err)
	}

	// Skip draft and prerelease versions
	if release.Draft || release.Prerelease {
		u.logger.WithComponent("updater").Debugf("Skipping draft/prerelease version: %s", release.TagName)
		return &release, false, nil
	}

	// Compare versions
	hasUpdate := u.isNewerVersion(release.TagName, u.config.CurrentVersion)
	
	u.logger.WithComponent("updater").Debugf("Version comparison: current=%s, latest=%s, hasUpdate=%t", 
		u.config.CurrentVersion, release.TagName, hasUpdate)

	return &release, hasUpdate, nil
}

// Update downloads and installs the new version
func (u *Updater) Update(release *GitHubRelease, force bool) error {
	u.logger.WithComponent("updater").Infof("Starting update to version %s", release.TagName)

	// Find the appropriate asset for current platform
	asset, err := u.findAssetForPlatform(release.Assets)
	if err != nil {
		return fmt.Errorf("failed to find asset for platform: %w", err)
	}

	u.logger.WithComponent("updater").Infof("Found asset: %s (%d bytes)", asset.Name, asset.Size)

	// Create temporary directory for download
	tempDir, err := os.MkdirTemp("", "updater-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Download the asset
	downloadPath := filepath.Join(tempDir, asset.Name)
	err = u.httpClient.DownloadFile(asset.BrowserDownloadURL, downloadPath)
	if err != nil {
		return fmt.Errorf("failed to download asset: %w", err)
	}

	u.logger.WithComponent("updater").Infof("Downloaded asset to: %s", downloadPath)

	// Extract binary from archive if needed
	binaryPath, err := u.extractBinary(downloadPath, tempDir)
	if err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}

	// Get current executable path
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	// Create backup of current binary
	backupPath := currentExe + ".backup"
	err = u.copyFile(currentExe, backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	u.logger.WithComponent("updater").Infof("Created backup: %s", backupPath)

	// Replace current binary with new one
	err = u.replaceExecutable(currentExe, binaryPath)
	if err != nil {
		// Restore backup on failure
		u.logger.WithComponent("updater").Errorf("Failed to replace executable, restoring backup: %v", err)
		if restoreErr := u.copyFile(backupPath, currentExe); restoreErr != nil {
			return fmt.Errorf("failed to replace executable and restore backup: %w (restore error: %v)", err, restoreErr)
		}
		return fmt.Errorf("failed to replace executable: %w", err)
	}

	// Remove backup on success
	os.Remove(backupPath)

	u.logger.WithComponent("updater").Infof("Successfully updated to version %s", release.TagName)
	return nil
}

// isNewerVersion compares two version strings
func (u *Updater) isNewerVersion(latest, current string) bool {
	// Remove 'v' prefix if present
	latest = strings.TrimPrefix(latest, "v")
	current = strings.TrimPrefix(current, "v")

	// Handle special cases
	if current == "dev" || current == "unknown" {
		return true // Always update from dev/unknown versions
	}

	if latest == current {
		return false
	}

	// Simple lexicographic comparison for now
	// Real implementation would use semantic versioning
	return latest > current
}

// findAssetForPlatform finds the appropriate asset for the current platform
func (u *Updater) findAssetForPlatform(assets []GitHubAsset) (*GitHubAsset, error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// Build platform identifier patterns
	patterns := []string{
		fmt.Sprintf("%s-%s-%s", u.config.BinaryName, goos, goarch),
		fmt.Sprintf("%s_%s_%s", u.config.BinaryName, goos, goarch),
		fmt.Sprintf("%s-%s", goos, goarch),
		fmt.Sprintf("%s_%s", goos, goarch),
	}

	// Add Windows .exe extension
	if goos == "windows" {
		for _, pattern := range patterns {
			patterns = append(patterns, pattern+".exe")
		}
	}

	// Find matching asset
	for _, asset := range assets {
		assetName := strings.ToLower(asset.Name)
		
		for _, pattern := range patterns {
			if strings.Contains(assetName, strings.ToLower(pattern)) {
				return &asset, nil
			}
		}
	}

	return nil, fmt.Errorf("no asset found for platform %s/%s", goos, goarch)
}

// extractBinary extracts the binary from an archive or returns the file path if it's already a binary
func (u *Updater) extractBinary(archivePath, extractDir string) (string, error) {
	// Check if it's an archive by extension
	ext := strings.ToLower(filepath.Ext(archivePath))
	
	switch ext {
	case ".zip":
		return u.extractFromZip(archivePath, extractDir)
	case ".gz":
		if strings.HasSuffix(strings.ToLower(archivePath), ".tar.gz") {
			return u.extractFromTarGz(archivePath, extractDir)
		}
		return u.extractFromGzip(archivePath, extractDir)
	case ".tar":
		return u.extractFromTar(archivePath, extractDir)
	default:
		// Assume it's already a binary
		return archivePath, nil
	}
}

// extractFromZip extracts binary from ZIP archive
func (u *Updater) extractFromZip(zipPath, extractDir string) (string, error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to open ZIP file: %w", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		if u.isBinaryFile(file.Name) {
			return u.extractZipFile(file, extractDir)
		}
	}

	return "", fmt.Errorf("no binary file found in ZIP archive")
}

// extractFromTarGz extracts binary from tar.gz archive
func (u *Updater) extractFromTarGz(tarGzPath, extractDir string) (string, error) {
	file, err := os.Open(tarGzPath)
	if err != nil {
		return "", fmt.Errorf("failed to open tar.gz file: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read tar entry: %w", err)
		}

		if header.Typeflag == tar.TypeReg && u.isBinaryFile(header.Name) {
			return u.extractTarFile(tarReader, header, extractDir)
		}
	}

	return "", fmt.Errorf("no binary file found in tar.gz archive")
}

// extractFromTar extracts binary from tar archive
func (u *Updater) extractFromTar(tarPath, extractDir string) (string, error) {
	file, err := os.Open(tarPath)
	if err != nil {
		return "", fmt.Errorf("failed to open tar file: %w", err)
	}
	defer file.Close()

	tarReader := tar.NewReader(file)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read tar entry: %w", err)
		}

		if header.Typeflag == tar.TypeReg && u.isBinaryFile(header.Name) {
			return u.extractTarFile(tarReader, header, extractDir)
		}
	}

	return "", fmt.Errorf("no binary file found in tar archive")
}

// extractFromGzip extracts binary from gzip file
func (u *Updater) extractFromGzip(gzPath, extractDir string) (string, error) {
	file, err := os.Open(gzPath)
	if err != nil {
		return "", fmt.Errorf("failed to open gzip file: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Extract to file with same name minus .gz extension
	baseName := strings.TrimSuffix(filepath.Base(gzPath), ".gz")
	extractPath := filepath.Join(extractDir, baseName)

	outFile, err := os.Create(extractPath)
	if err != nil {
		return "", fmt.Errorf("failed to create extracted file: %w", err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, gzReader)
	if err != nil {
		return "", fmt.Errorf("failed to extract gzip file: %w", err)
	}

	// Make executable
	err = os.Chmod(extractPath, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to make file executable: %w", err)
	}

	return extractPath, nil
}

// extractZipFile extracts a single file from ZIP archive
func (u *Updater) extractZipFile(file *zip.File, extractDir string) (string, error) {
	reader, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open ZIP file entry: %w", err)
	}
	defer reader.Close()

	extractPath := filepath.Join(extractDir, filepath.Base(file.Name))
	outFile, err := os.Create(extractPath)
	if err != nil {
		return "", fmt.Errorf("failed to create extracted file: %w", err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, reader)
	if err != nil {
		return "", fmt.Errorf("failed to extract ZIP file: %w", err)
	}

	// Make executable
	err = os.Chmod(extractPath, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to make file executable: %w", err)
	}

	return extractPath, nil
}

// extractTarFile extracts a single file from tar archive
func (u *Updater) extractTarFile(tarReader *tar.Reader, header *tar.Header, extractDir string) (string, error) {
	extractPath := filepath.Join(extractDir, filepath.Base(header.Name))
	outFile, err := os.Create(extractPath)
	if err != nil {
		return "", fmt.Errorf("failed to create extracted file: %w", err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, tarReader)
	if err != nil {
		return "", fmt.Errorf("failed to extract tar file: %w", err)
	}

	// Make executable
	err = os.Chmod(extractPath, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to make file executable: %w", err)
	}

	return extractPath, nil
}

// isBinaryFile checks if a file name matches the expected binary
func (u *Updater) isBinaryFile(filename string) bool {
	baseName := filepath.Base(filename)
	
	// Check for exact match
	if baseName == u.config.BinaryName {
		return true
	}
	
	// Check for Windows executable
	if runtime.GOOS == "windows" && baseName == u.config.BinaryName+".exe" {
		return true
	}
	
	// Check if filename contains binary name
	return strings.Contains(strings.ToLower(baseName), strings.ToLower(u.config.BinaryName))
}

// copyFile copies a file from src to dst
func (u *Updater) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	// Copy file permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get source file info: %w", err)
	}

	err = os.Chmod(dst, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	return nil
}

// replaceExecutable replaces the current executable with a new one
func (u *Updater) replaceExecutable(currentPath, newPath string) error {
	// On Windows, we can't replace a running executable directly
	if runtime.GOOS == "windows" {
		return u.replaceExecutableWindows(currentPath, newPath)
	}

	// On Unix-like systems, we can replace the file directly
	return u.copyFile(newPath, currentPath)
}

// replaceExecutableWindows handles executable replacement on Windows
func (u *Updater) replaceExecutableWindows(currentPath, newPath string) error {
	// Move current executable to temporary name
	tempPath := currentPath + ".old"
	err := os.Rename(currentPath, tempPath)
	if err != nil {
		return fmt.Errorf("failed to move current executable: %w", err)
	}

	// Copy new executable to current location
	err = u.copyFile(newPath, currentPath)
	if err != nil {
		// Restore original file on failure
		os.Rename(tempPath, currentPath)
		return fmt.Errorf("failed to copy new executable: %w", err)
	}

	// Schedule deletion of old executable on next boot
	// This is a simplified approach - production code might use more sophisticated methods
	go func() {
		time.Sleep(5 * time.Second)
		os.Remove(tempPath)
	}()

	return nil
}

// GetCurrentVersion returns the current version
func (u *Updater) GetCurrentVersion() string {
	return u.config.CurrentVersion
}

// SetCurrentVersion updates the current version
func (u *Updater) SetCurrentVersion(version string) {
	u.config.CurrentVersion = version
}