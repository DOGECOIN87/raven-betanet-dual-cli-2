package tlsgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VersionCacheManager handles caching of Chrome version information
type VersionCacheManager struct {
	cacheDir string
	cacheTTL time.Duration
}

// CachedVersionData represents cached Chrome version data
type CachedVersionData struct {
	Versions  []ChromeVersion `json:"versions"`
	CachedAt  time.Time       `json:"cached_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Source    string          `json:"source"`
}

// NewVersionCacheManager creates a new version cache manager
func NewVersionCacheManager(cacheTTL time.Duration) *VersionCacheManager {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if home directory is not available
		homeDir = "."
	}
	
	cacheDir := filepath.Join(homeDir, ".raven-betanet", "cache", "chrome-versions")
	
	return &VersionCacheManager{
		cacheDir: cacheDir,
		cacheTTL: cacheTTL,
	}
}

// NewVersionCacheManagerWithPath creates a version cache manager with custom cache directory
func NewVersionCacheManagerWithPath(cacheDir string, cacheTTL time.Duration) *VersionCacheManager {
	return &VersionCacheManager{
		cacheDir: cacheDir,
		cacheTTL: cacheTTL,
	}
}

// GetCachedVersions retrieves cached Chrome versions if they are still valid
func (v *VersionCacheManager) GetCachedVersions() ([]ChromeVersion, bool, error) {
	cacheFile := filepath.Join(v.cacheDir, "versions.json")
	
	// Check if cache file exists
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return nil, false, nil // No cache file, not an error
	}
	
	// Read cache file
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read cache file: %w", err)
	}
	
	// Parse cached data
	var cachedData CachedVersionData
	if err := json.Unmarshal(data, &cachedData); err != nil {
		return nil, false, fmt.Errorf("failed to parse cache file: %w", err)
	}
	
	// Check if cache is still valid
	if time.Now().After(cachedData.ExpiresAt) {
		return cachedData.Versions, false, nil // Cache expired
	}
	
	return cachedData.Versions, true, nil
}

// CacheVersions stores Chrome versions in the cache
func (v *VersionCacheManager) CacheVersions(versions []ChromeVersion) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(v.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	
	// Create cached data
	now := time.Now()
	cachedData := CachedVersionData{
		Versions:  versions,
		CachedAt:  now,
		ExpiresAt: now.Add(v.cacheTTL),
		Source:    "chromium-api",
	}
	
	// Marshal to JSON
	data, err := json.MarshalIndent(cachedData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %w", err)
	}
	
	// Write to cache file
	cacheFile := filepath.Join(v.cacheDir, "versions.json")
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	
	return nil
}

// ClearCache removes all cached version data
func (v *VersionCacheManager) ClearCache() error {
	cacheFile := filepath.Join(v.cacheDir, "versions.json")
	
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return nil // Cache file doesn't exist, nothing to clear
	}
	
	if err := os.Remove(cacheFile); err != nil {
		return fmt.Errorf("failed to remove cache file: %w", err)
	}
	
	return nil
}

// GetCacheInfo returns information about the current cache
func (v *VersionCacheManager) GetCacheInfo() (*CacheInfo, error) {
	cacheFile := filepath.Join(v.cacheDir, "versions.json")
	
	info := &CacheInfo{
		CacheDir:  v.cacheDir,
		CacheFile: cacheFile,
		TTL:       v.cacheTTL,
		Exists:    false,
		Valid:     false,
	}
	
	// Check if cache file exists
	fileInfo, err := os.Stat(cacheFile)
	if os.IsNotExist(err) {
		return info, nil
	} else if err != nil {
		return info, fmt.Errorf("failed to stat cache file: %w", err)
	}
	
	info.Exists = true
	info.Size = fileInfo.Size()
	info.ModTime = fileInfo.ModTime()
	
	// Read and parse cache to get more details
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return info, fmt.Errorf("failed to read cache file: %w", err)
	}
	
	var cachedData CachedVersionData
	if err := json.Unmarshal(data, &cachedData); err != nil {
		return info, fmt.Errorf("failed to parse cache file: %w", err)
	}
	
	info.CachedAt = cachedData.CachedAt
	info.ExpiresAt = cachedData.ExpiresAt
	info.VersionCount = len(cachedData.Versions)
	info.Source = cachedData.Source
	info.Valid = time.Now().Before(cachedData.ExpiresAt)
	
	return info, nil
}

// CacheInfo represents information about the version cache
type CacheInfo struct {
	CacheDir     string        `json:"cache_dir"`
	CacheFile    string        `json:"cache_file"`
	TTL          time.Duration `json:"ttl"`
	Exists       bool          `json:"exists"`
	Valid        bool          `json:"valid"`
	Size         int64         `json:"size"`
	ModTime      time.Time     `json:"mod_time"`
	CachedAt     time.Time     `json:"cached_at"`
	ExpiresAt    time.Time     `json:"expires_at"`
	VersionCount int           `json:"version_count"`
	Source       string        `json:"source"`
}

// IsExpired checks if the cache is expired
func (c *CacheInfo) IsExpired() bool {
	return !c.Valid
}

// TimeUntilExpiry returns the time until cache expiry
func (c *CacheInfo) TimeUntilExpiry() time.Duration {
	if c.IsExpired() {
		return 0
	}
	return time.Until(c.ExpiresAt)
}

// GetCacheAge returns how long ago the cache was created
func (c *CacheInfo) GetCacheAge() time.Duration {
	if !c.Exists {
		return 0
	}
	return time.Since(c.CachedAt)
}

// TemplateCache handles caching of ClientHello templates
type TemplateCache struct {
	cacheDir string
}

// NewTemplateCache creates a new template cache
func NewTemplateCache() *TemplateCache {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	
	cacheDir := filepath.Join(homeDir, ".raven-betanet", "templates")
	
	return &TemplateCache{
		cacheDir: cacheDir,
	}
}

// NewTemplateCacheWithPath creates a template cache with custom directory
func NewTemplateCacheWithPath(cacheDir string) *TemplateCache {
	return &TemplateCache{
		cacheDir: cacheDir,
	}
}

// GetTemplate retrieves a cached template for the specified Chrome version
func (t *TemplateCache) GetTemplate(version ChromeVersion) (*ClientHelloTemplate, error) {
	templateFile := t.getTemplateFilePath(version)
	
	// Check if template file exists
	if _, err := os.Stat(templateFile); os.IsNotExist(err) {
		return nil, nil // No cached template
	}
	
	// Read template file
	data, err := os.ReadFile(templateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}
	
	// Parse template
	var template ClientHelloTemplate
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template file: %w", err)
	}
	
	return &template, nil
}

// StoreTemplate stores a template in the cache
func (t *TemplateCache) StoreTemplate(template *ClientHelloTemplate) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(t.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	
	// Marshal template to JSON
	data, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}
	
	// Write to template file
	templateFile := t.getTemplateFilePath(template.Version)
	if err := os.WriteFile(templateFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write template file: %w", err)
	}
	
	return nil
}

// ListTemplates returns a list of all cached templates
func (t *TemplateCache) ListTemplates() ([]TemplateInfo, error) {
	var templates []TemplateInfo
	
	// Check if cache directory exists
	if _, err := os.Stat(t.cacheDir); os.IsNotExist(err) {
		return templates, nil // No cache directory
	}
	
	// Read directory contents
	entries, err := os.ReadDir(t.cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache directory: %w", err)
	}
	
	// Process each template file
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		
		templateFile := filepath.Join(t.cacheDir, entry.Name())
		
		// Get file info
		fileInfo, err := entry.Info()
		if err != nil {
			continue
		}
		
		// Try to parse template to get version info
		data, err := os.ReadFile(templateFile)
		if err != nil {
			continue
		}
		
		var template ClientHelloTemplate
		if err := json.Unmarshal(data, &template); err != nil {
			continue
		}
		
		templateInfo := TemplateInfo{
			Version:     template.Version,
			FilePath:    templateFile,
			Size:        fileInfo.Size(),
			ModTime:     fileInfo.ModTime(),
			GeneratedAt: template.GeneratedAt,
			JA3Hash:     template.JA3Hash,
		}
		
		templates = append(templates, templateInfo)
	}
	
	return templates, nil
}

// TemplateInfo represents information about a cached template
type TemplateInfo struct {
	Version     ChromeVersion `json:"version"`
	FilePath    string        `json:"file_path"`
	Size        int64         `json:"size"`
	ModTime     time.Time     `json:"mod_time"`
	GeneratedAt time.Time     `json:"generated_at"`
	JA3Hash     string        `json:"ja3_hash"`
}

// ClearTemplates removes all cached templates
func (t *TemplateCache) ClearTemplates() error {
	// Check if cache directory exists
	if _, err := os.Stat(t.cacheDir); os.IsNotExist(err) {
		return nil // No cache directory
	}
	
	// Remove entire cache directory
	if err := os.RemoveAll(t.cacheDir); err != nil {
		return fmt.Errorf("failed to remove cache directory: %w", err)
	}
	
	return nil
}

// RemoveTemplate removes a specific template from the cache
func (t *TemplateCache) RemoveTemplate(version ChromeVersion) error {
	templateFile := t.getTemplateFilePath(version)
	
	if _, err := os.Stat(templateFile); os.IsNotExist(err) {
		return nil // Template doesn't exist
	}
	
	if err := os.Remove(templateFile); err != nil {
		return fmt.Errorf("failed to remove template file: %w", err)
	}
	
	return nil
}

// getTemplateFilePath returns the file path for a template
func (t *TemplateCache) getTemplateFilePath(version ChromeVersion) string {
	filename := fmt.Sprintf("chrome_%s.json", version.String())
	return filepath.Join(t.cacheDir, filename)
}

// GetCacheSize returns the total size of the template cache
func (t *TemplateCache) GetCacheSize() (int64, error) {
	var totalSize int64
	
	// Check if cache directory exists
	if _, err := os.Stat(t.cacheDir); os.IsNotExist(err) {
		return 0, nil
	}
	
	// Walk through cache directory
	err := filepath.Walk(t.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	
	if err != nil {
		return 0, fmt.Errorf("failed to calculate cache size: %w", err)
	}
	
	return totalSize, nil
}

// CleanupExpiredTemplates removes templates older than the specified age
func (t *TemplateCache) CleanupExpiredTemplates(maxAge time.Duration) error {
	templates, err := t.ListTemplates()
	if err != nil {
		return fmt.Errorf("failed to list templates: %w", err)
	}
	
	cutoff := time.Now().Add(-maxAge)
	
	for _, template := range templates {
		if template.GeneratedAt.Before(cutoff) {
			if err := t.RemoveTemplate(template.Version); err != nil {
				// Log error but continue with other templates
				continue
			}
		}
	}
	
	return nil
}

