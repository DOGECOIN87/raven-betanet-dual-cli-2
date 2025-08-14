package tlsgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultCacheDir      = ".cache/chrome-versions"
	DefaultCacheFile     = "versions.json"
	DefaultCacheLifetime = 24 * time.Hour
)

// VersionCache represents cached Chrome version data
type VersionCache struct {
	Versions  []ChromeVersion `json:"versions"`
	UpdatedAt time.Time       `json:"updated_at"`
	TTL       time.Duration   `json:"ttl"`
}

// VersionCacheManager handles caching of Chrome version data
type VersionCacheManager struct {
	cacheDir  string
	cacheFile string
	ttl       time.Duration
}

// NewVersionCacheManager creates a new version cache manager
func NewVersionCacheManager() *VersionCacheManager {
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, DefaultCacheDir)
	
	return &VersionCacheManager{
		cacheDir:  cacheDir,
		cacheFile: DefaultCacheFile,
		ttl:       DefaultCacheLifetime,
	}
}

// NewVersionCacheManagerWithPath creates a cache manager with custom path
func NewVersionCacheManagerWithPath(cacheDir string, ttl time.Duration) *VersionCacheManager {
	return &VersionCacheManager{
		cacheDir:  cacheDir,
		cacheFile: DefaultCacheFile,
		ttl:       ttl,
	}
}

// GetCachedVersions retrieves cached versions if they're still valid
func (vcm *VersionCacheManager) GetCachedVersions() ([]ChromeVersion, bool, error) {
	cachePath := filepath.Join(vcm.cacheDir, vcm.cacheFile)
	
	// Check if cache file exists
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return nil, false, nil
	}
	
	// Read cache file
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read cache file: %w", err)
	}
	
	var cache VersionCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, false, fmt.Errorf("failed to parse cache file: %w", err)
	}
	
	// Check if cache is still valid
	if time.Since(cache.UpdatedAt) > vcm.ttl {
		return cache.Versions, false, nil // Return cached data but indicate it's stale
	}
	
	return cache.Versions, true, nil
}

// CacheVersions stores versions in the cache
func (vcm *VersionCacheManager) CacheVersions(versions []ChromeVersion) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(vcm.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	
	cache := VersionCache{
		Versions:  versions,
		UpdatedAt: time.Now(),
		TTL:       vcm.ttl,
	}
	
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %w", err)
	}
	
	cachePath := filepath.Join(vcm.cacheDir, vcm.cacheFile)
	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	
	return nil
}

// InvalidateCache removes the cache file
func (vcm *VersionCacheManager) InvalidateCache() error {
	cachePath := filepath.Join(vcm.cacheDir, vcm.cacheFile)
	
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return nil // Cache doesn't exist, nothing to invalidate
	}
	
	if err := os.Remove(cachePath); err != nil {
		return fmt.Errorf("failed to remove cache file: %w", err)
	}
	
	return nil
}

// GetCacheInfo returns information about the current cache
func (vcm *VersionCacheManager) GetCacheInfo() (*VersionCache, error) {
	cachePath := filepath.Join(vcm.cacheDir, vcm.cacheFile)
	
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cache file does not exist")
	}
	
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}
	
	var cache VersionCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("failed to parse cache file: %w", err)
	}
	
	return &cache, nil
}

// IsStale checks if the cache is stale without reading the versions
func (vcm *VersionCacheManager) IsStale() (bool, error) {
	cache, err := vcm.GetCacheInfo()
	if err != nil {
		return true, err // If we can't read cache, consider it stale
	}
	
	return time.Since(cache.UpdatedAt) > vcm.ttl, nil
}