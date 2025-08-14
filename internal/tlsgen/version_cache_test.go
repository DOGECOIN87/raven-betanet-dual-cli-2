package tlsgen

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewVersionCacheManager(t *testing.T) {
	vcm := NewVersionCacheManager()
	
	if vcm == nil {
		t.Fatal("NewVersionCacheManager() returned nil")
	}
	
	if vcm.cacheFile != DefaultCacheFile {
		t.Errorf("NewVersionCacheManager() cacheFile = %v, want %v", vcm.cacheFile, DefaultCacheFile)
	}
	
	if vcm.ttl != DefaultCacheLifetime {
		t.Errorf("NewVersionCacheManager() ttl = %v, want %v", vcm.ttl, DefaultCacheLifetime)
	}
}

func TestNewVersionCacheManagerWithPath(t *testing.T) {
	customDir := "/tmp/test-cache"
	customTTL := 2 * time.Hour
	
	vcm := NewVersionCacheManagerWithPath(customDir, customTTL)
	
	if vcm == nil {
		t.Fatal("NewVersionCacheManagerWithPath() returned nil")
	}
	
	if vcm.cacheDir != customDir {
		t.Errorf("NewVersionCacheManagerWithPath() cacheDir = %v, want %v", vcm.cacheDir, customDir)
	}
	
	if vcm.ttl != customTTL {
		t.Errorf("NewVersionCacheManagerWithPath() ttl = %v, want %v", vcm.ttl, customTTL)
	}
}

func TestVersionCacheManager_CacheAndGetVersions(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "chrome-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	vcm := NewVersionCacheManagerWithPath(tempDir, time.Hour)
	
	// Test data
	testVersions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109, Channel: "Stable", Platform: "Linux"},
		{Major: 119, Minor: 0, Build: 6045, Patch: 199, Channel: "Stable", Platform: "Linux"},
	}
	
	// Test caching versions
	err = vcm.CacheVersions(testVersions)
	if err != nil {
		t.Errorf("CacheVersions() unexpected error: %v", err)
	}
	
	// Verify cache file was created
	cachePath := filepath.Join(tempDir, DefaultCacheFile)
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Error("CacheVersions() did not create cache file")
	}
	
	// Test getting cached versions
	cachedVersions, isValid, err := vcm.GetCachedVersions()
	if err != nil {
		t.Errorf("GetCachedVersions() unexpected error: %v", err)
	}
	
	if !isValid {
		t.Error("GetCachedVersions() returned invalid cache when it should be valid")
	}
	
	if len(cachedVersions) != len(testVersions) {
		t.Errorf("GetCachedVersions() returned %d versions, want %d", len(cachedVersions), len(testVersions))
	}
	
	// Verify version data
	for i, version := range cachedVersions {
		if !version.Equal(testVersions[i]) {
			t.Errorf("GetCachedVersions() version[%d] = %v, want %v", i, version, testVersions[i])
		}
	}
}

func TestVersionCacheManager_GetCachedVersions_NoCache(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "chrome-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	vcm := NewVersionCacheManagerWithPath(tempDir, time.Hour)
	
	// Test getting cached versions when no cache exists
	cachedVersions, isValid, err := vcm.GetCachedVersions()
	if err != nil {
		t.Errorf("GetCachedVersions() unexpected error: %v", err)
	}
	
	if isValid {
		t.Error("GetCachedVersions() returned valid cache when no cache should exist")
	}
	
	if cachedVersions != nil {
		t.Error("GetCachedVersions() returned non-nil versions when no cache should exist")
	}
}

func TestVersionCacheManager_GetCachedVersions_StaleCache(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "chrome-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Use very short TTL to make cache stale immediately
	vcm := NewVersionCacheManagerWithPath(tempDir, time.Nanosecond)
	
	// Test data
	testVersions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109, Channel: "Stable", Platform: "Linux"},
	}
	
	// Cache versions
	err = vcm.CacheVersions(testVersions)
	if err != nil {
		t.Errorf("CacheVersions() unexpected error: %v", err)
	}
	
	// Wait for cache to become stale
	time.Sleep(time.Millisecond)
	
	// Test getting stale cached versions
	cachedVersions, isValid, err := vcm.GetCachedVersions()
	if err != nil {
		t.Errorf("GetCachedVersions() unexpected error: %v", err)
	}
	
	if isValid {
		t.Error("GetCachedVersions() returned valid cache when cache should be stale")
	}
	
	if cachedVersions == nil {
		t.Error("GetCachedVersions() returned nil versions, should return stale data")
	}
	
	if len(cachedVersions) != len(testVersions) {
		t.Errorf("GetCachedVersions() returned %d versions, want %d", len(cachedVersions), len(testVersions))
	}
}

func TestVersionCacheManager_InvalidateCache(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "chrome-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	vcm := NewVersionCacheManagerWithPath(tempDir, time.Hour)
	
	// Test data
	testVersions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109, Channel: "Stable", Platform: "Linux"},
	}
	
	// Cache versions
	err = vcm.CacheVersions(testVersions)
	if err != nil {
		t.Errorf("CacheVersions() unexpected error: %v", err)
	}
	
	// Verify cache file exists
	cachePath := filepath.Join(tempDir, DefaultCacheFile)
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Error("Cache file should exist before invalidation")
	}
	
	// Invalidate cache
	err = vcm.InvalidateCache()
	if err != nil {
		t.Errorf("InvalidateCache() unexpected error: %v", err)
	}
	
	// Verify cache file was removed
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Error("Cache file should not exist after invalidation")
	}
	
	// Test invalidating non-existent cache (should not error)
	err = vcm.InvalidateCache()
	if err != nil {
		t.Errorf("InvalidateCache() on non-existent cache unexpected error: %v", err)
	}
}

func TestVersionCacheManager_GetCacheInfo(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "chrome-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	vcm := NewVersionCacheManagerWithPath(tempDir, time.Hour)
	
	// Test getting cache info when no cache exists
	_, err = vcm.GetCacheInfo()
	if err == nil {
		t.Error("GetCacheInfo() should return error when no cache exists")
	}
	
	// Test data
	testVersions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109, Channel: "Stable", Platform: "Linux"},
	}
	
	// Cache versions
	beforeCache := time.Now()
	err = vcm.CacheVersions(testVersions)
	if err != nil {
		t.Errorf("CacheVersions() unexpected error: %v", err)
	}
	afterCache := time.Now()
	
	// Get cache info
	cacheInfo, err := vcm.GetCacheInfo()
	if err != nil {
		t.Errorf("GetCacheInfo() unexpected error: %v", err)
	}
	
	if cacheInfo == nil {
		t.Fatal("GetCacheInfo() returned nil cache info")
	}
	
	if len(cacheInfo.Versions) != len(testVersions) {
		t.Errorf("GetCacheInfo() returned %d versions, want %d", len(cacheInfo.Versions), len(testVersions))
	}
	
	if cacheInfo.TTL != time.Hour {
		t.Errorf("GetCacheInfo() TTL = %v, want %v", cacheInfo.TTL, time.Hour)
	}
	
	// Check that UpdatedAt is reasonable
	if cacheInfo.UpdatedAt.Before(beforeCache) || cacheInfo.UpdatedAt.After(afterCache) {
		t.Errorf("GetCacheInfo() UpdatedAt = %v, should be between %v and %v", 
			cacheInfo.UpdatedAt, beforeCache, afterCache)
	}
}

func TestVersionCacheManager_IsStale(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "chrome-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Test when no cache exists
	vcm := NewVersionCacheManagerWithPath(tempDir, time.Hour)
	isStale, err := vcm.IsStale()
	if err == nil {
		t.Error("IsStale() should return error when no cache exists")
	}
	if !isStale {
		t.Error("IsStale() should return true when no cache exists")
	}
	
	// Test with fresh cache
	vcm = NewVersionCacheManagerWithPath(tempDir, time.Hour)
	testVersions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109, Channel: "Stable", Platform: "Linux"},
	}
	
	err = vcm.CacheVersions(testVersions)
	if err != nil {
		t.Errorf("CacheVersions() unexpected error: %v", err)
	}
	
	isStale, err = vcm.IsStale()
	if err != nil {
		t.Errorf("IsStale() unexpected error: %v", err)
	}
	if isStale {
		t.Error("IsStale() should return false for fresh cache")
	}
	
	// Test with stale cache
	vcm = NewVersionCacheManagerWithPath(tempDir, time.Nanosecond)
	time.Sleep(time.Millisecond)
	
	isStale, err = vcm.IsStale()
	if err != nil {
		t.Errorf("IsStale() unexpected error: %v", err)
	}
	if !isStale {
		t.Error("IsStale() should return true for stale cache")
	}
}