package tlsgen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVersionCacheManager(t *testing.T) {
	cacheTTL := 24 * time.Hour
	vcm := NewVersionCacheManager(cacheTTL)
	
	assert.NotNil(t, vcm)
	assert.Equal(t, cacheTTL, vcm.cacheTTL)
	assert.NotEmpty(t, vcm.cacheDir)
}

func TestNewVersionCacheManagerWithPath(t *testing.T) {
	customPath := "/tmp/test-cache"
	cacheTTL := 12 * time.Hour
	vcm := NewVersionCacheManagerWithPath(customPath, cacheTTL)
	
	assert.NotNil(t, vcm)
	assert.Equal(t, cacheTTL, vcm.cacheTTL)
	assert.Equal(t, customPath, vcm.cacheDir)
}

func TestVersionCacheManager_CacheAndGetVersions(t *testing.T) {
	tempDir := t.TempDir()
	vcm := NewVersionCacheManagerWithPath(tempDir, 1*time.Hour)

	// Test versions
	versions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109, Channel: "stable"},
		{Major: 119, Minor: 0, Build: 6045, Patch: 105, Channel: "stable"},
	}

	// Cache versions
	err := vcm.CacheVersions(versions)
	require.NoError(t, err)

	// Retrieve cached versions
	cachedVersions, isValid, err := vcm.GetCachedVersions()
	require.NoError(t, err)
	assert.True(t, isValid)
	assert.Len(t, cachedVersions, 2)
	assert.Equal(t, versions[0].Major, cachedVersions[0].Major)
	assert.Equal(t, versions[1].Major, cachedVersions[1].Major)
}

func TestVersionCacheManager_GetCachedVersions_NoCache(t *testing.T) {
	tempDir := t.TempDir()
	vcm := NewVersionCacheManagerWithPath(tempDir, 1*time.Hour)

	// Try to get versions when no cache exists
	cachedVersions, isValid, err := vcm.GetCachedVersions()
	require.NoError(t, err)
	assert.False(t, isValid)
	assert.Nil(t, cachedVersions)
}

func TestVersionCacheManager_GetCachedVersions_Expired(t *testing.T) {
	tempDir := t.TempDir()
	vcm := NewVersionCacheManagerWithPath(tempDir, 1*time.Millisecond) // Very short TTL

	versions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109},
	}

	// Cache versions
	err := vcm.CacheVersions(versions)
	require.NoError(t, err)

	// Wait for cache to expire
	time.Sleep(10 * time.Millisecond)

	// Try to get expired versions
	cachedVersions, isValid, err := vcm.GetCachedVersions()
	require.NoError(t, err)
	assert.False(t, isValid)
	assert.NotNil(t, cachedVersions) // Should still return the versions even if expired
}

func TestVersionCacheManager_ClearCache(t *testing.T) {
	tempDir := t.TempDir()
	vcm := NewVersionCacheManagerWithPath(tempDir, 1*time.Hour)

	versions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109},
	}

	// Cache versions
	err := vcm.CacheVersions(versions)
	require.NoError(t, err)

	// Verify cache exists
	cachedVersions, isValid, err := vcm.GetCachedVersions()
	require.NoError(t, err)
	assert.True(t, isValid)
	assert.NotNil(t, cachedVersions)

	// Clear cache
	err = vcm.ClearCache()
	require.NoError(t, err)

	// Verify cache is cleared
	cachedVersions, isValid, err = vcm.GetCachedVersions()
	require.NoError(t, err)
	assert.False(t, isValid)
	assert.Nil(t, cachedVersions)
}

func TestVersionCacheManager_GetCacheInfo(t *testing.T) {
	tempDir := t.TempDir()
	vcm := NewVersionCacheManagerWithPath(tempDir, 1*time.Hour)

	// Test cache info when no cache exists
	info, err := vcm.GetCacheInfo()
	require.NoError(t, err)
	assert.False(t, info.Exists)
	assert.False(t, info.Valid)
	assert.Equal(t, 0, info.VersionCount)

	// Cache some versions
	versions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		{Major: 119, Minor: 0, Build: 6045, Patch: 105},
	}
	err = vcm.CacheVersions(versions)
	require.NoError(t, err)

	// Test cache info when cache exists
	info, err = vcm.GetCacheInfo()
	require.NoError(t, err)
	assert.True(t, info.Exists)
	assert.True(t, info.Valid)
	assert.Equal(t, 2, info.VersionCount)
	assert.Equal(t, "chromium-api", info.Source)
	assert.Greater(t, info.Size, int64(0))
}

func TestCacheInfo_IsExpired(t *testing.T) {
	// Test non-expired cache
	validInfo := &CacheInfo{
		Valid:     true,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	assert.False(t, validInfo.IsExpired())

	// Test expired cache
	expiredInfo := &CacheInfo{
		Valid:     false,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	assert.True(t, expiredInfo.IsExpired())
}

func TestCacheInfo_TimeUntilExpiry(t *testing.T) {
	// Test non-expired cache
	validInfo := &CacheInfo{
		Valid:     true,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	timeUntilExpiry := validInfo.TimeUntilExpiry()
	assert.Greater(t, timeUntilExpiry, 50*time.Minute)
	assert.Less(t, timeUntilExpiry, 70*time.Minute)

	// Test expired cache
	expiredInfo := &CacheInfo{
		Valid:     false,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	assert.Equal(t, time.Duration(0), expiredInfo.TimeUntilExpiry())
}

func TestCacheInfo_GetCacheAge(t *testing.T) {
	// Test cache with age
	info := &CacheInfo{
		Exists:   true,
		CachedAt: time.Now().Add(-30 * time.Minute),
	}
	age := info.GetCacheAge()
	assert.Greater(t, age, 25*time.Minute)
	assert.Less(t, age, 35*time.Minute)

	// Test non-existent cache
	nonExistentInfo := &CacheInfo{
		Exists: false,
	}
	assert.Equal(t, time.Duration(0), nonExistentInfo.GetCacheAge())
}

func TestNewTemplateCache(t *testing.T) {
	cache := NewTemplateCache()
	assert.NotNil(t, cache)
	assert.NotEmpty(t, cache.cacheDir)
}

func TestNewTemplateCacheWithPath(t *testing.T) {
	customPath := "/tmp/test-templates"
	cache := NewTemplateCacheWithPath(customPath)
	assert.NotNil(t, cache)
	assert.Equal(t, customPath, cache.cacheDir)
}

func TestTemplateCache_StoreAndGetTemplate(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewTemplateCacheWithPath(tempDir)

	version := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}
	template := &ClientHelloTemplate{
		Version:     version,
		Bytes:       []byte{0x16, 0x03, 0x01, 0x00, 0x10},
		JA3String:   "771,4865-4866-4867,0-23-65281,29-23-24,0",
		JA3Hash:     "cd08e31494f9531f560d64c695473da9",
		GeneratedAt: time.Now(),
	}

	// Store template
	err := cache.StoreTemplate(template)
	require.NoError(t, err)

	// Retrieve template
	retrievedTemplate, err := cache.GetTemplate(version)
	require.NoError(t, err)
	require.NotNil(t, retrievedTemplate)

	assert.Equal(t, template.Version, retrievedTemplate.Version)
	assert.Equal(t, template.JA3Hash, retrievedTemplate.JA3Hash)
	assert.Equal(t, template.JA3String, retrievedTemplate.JA3String)
}

func TestTemplateCache_GetTemplate_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewTemplateCacheWithPath(tempDir)

	version := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}

	// Try to get non-existent template
	template, err := cache.GetTemplate(version)
	require.NoError(t, err)
	assert.Nil(t, template)
}

func TestTemplateCache_ListTemplates(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewTemplateCacheWithPath(tempDir)

	// Test empty cache
	templates, err := cache.ListTemplates()
	require.NoError(t, err)
	assert.Empty(t, templates)

	// Store some templates
	versions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		{Major: 119, Minor: 0, Build: 6045, Patch: 105},
	}

	for _, version := range versions {
		template := &ClientHelloTemplate{
			Version:     version,
			Bytes:       []byte{0x16, 0x03, 0x01, 0x00, 0x10},
			JA3Hash:     "test-hash",
			GeneratedAt: time.Now(),
		}
		err := cache.StoreTemplate(template)
		require.NoError(t, err)
	}

	// List templates
	templates, err = cache.ListTemplates()
	require.NoError(t, err)
	assert.Len(t, templates, 2)

	// Check template info
	for _, templateInfo := range templates {
		assert.NotEmpty(t, templateInfo.FilePath)
		assert.Greater(t, templateInfo.Size, int64(0))
		assert.False(t, templateInfo.GeneratedAt.IsZero())
		assert.Equal(t, "test-hash", templateInfo.JA3Hash)
	}
}

func TestTemplateCache_RemoveTemplate(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewTemplateCacheWithPath(tempDir)

	version := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}
	template := &ClientHelloTemplate{
		Version:     version,
		Bytes:       []byte{0x16, 0x03, 0x01, 0x00, 0x10},
		JA3Hash:     "test-hash",
		GeneratedAt: time.Now(),
	}

	// Store template
	err := cache.StoreTemplate(template)
	require.NoError(t, err)

	// Verify template exists
	retrievedTemplate, err := cache.GetTemplate(version)
	require.NoError(t, err)
	assert.NotNil(t, retrievedTemplate)

	// Remove template
	err = cache.RemoveTemplate(version)
	require.NoError(t, err)

	// Verify template is removed
	retrievedTemplate, err = cache.GetTemplate(version)
	require.NoError(t, err)
	assert.Nil(t, retrievedTemplate)
}

func TestTemplateCache_ClearTemplates(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewTemplateCacheWithPath(tempDir)

	// Store some templates
	versions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		{Major: 119, Minor: 0, Build: 6045, Patch: 105},
	}

	for _, version := range versions {
		template := &ClientHelloTemplate{
			Version:     version,
			Bytes:       []byte{0x16, 0x03, 0x01, 0x00, 0x10},
			JA3Hash:     "test-hash",
			GeneratedAt: time.Now(),
		}
		err := cache.StoreTemplate(template)
		require.NoError(t, err)
	}

	// Verify templates exist
	templates, err := cache.ListTemplates()
	require.NoError(t, err)
	assert.Len(t, templates, 2)

	// Clear all templates
	err = cache.ClearTemplates()
	require.NoError(t, err)

	// Verify templates are cleared
	templates, err = cache.ListTemplates()
	require.NoError(t, err)
	assert.Empty(t, templates)
}

func TestTemplateCache_GetCacheSize(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewTemplateCacheWithPath(tempDir)

	// Test empty cache
	size, err := cache.GetCacheSize()
	require.NoError(t, err)
	assert.Equal(t, int64(0), size)

	// Store a template
	version := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}
	template := &ClientHelloTemplate{
		Version:     version,
		Bytes:       []byte{0x16, 0x03, 0x01, 0x00, 0x10},
		JA3Hash:     "test-hash",
		GeneratedAt: time.Now(),
	}
	err = cache.StoreTemplate(template)
	require.NoError(t, err)

	// Test cache with content
	size, err = cache.GetCacheSize()
	require.NoError(t, err)
	assert.Greater(t, size, int64(0))
}

func TestTemplateCache_CleanupExpiredTemplates(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewTemplateCacheWithPath(tempDir)

	// Store templates with different ages
	oldVersion := ChromeVersion{Major: 119, Minor: 0, Build: 6045, Patch: 105}
	oldTemplate := &ClientHelloTemplate{
		Version:     oldVersion,
		Bytes:       []byte{0x16, 0x03, 0x01, 0x00, 0x10},
		JA3Hash:     "old-hash",
		GeneratedAt: time.Now().Add(-2 * time.Hour), // Old template
	}

	newVersion := ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109}
	newTemplate := &ClientHelloTemplate{
		Version:     newVersion,
		Bytes:       []byte{0x16, 0x03, 0x01, 0x00, 0x10},
		JA3Hash:     "new-hash",
		GeneratedAt: time.Now(), // New template
	}

	err := cache.StoreTemplate(oldTemplate)
	require.NoError(t, err)
	err = cache.StoreTemplate(newTemplate)
	require.NoError(t, err)

	// Verify both templates exist
	templates, err := cache.ListTemplates()
	require.NoError(t, err)
	assert.Len(t, templates, 2)

	// Cleanup templates older than 1 hour
	err = cache.CleanupExpiredTemplates(1 * time.Hour)
	require.NoError(t, err)

	// Verify only new template remains
	templates, err = cache.ListTemplates()
	require.NoError(t, err)
	assert.Len(t, templates, 1)
	assert.Equal(t, newVersion.Major, templates[0].Version.Major)
}

// Benchmark tests
func BenchmarkVersionCacheManager_CacheVersions(b *testing.B) {
	tempDir := b.TempDir()
	vcm := NewVersionCacheManagerWithPath(tempDir, 1*time.Hour)

	versions := []ChromeVersion{
		{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		{Major: 119, Minor: 0, Build: 6045, Patch: 105},
		{Major: 118, Minor: 0, Build: 5993, Patch: 117},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := vcm.CacheVersions(versions)
		require.NoError(b, err)
	}
}

func BenchmarkTemplateCache_StoreTemplate(b *testing.B) {
	tempDir := b.TempDir()
	cache := NewTemplateCacheWithPath(tempDir)

	template := &ClientHelloTemplate{
		Version:     ChromeVersion{Major: 120, Minor: 0, Build: 6099, Patch: 109},
		Bytes:       []byte{0x16, 0x03, 0x01, 0x00, 0x10},
		JA3Hash:     "test-hash",
		GeneratedAt: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		template.Version.Patch = i // Make each template unique
		err := cache.StoreTemplate(template)
		require.NoError(b, err)
	}
}