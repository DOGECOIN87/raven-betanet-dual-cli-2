package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewConfigLoader(t *testing.T) {
	loader := NewConfigLoader()
	if loader == nil {
		t.Fatal("NewConfigLoader() returned nil")
	}
	if loader.v == nil {
		t.Fatal("ConfigLoader.v is nil")
	}
}

func TestConfigLoader_LoadDefaults(t *testing.T) {
	loader := NewConfigLoader()
	config, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Test default values
	if config.LogLevel != "info" {
		t.Errorf("Expected default log_level=info, got: %s", config.LogLevel)
	}
	if config.LogFormat != "text" {
		t.Errorf("Expected default log_format=text, got: %s", config.LogFormat)
	}
	if config.OutputDir != "./output" {
		t.Errorf("Expected default output_dir=./output, got: %s", config.OutputDir)
	}
	if config.HTTPTimeout != 30*time.Second {
		t.Errorf("Expected default http_timeout=30s, got: %v", config.HTTPTimeout)
	}
	if config.Chrome.APIEndpoint != "https://chromiumdash.appspot.com/fetch_releases" {
		t.Errorf("Expected default chrome.api_endpoint, got: %s", config.Chrome.APIEndpoint)
	}
	if config.Linter.SBOMFormat != "cyclonedx" {
		t.Errorf("Expected default linter.sbom_format=cyclonedx, got: %s", config.Linter.SBOMFormat)
	}
}

func TestConfigLoader_LoadFromFile(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")
	
	configContent := `
log_level: debug
log_format: json
output_dir: /tmp/test-output
http_timeout: 60s
chrome:
  api_endpoint: https://example.com/api
  refresh_interval: 12h
  target_versions: ["stable", "beta"]
linter:
  sbom_format: spdx
  enabled_checks: ["check1", "check2"]
  output_format: json
`
	
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	
	// Change to temp directory so config file is found
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)
	os.Chdir(tempDir)
	
	loader := NewConfigLoader()
	config, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	
	// Test loaded values
	if config.LogLevel != "debug" {
		t.Errorf("Expected log_level=debug, got: %s", config.LogLevel)
	}
	if config.LogFormat != "json" {
		t.Errorf("Expected log_format=json, got: %s", config.LogFormat)
	}
	if config.HTTPTimeout != 60*time.Second {
		t.Errorf("Expected http_timeout=60s, got: %v", config.HTTPTimeout)
	}
	if config.Chrome.APIEndpoint != "https://example.com/api" {
		t.Errorf("Expected chrome.api_endpoint=https://example.com/api, got: %s", config.Chrome.APIEndpoint)
	}
	if config.Linter.SBOMFormat != "spdx" {
		t.Errorf("Expected linter.sbom_format=spdx, got: %s", config.Linter.SBOMFormat)
	}
}

func TestConfigLoader_LoadFromEnv(t *testing.T) {
	// Set environment variables
	os.Setenv("RAVEN_LOG_LEVEL", "error")
	os.Setenv("RAVEN_LOG_FORMAT", "json")
	os.Setenv("RAVEN_HTTP_TIMEOUT", "45s")
	defer func() {
		os.Unsetenv("RAVEN_LOG_LEVEL")
		os.Unsetenv("RAVEN_LOG_FORMAT")
		os.Unsetenv("RAVEN_HTTP_TIMEOUT")
	}()
	
	loader := NewConfigLoader()
	config, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	
	// Test environment variable values
	if config.LogLevel != "error" {
		t.Errorf("Expected log_level=error from env, got: %s", config.LogLevel)
	}
	if config.LogFormat != "json" {
		t.Errorf("Expected log_format=json from env, got: %s", config.LogFormat)
	}
	if config.HTTPTimeout != 45*time.Second {
		t.Errorf("Expected http_timeout=45s from env, got: %v", config.HTTPTimeout)
	}
}

func TestConfigLoader_LoadWithOverrides(t *testing.T) {
	loader := NewConfigLoader()
	
	overrides := map[string]interface{}{
		"log_level":  "warn",
		"log_format": "json",
		"chrome.api_endpoint": "https://override.com/api",
	}
	
	config, err := loader.LoadWithOverrides(overrides)
	if err != nil {
		t.Fatalf("LoadWithOverrides() error = %v", err)
	}
	
	// Test override values
	if config.LogLevel != "warn" {
		t.Errorf("Expected log_level=warn from override, got: %s", config.LogLevel)
	}
	if config.LogFormat != "json" {
		t.Errorf("Expected log_format=json from override, got: %s", config.LogFormat)
	}
	if config.Chrome.APIEndpoint != "https://override.com/api" {
		t.Errorf("Expected chrome.api_endpoint from override, got: %s", config.Chrome.APIEndpoint)
	}
}

func TestConfigValidation_InvalidLogLevel(t *testing.T) {
	loader := NewConfigLoader()
	
	overrides := map[string]interface{}{
		"log_level": "invalid",
	}
	
	_, err := loader.LoadWithOverrides(overrides)
	if err == nil {
		t.Error("Expected error for invalid log_level, got nil")
	}
	if !strings.Contains(err.Error(), "invalid log_level") {
		t.Errorf("Expected error message to contain 'invalid log_level', got: %s", err.Error())
	}
}

func TestConfigValidation_InvalidLogFormat(t *testing.T) {
	loader := NewConfigLoader()
	
	overrides := map[string]interface{}{
		"log_format": "invalid",
	}
	
	_, err := loader.LoadWithOverrides(overrides)
	if err == nil {
		t.Error("Expected error for invalid log_format, got nil")
	}
}

func TestConfigValidation_InvalidSBOMFormat(t *testing.T) {
	loader := NewConfigLoader()
	
	overrides := map[string]interface{}{
		"linter.sbom_format": "invalid",
	}
	
	_, err := loader.LoadWithOverrides(overrides)
	if err == nil {
		t.Error("Expected error for invalid sbom_format, got nil")
	}
}

func TestConfigValidation_InvalidHTTPTimeout(t *testing.T) {
	loader := NewConfigLoader()
	
	overrides := map[string]interface{}{
		"http_timeout": "-5s",
	}
	
	_, err := loader.LoadWithOverrides(overrides)
	if err == nil {
		t.Error("Expected error for negative http_timeout, got nil")
	}
}

func TestConfigValidation_EmptyAPIEndpoint(t *testing.T) {
	loader := NewConfigLoader()
	
	overrides := map[string]interface{}{
		"chrome.api_endpoint": "",
	}
	
	_, err := loader.LoadWithOverrides(overrides)
	if err == nil {
		t.Error("Expected error for empty api_endpoint, got nil")
	}
}

func TestConfigValidation_EmptyTargetVersions(t *testing.T) {
	loader := NewConfigLoader()
	
	overrides := map[string]interface{}{
		"chrome.target_versions": []string{},
	}
	
	_, err := loader.LoadWithOverrides(overrides)
	if err == nil {
		t.Error("Expected error for empty target_versions, got nil")
	}
}

func TestEnsureDir(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{
			name:    "empty directory",
			dir:     "",
			wantErr: true,
		},
		{
			name:    "valid directory",
			dir:     t.TempDir(),
			wantErr: false,
		},
		{
			name:    "non-existent directory",
			dir:     filepath.Join(t.TempDir(), "new-dir"),
			wantErr: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ensureDir(tt.dir)
			if (err != nil) != tt.wantErr {
				t.Errorf("ensureDir() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestContains(t *testing.T) {
	slice := []string{"a", "b", "c"}
	
	tests := []struct {
		item string
		want bool
	}{
		{"a", true},
		{"b", true},
		{"c", true},
		{"d", false},
		{"", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.item, func(t *testing.T) {
			got := contains(slice, tt.item)
			if got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}