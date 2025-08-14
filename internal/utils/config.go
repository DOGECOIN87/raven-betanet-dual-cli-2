package utils

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	LogLevel    string            `mapstructure:"log_level" yaml:"log_level"`
	LogFormat   string            `mapstructure:"log_format" yaml:"log_format"`
	OutputDir   string            `mapstructure:"output_dir" yaml:"output_dir"`
	HTTPTimeout time.Duration     `mapstructure:"http_timeout" yaml:"http_timeout"`
	Chrome      ChromeConfig      `mapstructure:"chrome" yaml:"chrome"`
	Linter      LinterConfig      `mapstructure:"linter" yaml:"linter"`
}

// ChromeConfig holds Chrome-specific configuration
type ChromeConfig struct {
	APIEndpoint     string   `mapstructure:"api_endpoint" yaml:"api_endpoint"`
	RefreshInterval string   `mapstructure:"refresh_interval" yaml:"refresh_interval"`
	TargetVersions  []string `mapstructure:"target_versions" yaml:"target_versions"`
}

// LinterConfig holds linter-specific configuration
type LinterConfig struct {
	SBOMFormat    string   `mapstructure:"sbom_format" yaml:"sbom_format"`
	EnabledChecks []string `mapstructure:"enabled_checks" yaml:"enabled_checks"`
	OutputFormat  string   `mapstructure:"output_format" yaml:"output_format"`
}

// ConfigLoader handles loading configuration from multiple sources
type ConfigLoader struct {
	v *viper.Viper
}

// NewConfigLoader creates a new configuration loader
func NewConfigLoader() *ConfigLoader {
	v := viper.New()
	
	// Set default values
	setDefaults(v)
	
	// Configure viper
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.raven-betanet")
	v.AddConfigPath("/etc/raven-betanet")
	
	// Enable environment variable support
	v.AutomaticEnv()
	v.SetEnvPrefix("RAVEN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	
	return &ConfigLoader{v: v}
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Logging defaults
	v.SetDefault("log_level", "info")
	v.SetDefault("log_format", "text")
	
	// General defaults
	v.SetDefault("output_dir", "./output")
	v.SetDefault("http_timeout", "30s")
	
	// Chrome defaults
	v.SetDefault("chrome.api_endpoint", "https://chromiumdash.appspot.com/fetch_releases")
	v.SetDefault("chrome.refresh_interval", "24h")
	v.SetDefault("chrome.target_versions", []string{"stable", "stable-2"})
	
	// Linter defaults
	v.SetDefault("linter.sbom_format", "cyclonedx")
	v.SetDefault("linter.enabled_checks", []string{}) // empty means all checks
	v.SetDefault("linter.output_format", "text")
}

// Load loads configuration from file and environment variables
func (cl *ConfigLoader) Load() (*Config, error) {
	// Try to read config file (it's okay if it doesn't exist)
	if err := cl.v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}
	
	var config Config
	if err := cl.v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}
	
	// Validate configuration
	if err := cl.validate(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	
	return &config, nil
}

// LoadWithOverrides loads configuration with command-line overrides
func (cl *ConfigLoader) LoadWithOverrides(overrides map[string]interface{}) (*Config, error) {
	// Apply overrides
	for key, value := range overrides {
		cl.v.Set(key, value)
	}
	
	return cl.Load()
}

// validate validates the configuration
func (cl *ConfigLoader) validate(config *Config) error {
	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLogLevels, strings.ToLower(config.LogLevel)) {
		return fmt.Errorf("invalid log_level: %s, must be one of: %v", config.LogLevel, validLogLevels)
	}
	
	// Validate log format
	validLogFormats := []string{"text", "json"}
	if !contains(validLogFormats, strings.ToLower(config.LogFormat)) {
		return fmt.Errorf("invalid log_format: %s, must be one of: %v", config.LogFormat, validLogFormats)
	}
	
	// Validate SBOM format
	validSBOMFormats := []string{"cyclonedx", "spdx"}
	if !contains(validSBOMFormats, strings.ToLower(config.Linter.SBOMFormat)) {
		return fmt.Errorf("invalid sbom_format: %s, must be one of: %v", config.Linter.SBOMFormat, validSBOMFormats)
	}
	
	// Validate output format
	validOutputFormats := []string{"text", "json"}
	if !contains(validOutputFormats, strings.ToLower(config.Linter.OutputFormat)) {
		return fmt.Errorf("invalid output_format: %s, must be one of: %v", config.Linter.OutputFormat, validOutputFormats)
	}
	
	// Validate HTTP timeout
	if config.HTTPTimeout <= 0 {
		return fmt.Errorf("http_timeout must be positive, got: %v", config.HTTPTimeout)
	}
	
	// Validate output directory exists or can be created
	if err := ensureDir(config.OutputDir); err != nil {
		return fmt.Errorf("invalid output_dir: %w", err)
	}
	
	// Validate Chrome API endpoint
	if config.Chrome.APIEndpoint == "" {
		return fmt.Errorf("chrome.api_endpoint cannot be empty")
	}
	
	// Validate target versions
	if len(config.Chrome.TargetVersions) == 0 {
		return fmt.Errorf("chrome.target_versions cannot be empty")
	}
	
	return nil
}

// ensureDir ensures a directory exists, creating it if necessary
func ensureDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("directory path cannot be empty")
	}
	
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Try to create the directory
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("cannot create directory %s: %w", dir, err)
			}
			return nil
		}
		return fmt.Errorf("cannot access directory %s: %w", dir, err)
	}
	
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	
	return nil
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetConfigFilePath returns the path to the config file being used
func (cl *ConfigLoader) GetConfigFilePath() string {
	return cl.v.ConfigFileUsed()
}