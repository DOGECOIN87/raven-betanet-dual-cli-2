package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	// Logging configuration
	Log LoggerConfig `yaml:"log" mapstructure:"log"`
	
	// HTTP client configuration
	HTTP HTTPClientConfig `yaml:"http" mapstructure:"http"`
	
	// Chrome uTLS generator configuration
	Chrome ChromeConfig `yaml:"chrome" mapstructure:"chrome"`
	
	// SBOM generator configuration
	SBOM SBOMConfig `yaml:"sbom" mapstructure:"sbom"`
	
	// Compliance checker configuration
	Compliance ComplianceConfig `yaml:"compliance" mapstructure:"compliance"`
}

// ChromeConfig holds Chrome-specific configuration
type ChromeConfig struct {
	APIEndpoint   string `yaml:"api_endpoint" env:"CHROME_API_ENDPOINT"`
	CacheDir      string `yaml:"cache_dir" env:"CHROME_CACHE_DIR"`
	CacheTTL      string `yaml:"cache_ttl" env:"CHROME_CACHE_TTL"`
	TemplateDir   string `yaml:"template_dir" env:"CHROME_TEMPLATE_DIR"`
	UpdateCheck   bool   `yaml:"update_check" env:"CHROME_UPDATE_CHECK"`
}

// SBOMConfig holds SBOM generation configuration
type SBOMConfig struct {
	DefaultFormat string `yaml:"default_format" env:"SBOM_DEFAULT_FORMAT"`
	OutputDir     string `yaml:"output_dir" env:"SBOM_OUTPUT_DIR"`
	Validate      bool   `yaml:"validate" env:"SBOM_VALIDATE"`
	IncludeTests  bool   `yaml:"include_tests" env:"SBOM_INCLUDE_TESTS"`
}

// ComplianceConfig holds compliance checking configuration
type ComplianceConfig struct {
	StrictMode    bool     `yaml:"strict_mode" env:"COMPLIANCE_STRICT_MODE"`
	SkipChecks    []string `yaml:"skip_checks" env:"COMPLIANCE_SKIP_CHECKS"`
	FailFast      bool     `yaml:"fail_fast" env:"COMPLIANCE_FAIL_FAST"`
	ReportFormat  string   `yaml:"report_format" env:"COMPLIANCE_REPORT_FORMAT"`
}

// ConfigManager handles configuration loading and management
type ConfigManager struct {
	config *Config
	viper  *viper.Viper
	logger *Logger
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		config: &Config{},
		viper:  viper.New(),
		logger: NewDefaultLogger(),
	}
}

// LoadConfig loads configuration from file and environment variables
func (c *ConfigManager) LoadConfig(configFile string) error {
	// Set defaults
	c.setDefaults()
	
	// Configure viper
	c.viper.SetConfigType("yaml")
	c.viper.AutomaticEnv()
	c.viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	
	// Load from file if specified
	if configFile != "" {
		c.viper.SetConfigFile(configFile)
		if err := c.viper.ReadInConfig(); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("failed to read config file: %w", err)
			}
			c.logger.WithComponent("config").Warnf("Config file not found: %s", configFile)
		} else {
			c.logger.WithComponent("config").Infof("Loaded config from: %s", c.viper.ConfigFileUsed())
		}
	} else {
		// Look for config in standard locations
		c.viper.SetConfigName("config")
		c.viper.AddConfigPath(".")
		c.viper.AddConfigPath("$HOME/.raven-betanet")
		c.viper.AddConfigPath("/etc/raven-betanet")
		
		if err := c.viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return fmt.Errorf("failed to read config file: %w", err)
			}
			c.logger.WithComponent("config").Debug("No config file found, using defaults and environment variables")
		} else {
			c.logger.WithComponent("config").Infof("Loaded config from: %s", c.viper.ConfigFileUsed())
		}
	}
	
	// Unmarshal into config struct
	if err := c.viper.Unmarshal(c.config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Load environment variables
	if err := c.loadFromEnv(); err != nil {
		return fmt.Errorf("failed to load environment variables: %w", err)
	}
	
	// Validate configuration
	if err := c.validateConfig(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	c.logger.WithComponent("config").Debug("Configuration loaded successfully")
	return nil
}

// setDefaults sets default configuration values
func (c *ConfigManager) setDefaults() {
	// Logging defaults
	c.viper.SetDefault("log.level", "info")
	c.viper.SetDefault("log.format", "text")
	
	// HTTP defaults
	c.viper.SetDefault("http.timeout", "30s")
	c.viper.SetDefault("http.max_retries", 3)
	c.viper.SetDefault("http.retry_delay", "1s")
	c.viper.SetDefault("http.user_agent", "raven-betanet-dual-cli/1.0")
	c.viper.SetDefault("http.follow_redirects", true)
	
	// Chrome defaults
	c.viper.SetDefault("chrome.api_endpoint", "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Linux")
	c.viper.SetDefault("chrome.cache_ttl", "24h")
	c.viper.SetDefault("chrome.update_check", true)
	
	// SBOM defaults
	c.viper.SetDefault("sbom.default_format", "cyclonedx")
	c.viper.SetDefault("sbom.validate", true)
	c.viper.SetDefault("sbom.include_tests", false)
	
	// Compliance defaults
	c.viper.SetDefault("compliance.strict_mode", false)
	c.viper.SetDefault("compliance.fail_fast", false)
	c.viper.SetDefault("compliance.report_format", "text")
}

// loadFromEnv loads configuration from environment variables using struct tags
func (c *ConfigManager) loadFromEnv() error {
	return c.loadEnvForStruct(reflect.ValueOf(c.config).Elem(), "")
}

// loadEnvForStruct recursively loads environment variables for a struct
func (c *ConfigManager) loadEnvForStruct(v reflect.Value, prefix string) error {
	t := v.Type()
	
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		
		// Skip unexported fields
		if !field.CanSet() {
			continue
		}
		
		// Get env tag
		envTag := fieldType.Tag.Get("env")
		if envTag == "" && field.Kind() != reflect.Struct {
			continue
		}
		
		// Handle nested structs
		if field.Kind() == reflect.Struct {
			newPrefix := prefix
			if prefix != "" {
				newPrefix += "_"
			}
			newPrefix += strings.ToUpper(fieldType.Name)
			
			if err := c.loadEnvForStruct(field, newPrefix); err != nil {
				return err
			}
			continue
		}
		
		// Load environment variable
		if envTag != "" {
			envValue := os.Getenv(envTag)
			if envValue != "" {
				if err := c.setFieldFromString(field, envValue); err != nil {
					return fmt.Errorf("failed to set field %s from env %s: %w", fieldType.Name, envTag, err)
				}
			}
		}
	}
	
	return nil
}

// setFieldFromString sets a field value from a string
func (c *ConfigManager) setFieldFromString(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean value: %s", value)
		}
		field.SetBool(boolVal)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer value: %s", value)
		}
		field.SetInt(intVal)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uintVal, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid unsigned integer value: %s", value)
		}
		field.SetUint(uintVal)
	case reflect.Float32, reflect.Float64:
		floatVal, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("invalid float value: %s", value)
		}
		field.SetFloat(floatVal)
	case reflect.Slice:
		// Handle string slices (comma-separated values)
		if field.Type().Elem().Kind() == reflect.String {
			values := strings.Split(value, ",")
			for i, v := range values {
				values[i] = strings.TrimSpace(v)
			}
			field.Set(reflect.ValueOf(values))
		}
	default:
		return fmt.Errorf("unsupported field type: %s", field.Kind())
	}
	
	return nil
}

// validateConfig validates the loaded configuration
func (c *ConfigManager) validateConfig() error {
	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLogLevels, strings.ToLower(string(c.config.Log.Level))) {
		return fmt.Errorf("invalid log level: %s (valid: %v)", c.config.Log.Level, validLogLevels)
	}
	
	// Validate log format
	validLogFormats := []string{"text", "json"}
	if !contains(validLogFormats, strings.ToLower(string(c.config.Log.Format))) {
		return fmt.Errorf("invalid log format: %s (valid: %v)", c.config.Log.Format, validLogFormats)
	}
	
	// Validate SBOM format
	validSBOMFormats := []string{"cyclonedx", "spdx"}
	if !contains(validSBOMFormats, strings.ToLower(c.config.SBOM.DefaultFormat)) {
		return fmt.Errorf("invalid SBOM format: %s (valid: %v)", c.config.SBOM.DefaultFormat, validSBOMFormats)
	}
	
	// Validate compliance report format
	validReportFormats := []string{"text", "json"}
	if !contains(validReportFormats, strings.ToLower(c.config.Compliance.ReportFormat)) {
		return fmt.Errorf("invalid compliance report format: %s (valid: %v)", c.config.Compliance.ReportFormat, validReportFormats)
	}
	
	// Expand paths
	if err := c.expandPaths(); err != nil {
		return fmt.Errorf("failed to expand paths: %w", err)
	}
	
	return nil
}

// expandPaths expands relative paths and environment variables in path fields
func (c *ConfigManager) expandPaths() error {
	// Expand Chrome cache directory
	if c.config.Chrome.CacheDir != "" {
		expanded, err := c.expandPath(c.config.Chrome.CacheDir)
		if err != nil {
			return fmt.Errorf("failed to expand Chrome cache dir: %w", err)
		}
		c.config.Chrome.CacheDir = expanded
	} else {
		// Set default cache directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "."
		}
		c.config.Chrome.CacheDir = filepath.Join(homeDir, ".raven-betanet", "cache", "chrome")
	}
	
	// Expand Chrome template directory
	if c.config.Chrome.TemplateDir != "" {
		expanded, err := c.expandPath(c.config.Chrome.TemplateDir)
		if err != nil {
			return fmt.Errorf("failed to expand Chrome template dir: %w", err)
		}
		c.config.Chrome.TemplateDir = expanded
	} else {
		// Set default template directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "."
		}
		c.config.Chrome.TemplateDir = filepath.Join(homeDir, ".raven-betanet", "templates")
	}
	
	// Expand SBOM output directory
	if c.config.SBOM.OutputDir != "" {
		expanded, err := c.expandPath(c.config.SBOM.OutputDir)
		if err != nil {
			return fmt.Errorf("failed to expand SBOM output dir: %w", err)
		}
		c.config.SBOM.OutputDir = expanded
	}
	
	return nil
}

// expandPath expands a path with environment variables and home directory
func (c *ConfigManager) expandPath(path string) (string, error) {
	// Expand environment variables
	expanded := os.ExpandEnv(path)
	
	// Expand home directory
	if strings.HasPrefix(expanded, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		expanded = filepath.Join(homeDir, expanded[2:])
	}
	
	// Convert to absolute path
	absPath, err := filepath.Abs(expanded)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}
	
	return absPath, nil
}

// GetConfig returns the loaded configuration
func (c *ConfigManager) GetConfig() *Config {
	return c.config
}

// SaveConfig saves the current configuration to a file
func (c *ConfigManager) SaveConfig(filename string) error {
	return c.viper.WriteConfigAs(filename)
}

// SetLogger sets the logger for the config manager
func (c *ConfigManager) SetLogger(logger *Logger) {
	c.logger = logger
}

// GetConfigValue gets a configuration value by key
func (c *ConfigManager) GetConfigValue(key string) interface{} {
	return c.viper.Get(key)
}

// SetConfigValue sets a configuration value by key
func (c *ConfigManager) SetConfigValue(key string, value interface{}) {
	c.viper.Set(key, value)
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

// LoadDefaultConfig loads a default configuration
func LoadDefaultConfig() (*Config, error) {
	manager := NewConfigManager()
	if err := manager.LoadConfig(""); err != nil {
		return nil, err
	}
	return manager.GetConfig(), nil
}

// LoadConfigFromFile loads configuration from a specific file
func LoadConfigFromFile(filename string) (*Config, error) {
	manager := NewConfigManager()
	if err := manager.LoadConfig(filename); err != nil {
		return nil, err
	}
	return manager.GetConfig(), nil
}