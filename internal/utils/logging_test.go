package utils

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name   string
		config LoggerConfig
		want   logrus.Level
	}{
		{
			name: "debug level",
			config: LoggerConfig{
				Level:  LogLevelDebug,
				Format: LogFormatText,
			},
			want: logrus.DebugLevel,
		},
		{
			name: "info level",
			config: LoggerConfig{
				Level:  LogLevelInfo,
				Format: LogFormatText,
			},
			want: logrus.InfoLevel,
		},
		{
			name: "warn level",
			config: LoggerConfig{
				Level:  LogLevelWarn,
				Format: LogFormatText,
			},
			want: logrus.WarnLevel,
		},
		{
			name: "error level",
			config: LoggerConfig{
				Level:  LogLevelError,
				Format: LogFormatText,
			},
			want: logrus.ErrorLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.config)
			if logger.GetLevel() != tt.want {
				t.Errorf("NewLogger() level = %v, want %v", logger.GetLevel(), tt.want)
			}
		})
	}
}

func TestLoggerFormats(t *testing.T) {
	tests := []struct {
		name   string
		format LogFormat
		want   string // substring to check for in output
	}{
		{
			name:   "text format",
			format: LogFormatText,
			want:   "level=info",
		},
		{
			name:   "json format",
			format: LogFormatJSON,
			want:   `"level":"info"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLogger(LoggerConfig{
				Level:  LogLevelInfo,
				Format: tt.format,
				Output: &buf,
			})

			logger.Info("test message")
			output := buf.String()

			if !strings.Contains(output, tt.want) {
				t.Errorf("Expected output to contain %q, got: %s", tt.want, output)
			}
		})
	}
}

func TestLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: &buf,
	})

	logger.Info("test message")
	output := buf.String()

	// Verify it's valid JSON
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}

	// Check required fields
	if logEntry["level"] != "info" {
		t.Errorf("Expected level=info, got: %v", logEntry["level"])
	}
	if logEntry["msg"] != "test message" {
		t.Errorf("Expected msg='test message', got: %v", logEntry["msg"])
	}
	if _, ok := logEntry["time"]; !ok {
		t.Error("Expected time field in JSON output")
	}
}

func TestLoggerWithContext(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: &buf,
	})

	contextFields := map[string]interface{}{
		"user_id":    "12345",
		"request_id": "req-abc-123",
	}

	logger.WithContext(contextFields).Info("test message with context")
	output := buf.String()

	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}

	if logEntry["user_id"] != "12345" {
		t.Errorf("Expected user_id=12345, got: %v", logEntry["user_id"])
	}
	if logEntry["request_id"] != "req-abc-123" {
		t.Errorf("Expected request_id=req-abc-123, got: %v", logEntry["request_id"])
	}
}

func TestLoggerWithComponent(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: &buf,
	})

	logger.WithComponent("compliance-checker").Info("test message")
	output := buf.String()

	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}

	if logEntry["component"] != "compliance-checker" {
		t.Errorf("Expected component=compliance-checker, got: %v", logEntry["component"])
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  LogLevel
	}{
		{"debug", LogLevelDebug},
		{"DEBUG", LogLevelDebug},
		{"info", LogLevelInfo},
		{"INFO", LogLevelInfo},
		{"warn", LogLevelWarn},
		{"WARN", LogLevelWarn},
		{"warning", LogLevelWarn},
		{"error", LogLevelError},
		{"ERROR", LogLevelError},
		{"invalid", LogLevelInfo}, // defaults to info
		{"", LogLevelInfo},        // defaults to info
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, _ := ParseLogLevel(tt.input)
			if got != tt.want {
				t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseLogFormat(t *testing.T) {
	tests := []struct {
		input string
		want  LogFormat
	}{
		{"json", LogFormatJSON},
		{"JSON", LogFormatJSON},
		{"text", LogFormatText},
		{"TEXT", LogFormatText},
		{"invalid", LogFormatText}, // defaults to text
		{"", LogFormatText},        // defaults to text
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseLogFormat(tt.input)
			if got != tt.want {
				t.Errorf("ParseLogFormat(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewDefaultLogger(t *testing.T) {
	logger := NewDefaultLogger()
	
	if logger.GetLevel() != logrus.InfoLevel {
		t.Errorf("Expected default level to be InfoLevel, got: %v", logger.GetLevel())
	}
	
	// Test that it can log without panicking
	logger.Info("test default logger")
}