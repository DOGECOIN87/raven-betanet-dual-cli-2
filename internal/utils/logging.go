package utils

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// LogLevel represents the logging level
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// LogFormat represents the logging format
type LogFormat string

const (
	LogFormatText LogFormat = "text"
	LogFormatJSON LogFormat = "json"
)

// Logger wraps logrus.Logger with additional functionality
type Logger struct {
	*logrus.Logger
}

// LoggerConfig holds configuration for the logger
type LoggerConfig struct {
	Level  LogLevel  `yaml:"level" env:"LOG_LEVEL"`
	Format LogFormat `yaml:"format" env:"LOG_FORMAT"`
	Output io.Writer `yaml:"-"`
}

// NewLogger creates a new logger with the given configuration
func NewLogger(config LoggerConfig) *Logger {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(string(config.Level))
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Set format
	switch config.Format {
	case LogFormatJSON:
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	default:
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	}

	// Set output
	if config.Output != nil {
		logger.SetOutput(config.Output)
	} else {
		logger.SetOutput(os.Stdout)
	}

	return &Logger{Logger: logger}
}

// NewDefaultLogger creates a logger with default configuration
func NewDefaultLogger() *Logger {
	return NewLogger(LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatText,
		Output: os.Stdout,
	})
}

// WithContext adds context fields to the logger
func (l *Logger) WithContext(fields map[string]interface{}) *logrus.Entry {
	return l.WithFields(logrus.Fields(fields))
}

// WithComponent adds a component field to the logger
func (l *Logger) WithComponent(component string) *logrus.Entry {
	return l.WithField("component", component)
}

// ParseLogLevel parses a log level string
func ParseLogLevel(level string) (LogLevel, error) {
	switch strings.ToLower(level) {
	case "debug":
		return LogLevelDebug, nil
	case "info":
		return LogLevelInfo, nil
	case "warn", "warning":
		return LogLevelWarn, nil
	case "error":
		return LogLevelError, nil
	default:
		return LogLevelInfo, nil
	}
}

// ParseLogFormat parses a log format string
func ParseLogFormat(format string) LogFormat {
	switch strings.ToLower(format) {
	case "json":
		return LogFormatJSON
	default:
		return LogFormatText
	}
}

// Context key for logger
type contextKey string

const loggerContextKey contextKey = "logger"

// WithLogger adds a logger to the context
func WithLogger(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey, logger)
}

// LoggerFromContext retrieves a logger from the context
func LoggerFromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerContextKey).(*Logger); ok {
		return logger
	}
	return nil
}