package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCheckStatus(t *testing.T) {
	tests := []struct {
		name   string
		status CheckStatus
		valid  bool
	}{
		{"Pass status", StatusPass, true},
		{"Fail status", StatusFail, true},
		{"Skip status", StatusSkip, true},
		{"Error status", StatusError, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, string(tt.status))
		})
	}
}

func TestCheckResult(t *testing.T) {
	result := CheckResult{
		CheckID:  1,
		Name:     "Test Check",
		Status:   "pass",
		Message:  "Test passed",
		Duration: time.Millisecond * 100,
	}

	assert.Equal(t, 1, result.CheckID)
	assert.Equal(t, "Test Check", result.Name)
	assert.Equal(t, "pass", result.Status)
	assert.Equal(t, "Test passed", result.Message)
	assert.Equal(t, time.Millisecond*100, result.Duration)
}

func TestExtendedBinaryInfo(t *testing.T) {
	info := ExtendedBinaryInfo{
		Dependencies: []string{"libc.so.6"},
		FileSize:     1024,
		FilePath:     "/test/binary",
		Metadata:     map[string]string{"test": "value"},
	}

	assert.Equal(t, []string{"libc.so.6"}, info.Dependencies)
	assert.Equal(t, int64(1024), info.FileSize)
	assert.Equal(t, "/test/binary", info.FilePath)
	assert.Equal(t, "value", info.Metadata["test"])
}