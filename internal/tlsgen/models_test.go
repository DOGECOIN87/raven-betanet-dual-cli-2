package tlsgen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExtendedChromeVersion(t *testing.T) {
	now := time.Now()
	extended := ExtendedChromeVersion{
		JA3String:   "771,4865-4866-4867,0-23-65281,29-23-24,0",
		JA3Hash:     "cd08e31494f9531f560d64c695473da9",
		Cached:      now,
		Metadata:    map[string]string{"test": "value"},
	}

	assert.Equal(t, "771,4865-4866-4867,0-23-65281,29-23-24,0", extended.JA3String)
	assert.Equal(t, "cd08e31494f9531f560d64c695473da9", extended.JA3Hash)
	assert.Equal(t, now, extended.Cached)
	assert.Equal(t, "value", extended.Metadata["test"])
}

func TestJA3Result(t *testing.T) {
	result := JA3Result{
		String:     "771,4865-4866-4867,0-23-65281,29-23-24,0",
		Hash:       "cd08e31494f9531f560d64c695473da9",
		ServerName: "google.com",
		Port:       443,
		Duration:   time.Millisecond * 100,
		TLSVersion: 0x0304, // TLS 1.3
	}

	assert.Equal(t, "771,4865-4866-4867,0-23-65281,29-23-24,0", result.String)
	assert.Equal(t, "cd08e31494f9531f560d64c695473da9", result.Hash)
	assert.Equal(t, "google.com", result.ServerName)
	assert.Equal(t, 443, result.Port)
	assert.Equal(t, time.Millisecond*100, result.Duration)
	assert.Equal(t, uint16(0x0304), result.TLSVersion)
}

func TestTLSConfig(t *testing.T) {
	config := TLSConfig{
		ServerName: "example.com",
		Port:       443,
		Timeout:    time.Second * 30,
		MinVersion: 0x0303, // TLS 1.2
		MaxVersion: 0x0304, // TLS 1.3
	}

	assert.Equal(t, "example.com", config.ServerName)
	assert.Equal(t, 443, config.Port)
	assert.Equal(t, time.Second*30, config.Timeout)
	assert.Equal(t, uint16(0x0303), config.MinVersion)
	assert.Equal(t, uint16(0x0304), config.MaxVersion)
}