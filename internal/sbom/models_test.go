package sbom

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestComponentType(t *testing.T) {
	tests := []struct {
		name string
		ct   ComponentType
	}{
		{"Application", ComponentTypeApplication},
		{"Library", ComponentTypeLibrary},
		{"Framework", ComponentTypeFramework},
		{"Container", ComponentTypeContainer},
		{"OS", ComponentTypeOS},
		{"Device", ComponentTypeDevice},
		{"Firmware", ComponentTypeFirmware},
		{"File", ComponentTypeFile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, string(tt.ct))
		})
	}
}

func TestComponent(t *testing.T) {
	component := Component{
		Name:    "test-component",
		Version: "1.0.0",
		Type:    ComponentTypeLibrary,
		Supplier: "Test Supplier",
		Hashes: map[string]string{
			"sha256": "abc123",
		},
	}

	assert.Equal(t, "test-component", component.Name)
	assert.Equal(t, "1.0.0", component.Version)
	assert.Equal(t, ComponentTypeLibrary, component.Type)
	assert.Equal(t, "Test Supplier", component.Supplier)
	assert.Equal(t, "abc123", component.Hashes["sha256"])
}

func TestGenerationMetadata(t *testing.T) {
	now := time.Now()
	metadata := GenerationMetadata{
		Timestamp:   now,
		ToolName:    "raven-linter",
		ToolVersion: "1.0.0",
		Subject:     "/path/to/binary",
	}

	assert.Equal(t, now, metadata.Timestamp)
	assert.Equal(t, "raven-linter", metadata.ToolName)
	assert.Equal(t, "1.0.0", metadata.ToolVersion)
	assert.Equal(t, "/path/to/binary", metadata.Subject)
}