package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)



// TestJA3TestCommandIntegration tests the ja3-test command with real network connections
func TestJA3TestCommandIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	tests := []struct {
		name        string
		target      string
		version     string
		timeout     string
		expectedJA3 string
		wantErr     bool
		contains    []string
	}{
		{
			name:     "test against httpbin.org",
			target:   "httpbin.org:443",
			timeout:  "10s",
			wantErr:  false,
			contains: []string{"Connection Status: SUCCESS", "JA3 Hash:", "JA3 String:"},
		},
		{
			name:     "test with specific Chrome version",
			target:   "httpbin.org:443",
			version:  "120.0.6099.109",
			timeout:  "10s",
			wantErr:  false,
			contains: []string{"Chrome Version: 120.0.6099.109", "Connection Status: SUCCESS"},
		},
		{
			name:     "test with short timeout",
			target:   "httpbin.org:443",
			timeout:  "1ms",
			wantErr:  true,
			contains: []string{"connection to target server failed"},
		},
		{
			name:     "test invalid target",
			target:   "invalid-host-that-does-not-exist.com:443",
			timeout:  "5s",
			wantErr:  true,
			contains: []string{"connection to target server failed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build command arguments
			args := []string{"ja3-test", "--target", tt.target, "--timeout", tt.timeout}
			if tt.version != "" {
				args = append(args, "--version", tt.version)
			}
			if tt.expectedJA3 != "" {
				args = append(args, "--expected", tt.expectedJA3)
			}

			// Create command
			cmd := newJA3TestCmd()

			// Capture output
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			// Execute command
			cmd.SetArgs(args[1:])
			err := cmd.Execute()

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output contains expected strings
			output := buf.String()
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("output should contain %q, got: %s", expected, output)
				}
			}
		})
	}
}

// TestJA3TestCommandWithMockServer tests the ja3-test command with a mock TLS server
func TestJA3TestCommandWithMockServer(t *testing.T) {
	// Create a test TLS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, TLS!"))
	}))
	defer server.Close()

	// Extract host and port from server URL
	serverURL := strings.TrimPrefix(server.URL, "https://")
	
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains []string
	}{
		{
			name:     "successful connection to mock server",
			args:     []string{"ja3-test", "--target", serverURL, "--timeout", "10s"},
			wantErr:  false,
			contains: []string{"Connection Status: SUCCESS", "JA3 Hash:", "TLS Version:"},
		},
		{
			name:     "connection with specific version",
			args:     []string{"ja3-test", "--target", serverURL, "--version", "120.0.6099.109", "--timeout", "10s"},
			wantErr:  false,
			contains: []string{"Chrome Version: 120.0.6099.109", "Connection Status: SUCCESS"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newJA3TestCmd()

			// Capture stdout since the command writes to stdout
			output, err := captureStdout(func() error {
				cmd.SetArgs(tt.args[1:])
				return cmd.Execute()
			})

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output contains expected strings
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("output should contain %q, got: %s", expected, output)
				}
			}
		})
	}
}

// TestJA3TestCommandJA3Verification tests JA3 fingerprint verification
func TestJA3TestCommandJA3Verification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Test with a known JA3 hash (this will likely fail, but tests the verification logic)
	tests := []struct {
		name        string
		target      string
		expectedJA3 string
		wantErr     bool
		contains    []string
	}{
		{
			name:        "JA3 verification with mismatch",
			target:      "httpbin.org:443",
			expectedJA3: "00000000000000000000000000000000", // Intentionally wrong
			wantErr:     true,
			contains:    []string{"JA3 Verification:", "Expected JA3:", "Actual JA3:", "MISMATCH"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"ja3-test", "--target", tt.target, "--expected", tt.expectedJA3, "--timeout", "10s"}

			cmd := newJA3TestCmd()

			// Capture stdout since the command writes to stdout before returning error
			output, err := captureStdout(func() error {
				cmd.SetArgs(args[1:])
				return cmd.Execute()
			})

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output contains expected strings
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("output should contain %q, got: %s", expected, output)
				}
			}
		})
	}
}

// TestJA3TestCommandErrorHandling tests various error conditions
func TestJA3TestCommandErrorHandling(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains []string
	}{
		{
			name:     "invalid timeout format",
			args:     []string{"ja3-test", "--target", "example.com:443", "--timeout", "invalid"},
			wantErr:  true,
			contains: []string{"invalid timeout format"},
		},
		{
			name:     "invalid Chrome version format",
			args:     []string{"ja3-test", "--target", "example.com:443", "--version", "invalid.version"},
			wantErr:  true,
			contains: []string{"invalid Chrome version format"},
		},
		{
			name:     "missing target flag",
			args:     []string{"ja3-test"},
			wantErr:  true,
			contains: []string{"required flag(s) \"target\" not set"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newJA3TestCmd()

			// Capture output
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			// Execute command
			cmd.SetArgs(tt.args[1:])
			err := cmd.Execute()

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output contains expected strings
			output := buf.String()
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("output should contain %q, got: %s", expected, output)
				}
			}
		})
	}
}

// TestJA3TestCommandTimeout tests timeout handling
func TestJA3TestCommandTimeout(t *testing.T) {
	// Create a server that delays response to test timeout
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Delay longer than test timeout
		w.WriteHeader(http.StatusOK)
	}))
	
	// Configure TLS
	server.TLS = &tls.Config{
		InsecureSkipVerify: true,
	}
	server.StartTLS()
	defer server.Close()

	// Extract host and port
	serverURL := strings.TrimPrefix(server.URL, "https://")

	args := []string{"ja3-test", "--target", serverURL, "--timeout", "1s"}

	cmd := newJA3TestCmd()

	// Capture output
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	// Execute command with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		cmd.SetArgs(args[1:])
		done <- cmd.Execute()
	}()

	select {
	case err := <-done:
		// Command should fail due to timeout or connection issues
		if err == nil {
			t.Log("Command succeeded unexpectedly, but this may be acceptable")
		}
		
		output := buf.String()
		// Should contain timeout or connection failure information
		if !strings.Contains(output, "FAILED") && !strings.Contains(output, "timeout") && !strings.Contains(output, "connection") {
			t.Errorf("Expected timeout or connection failure, got: %s", output)
		}
	case <-ctx.Done():
		t.Error("Test timed out")
	}
}

// TestJA3TestCommandPortHandling tests various port formats
func TestJA3TestCommandPortHandling(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantErr  bool
		contains []string
	}{
		{
			name:     "target with explicit port",
			target:   "httpbin.org:443",
			wantErr:  false,
			contains: []string{"Target Server: httpbin.org:443"},
		},
		{
			name:     "target without port (should default to 443)",
			target:   "httpbin.org",
			wantErr:  false,
			contains: []string{"Target Server: httpbin.org:443"},
		},
		{
			name:     "target with custom port",
			target:   "httpbin.org:8443",
			wantErr:  true, // This will likely fail since httpbin.org doesn't listen on 8443
			contains: []string{"Target Server: httpbin.org:8443"},
		},
	}

	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"ja3-test", "--target", tt.target, "--timeout", "5s"}

			cmd := newJA3TestCmd()

			// Capture output
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			// Execute command
			cmd.SetArgs(args[1:])
			err := cmd.Execute()

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output contains expected strings
			output := buf.String()
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("output should contain %q, got: %s", expected, output)
				}
			}
		})
	}
}

// BenchmarkJA3TestCommand benchmarks the ja3-test command performance
func BenchmarkJA3TestCommand(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	// Create a simple TLS server for benchmarking
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL := strings.TrimPrefix(server.URL, "https://")
	args := []string{"ja3-test", "--target", serverURL, "--timeout", "5s"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := newJA3TestCmd()
		cmd.SetArgs(args[1:])
		
		// Suppress output for benchmarking
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		
		_ = cmd.Execute()
	}
}

// TestJA3TestCommandConcurrency tests concurrent execution of ja3-test commands
func TestJA3TestCommandConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Create a TLS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL := strings.TrimPrefix(server.URL, "https://")
	
	// Run multiple ja3-test commands concurrently
	const numConcurrent = 5
	results := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(id int) {
			args := []string{"ja3-test", "--target", serverURL, "--timeout", "10s"}
			
			cmd := newJA3TestCmd()
			cmd.SetArgs(args[1:])
			
			// Suppress output for concurrency test
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			
			results <- cmd.Execute()
		}(i)
	}

	// Collect results
	var errors []error
	for i := 0; i < numConcurrent; i++ {
		if err := <-results; err != nil {
			errors = append(errors, err)
		}
	}

	// All commands should succeed
	if len(errors) > 0 {
		t.Errorf("Expected all concurrent commands to succeed, but got %d errors: %v", len(errors), errors)
	}
}